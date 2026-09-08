package capture

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// App sources.
const (
	SourceHomebrew = "homebrew"
	SourceAppStore = "app store"
	SourceManual   = "manual"
	// SourceSystem is an Apple app that ships with macOS.
	SourceSystem = "system"
)

// isHelperBundle reports whether an app is a helper shipped with another app
// rather than something a person installs.
func isHelperBundle(name, bundleID string) bool {
	for _, suffix := range []string{
		" URL Handler", " Helper", " Updater", " Crash Reporter", " Uninstaller",
	} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return strings.HasSuffix(bundleID, ".helper")
}

// ScanApplications inventories installed applications and works out which ones a
// restore can actually reinstall.
//
// This exists because `brew bundle dump` only knows about software Homebrew
// installed, and on a real machine that is a minority of it. The first Mac this
// ran against had seventeen applications and exactly one Homebrew cask: Arc,
// Android Studio, Xcode, Postman, Telegram and the rest arrived as disk images or
// from the App Store, and were therefore completely invisible to capture. A
// migration tool that silently omits sixteen of your seventeen apps has not
// helped you move.
//
// None of these can be installed automatically without fetching from arbitrary
// URLs, which macstash does not do. So they are reported as a checklist. Being
// told "these eleven apps need reinstalling by hand, here are their versions" is
// the whole value; discovering it one app at a time over a month is the problem.
func ScanApplications(caskTokens []string) []bundle.App {
	casks := make(map[string]bool, len(caskTokens))
	for _, c := range caskTokens {
		casks[normaliseAppName(c)] = true
	}
	// The token is a fallback; the Caskroom bundle names are authoritative.
	for name := range caskAppNames() {
		casks[name] = true
	}

	var apps []bundle.App
	seen := map[string]bool{}
	for _, dir := range applicationDirs() {
		names, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, n := range names {
			if !strings.HasSuffix(n.Name(), ".app") {
				continue
			}
			path := filepath.Join(dir, n.Name())
			if seen[path] {
				continue
			}
			seen[path] = true

			name := strings.TrimSuffix(n.Name(), ".app")
			a := bundle.App{Name: name, Path: path, Source: SourceManual}
			a.Version, a.BundleID = appInfo(path)

			// Apple's own apps arrive with the OS. Listing Safari on a "reinstall
			// these by hand" checklist is noise that makes the real entries easier
			// to skim past.
			if strings.HasPrefix(a.BundleID, "com.apple.") {
				a.Source = SourceSystem
			}
			// Helper bundles (URL handlers, updaters, crash reporters) are shipped
			// inside or alongside a parent app and are not separately installable.
			if isHelperBundle(name, a.BundleID) {
				continue
			}

			switch a.Source {
			case SourceSystem:
				// leave as-is
			default:
				switch {
				case casks[normaliseAppName(name)]:
					a.Source = SourceHomebrew
				case isAppStore(path):
					a.Source = SourceAppStore
				}
			}
			apps = append(apps, a)
		}
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].Name < apps[j].Name })
	return apps
}

// applicationDirs are the locations worth scanning. /System/Applications is
// excluded: those ship with macOS and reinstalling them is not a thing anyone
// needs a checklist for.
func applicationDirs() []string {
	dirs := []string{"/Applications", "/Applications/Utilities"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

// isAppStore reports whether an app carries a Mac App Store receipt.
func isAppStore(appPath string) bool {
	_, err := os.Stat(filepath.Join(appPath, "Contents", "_MASReceipt", "receipt"))
	return err == nil
}

// appInfo reads the version and bundle identifier from an app's Info.plist.
func appInfo(appPath string) (version, bundleID string) {
	plist := filepath.Join(appPath, "Contents", "Info.plist")
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-", plist).Output()
	if err != nil {
		return "", ""
	}
	var info struct {
		Version  string `json:"CFBundleShortVersionString"`
		BundleID string `json:"CFBundleIdentifier"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return "", ""
	}
	return info.Version, info.BundleID
}

// normaliseAppName maps an app name and a cask token towards each other, so
// "Google Chrome" and "google-chrome" compare equal.
func normaliseAppName(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(" ", "-", "_", "-", ".", "-").Replace(s)
	return strings.Trim(s, "-")
}

// caskAppNames returns the .app bundle names Homebrew actually installed, read
// from the Caskroom.
//
// Matching on the cask token alone is not reliable: the cask is called iterm2
// and the app is iTerm.app, the cask is font-fira-code and there is no app at
// all. The Caskroom holds the real bundle names, so comparing against those
// answers the only question that matters — will `brew bundle` put this app back?
func caskAppNames() map[string]bool {
	out := map[string]bool{}
	prefix, err := runBrew("--prefix")
	if err != nil {
		return out
	}
	caskroom := filepath.Join(strings.TrimSpace(string(prefix)), "Caskroom")
	// Caskroom/<token>/<version>/<Name>.app
	matches, err := filepath.Glob(filepath.Join(caskroom, "*", "*", "*.app"))
	if err != nil {
		return out
	}
	for _, m := range matches {
		out[normaliseAppName(strings.TrimSuffix(filepath.Base(m), ".app"))] = true
	}
	return out
}

// CaskTokens lists the casks Homebrew installed, for cross-referencing.
//
// The bool reports whether brew could be consulted at all. Without it every app
// looks hand-installed, and quietly telling someone they must reinstall
// everything by hand is worse than telling them the check did not run.
func CaskTokens() ([]string, bool) {
	out, err := runBrew("list", "--cask")
	if err != nil {
		return nil, false
	}
	var tokens []string
	for _, line := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tokens = append(tokens, t)
		}
	}
	return tokens, true
}

// ManualApps returns just the applications a restore cannot reinstall.
func ManualApps(apps []bundle.App) []bundle.App {
	var out []bundle.App
	for _, a := range apps {
		if a.Source != SourceHomebrew && a.Source != SourceSystem {
			out = append(out, a)
		}
	}
	return out
}
