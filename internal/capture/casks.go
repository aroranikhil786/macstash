package capture

import (
	"os/exec"
	"strings"
	"sync"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// caskAliases maps application names Homebrew spells differently.
//
// Most apps resolve by lowercasing and hyphenating the .app name, but a
// meaningful minority do not, and the mismatches are not guessable: the app is
// iTerm and the cask is iterm2, the app is GitHub Desktop and the cask is plain
// github, the app is Claude and the cask is claude. Each of these was verified
// against `brew info --cask` rather than assumed.
var caskAliases = map[string]string{
	"iterm":                         "iterm2",
	"github desktop":                "github",
	"visual studio code":            "visual-studio-code",
	"visual studio code - insiders": "visual-studio-code@insiders",
	"postman 2":                     "postman",
	"docker desktop":                "docker",
	"google chrome":                 "google-chrome",
	"firefox developer edition":     "firefox@developer-edition",
	"intellij idea":                 "intellij-idea",
	"intellij idea ce":              "intellij-idea-ce",
	"pycharm ce":                    "pycharm-ce",
	"android studio":                "android-studio",
	"sublime text":                  "sublime-text",
	"microsoft edge":                "microsoft-edge",
	"microsoft word":                "microsoft-word",
	"microsoft excel":               "microsoft-excel",
	"vlc":                           "vlc",
	"obs":                           "obs",
	"zoom":                          "zoom",
	"1password":                     "1password",
}

// caskCandidates returns the tokens worth trying for an app, best guess first.
//
// A trailing version or edition in the app name ("Postman 2") is not part of the
// token, so a stripped form is tried after the literal one.
func caskCandidates(app bundle.App) []string {
	var out []string
	add := func(s string) {
		s = strings.Trim(s, "-")
		if s == "" {
			return
		}
		for _, existing := range out {
			if existing == s {
				return
			}
		}
		out = append(out, s)
	}

	lower := strings.ToLower(strings.TrimSpace(app.Name))
	if alias, ok := caskAliases[lower]; ok {
		add(alias)
	}
	add(normaliseAppName(app.Name))

	// "Postman 2" -> "postman". Only a trailing numeric word is dropped; doing
	// this to any trailing word would turn "Android Studio" into "android".
	if fields := strings.Fields(lower); len(fields) > 1 {
		last := fields[len(fields)-1]
		if isNumericWord(last) {
			add(normaliseAppName(strings.Join(fields[:len(fields)-1], " ")))
		}
	}

	// The last component of a bundle id is often the token: com.tinyspeck.slackmacgap
	// does not help, but com.figma.Desktop and md.obsidian do.
	if app.BundleID != "" {
		parts := strings.Split(app.BundleID, ".")
		if len(parts) >= 2 {
			add(normaliseAppName(parts[1]))
		}
	}
	return out
}

func isNumericWord(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// caskExists reports whether Homebrew knows a cask by that exact token.
//
// This reads Homebrew's local API cache and works inside the capture sandbox,
// which is what makes resolution possible at capture time rather than leaving it
// until the machine being restored onto is already in front of you.
func caskExists(token string) bool {
	cmd := exec.Command("brew", "info", "--cask", token)
	cmd.Env = brewEnv()
	return cmd.Run() == nil
}

// ResolveCasks fills in the Homebrew cask token for apps that have one.
//
// The inventory previously ended at "these were installed by hand, reinstall
// them yourself". On the first machine this ran against that was ten apps — and
// nine of the ten turned out to have a Homebrew cask. They were only unmanaged
// because they had been downloaded as disk images originally, not because
// Homebrew could not install them. Telling someone to hand-download nine apps
// that `brew install --cask` would fetch is a failure of the tool, not a fact
// about their machine.
//
// Nothing here downloads anything or contacts a registry: it asks the local
// Homebrew metadata whether a token exists, and records the answer.
func ResolveCasks(apps []bundle.App) []bundle.App {
	if _, err := exec.LookPath("brew"); err != nil {
		return apps
	}

	type job struct {
		idx        int
		candidates []string
	}
	var jobs []job
	for i, a := range apps {
		// Homebrew-installed apps already come back via the Brewfile, and App
		// Store apps need the App Store.
		if a.Source == SourceHomebrew || a.Source == SourceSystem || a.Source == SourceAppStore {
			continue
		}
		if c := caskCandidates(a); len(c) > 0 {
			jobs = append(jobs, job{idx: i, candidates: c})
		}
	}
	if len(jobs) == 0 {
		return apps
	}

	out := append([]bundle.App(nil), apps...)

	// Each probe is a brew subprocess taking roughly half a second, so a serial
	// sweep over a full Applications folder would add half a minute to capture.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		cache   = map[string]bool{}
		sem     = make(chan struct{}, 8)
		lookups = func(token string) bool {
			mu.Lock()
			hit, known := cache[token]
			mu.Unlock()
			if known {
				return hit
			}
			found := caskExists(token)
			mu.Lock()
			cache[token] = found
			mu.Unlock()
			return found
		}
	)

	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, token := range j.candidates {
				if lookups(token) {
					mu.Lock()
					out[j.idx].CaskToken = token
					mu.Unlock()
					return
				}
			}
		}(j)
	}
	wg.Wait()
	return out
}

// InstallableApps returns apps a restore can install through Homebrew even
// though this machine did not install them that way.
func InstallableApps(apps []bundle.App) []bundle.App {
	var out []bundle.App
	for _, a := range apps {
		if a.Source == SourceHomebrew || a.Source == SourceSystem {
			continue
		}
		if a.CaskToken != "" {
			out = append(out, a)
		}
	}
	return out
}

// UnmanagedApps returns the apps that genuinely cannot be reinstalled by any
// automated means — no cask, and not from the App Store.
func UnmanagedApps(apps []bundle.App) []bundle.App {
	var out []bundle.App
	for _, a := range apps {
		if a.Source == SourceHomebrew || a.Source == SourceSystem {
			continue
		}
		if a.CaskToken == "" {
			out = append(out, a)
		}
	}
	return out
}
