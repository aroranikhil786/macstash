package restore

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// AppInstall is one application a restore can put back through Homebrew.
type AppInstall struct {
	Name    string
	Token   string
	Present bool
	// Want is the version the bundle recorded; Have is the version already on
	// this machine. Both are CFBundleShortVersionString, read the same way at
	// capture and at restore, so comparing them as strings is meaningful.
	Want string
	Have string
}

// PlanApps works out which recorded applications are missing here and which of
// those Homebrew can install.
//
// Presence is decided by looking for the .app bundle rather than by asking
// Homebrew, because the common case on a machine being migrated onto is an app
// that is genuinely absent, and the second most common is an app the user
// already reinstalled by hand before running this. Reinstalling over the top of
// that would be slow and pointless.
func PlanApps(apps []bundle.App) (installable []AppInstall, unmanaged []string) {
	for _, a := range apps {
		if a.Source == "homebrew" || a.Source == "system" {
			continue
		}
		have, present := installedApp(a.Name)
		if a.CaskToken == "" {
			if !present {
				unmanaged = append(unmanaged, a.Name)
			}
			continue
		}
		installable = append(installable, AppInstall{
			Name:    a.Name,
			Token:   a.CaskToken,
			Present: present,
			Want:    a.Version,
			Have:    have,
		})
	}
	sort.Slice(installable, func(i, j int) bool { return installable[i].Name < installable[j].Name })
	sort.Strings(unmanaged)
	return installable, unmanaged
}

// appSearchDirs is where an installed application is looked for. It is a
// variable so tests can point it at a fixture tree instead of depending on
// whatever happens to be installed on the machine running them.
var appSearchDirs = func() []string {
	dirs := []string{"/Applications", "/Applications/Utilities"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

// installedApp reports whether an app bundle is already on this machine, and
// which version it is.
//
// Presence alone decides whether restore touches it; the version is carried so
// a difference can be reported. Upgrading, downgrading or adopting an
// application the user already installed is not a migration tool's call to
// make, but leaving them to assume they have the bundle's version is worse.
func installedApp(name string) (version string, present bool) {
	for _, d := range appSearchDirs() {
		path := filepath.Join(d, name+".app")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		return appVersion(path), true
	}
	return "", false
}

// appVersion reads CFBundleShortVersionString from an installed app — the same
// key capture read, so the two versions compare. An unreadable plist yields "",
// which every caller treats as "no version to compare" rather than a mismatch.
func appVersion(appPath string) string {
	out, err := exec.Command("plutil", "-convert", "json", "-o", "-",
		filepath.Join(appPath, "Contents", "Info.plist")).Output()
	if err != nil {
		return ""
	}
	var info struct {
		Version string `json:"CFBundleShortVersionString"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return ""
	}
	return info.Version
}

// Drifted reports whether what is installed differs from what the bundle
// recorded. Missing a version on either side is not a difference.
func (a AppInstall) Drifted() bool {
	return a.Present && a.Have != "" && a.Want != "" && a.Have != a.Want
}

// Status describes an application that is already here, naming the version
// difference where there is one.
func (a AppInstall) Status() string {
	switch {
	case !a.Present:
		return ""
	case a.Drifted():
		return fmt.Sprintf("already installed — %s here, %s in the bundle", a.Have, a.Want)
	case a.Have != "":
		return "already installed, " + a.Have
	default:
		return "already installed"
	}
}

// InstallApps installs missing applications with Homebrew.
//
// Every install goes through `brew install --cask`, so the invariant that
// macstash never fetches from a URL it chose itself holds: the download comes
// from a cask definition Homebrew maintains and verifies, exactly as if the user
// had typed the command. macstash supplies the list, not the source.
func InstallApps(apps []bundle.App, apply bool, out io.Writer) error {
	installable, unmanaged := PlanApps(apps)

	if len(installable) == 0 && len(unmanaged) == 0 {
		fmt.Fprintln(out, "No applications to install.")
		return nil
	}

	var todo []AppInstall
	for _, a := range installable {
		if !a.Present {
			todo = append(todo, a)
		}
	}

	if !apply {
		if len(todo) > 0 {
			fmt.Fprintf(out, "\n%d application(s) Homebrew can install:\n", len(todo))
			for _, a := range todo {
				fmt.Fprintf(out, "  install  %-32s brew install --cask %s\n", a.Name, a.Token)
			}
		}
		reportPresent(installable, out)
		reportUnmanaged(unmanaged, out)
		fmt.Fprintln(out, "\nNothing was installed. Re-run with --apply --install-apps.")
		return nil
	}

	if len(todo) == 0 {
		fmt.Fprintln(out, "\nEvery application Homebrew can install is already here.")
		reportDrift(installable, out)
		reportUnmanaged(unmanaged, out)
		return nil
	}

	if _, err := exec.LookPath("brew"); err != nil {
		return fmt.Errorf("Homebrew is not installed, so applications cannot be installed.\n" +
			"Install it from https://brew.sh and re-run.")
	}

	fmt.Fprintf(out, "\nInstalling %d application(s) with Homebrew:\n", len(todo))
	var installed, failed int
	for _, a := range todo {
		fmt.Fprintf(out, "  %s ... ", a.Name)
		cmd := exec.Command("brew", "install", "--cask", a.Token)
		cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ENV_HINTS=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			failed++
			fmt.Fprintf(out, "FAILED\n")
			// A cask can fail for reasons worth reading — a name that moved, a
			// version needing a password, a conflict with an app already there.
			// Swallowing the reason would leave the user with a bare count.
			fmt.Fprintf(out, "        %s\n", firstMeaningfulLine(string(output)))
			continue
		}
		installed++
		fmt.Fprintln(out, "ok")
	}

	fmt.Fprintf(out, "\ninstalled %d, failed %d\n", installed, failed)
	reportDrift(installable, out)
	reportUnmanaged(unmanaged, out)
	return nil
}

// reportPresent accounts for the applications restore is leaving alone.
func reportPresent(installable []AppInstall, out io.Writer) {
	present := 0
	for _, a := range installable {
		if a.Present {
			present++
		}
	}
	if present == 0 {
		return
	}
	fmt.Fprintf(out, "\n%d already here and left alone.\n", present)
	reportDrift(installable, out)
}

// reportDrift names the applications whose installed version differs from the
// one the bundle recorded.
//
// Restore deliberately does not upgrade them: presence is decided by name, and
// overwriting an application the user installed themselves is destructive. But
// skipping in silence would leave them believing they have the version the
// bundle carried, so the difference is stated even though nothing acts on it.
func reportDrift(installable []AppInstall, out io.Writer) {
	var drifted []AppInstall
	for _, a := range installable {
		if a.Drifted() {
			drifted = append(drifted, a)
		}
	}
	if len(drifted) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%d differ from the version in the bundle. Nothing is upgraded or\n"+
		"reinstalled — this is only so you know:\n", len(drifted))
	for _, a := range drifted {
		fmt.Fprintf(out, "  %-32s %s here, %s in the bundle\n", a.Name, a.Have, a.Want)
	}
}

func reportUnmanaged(unmanaged []string, out io.Writer) {
	if len(unmanaged) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%d application(s) have no Homebrew cask and are not here. These are the\n"+
		"only ones that need finding by hand:\n", len(unmanaged))
	for _, n := range unmanaged {
		fmt.Fprintf(out, "  %s\n", n)
	}
}

// firstMeaningfulLine picks the line of brew output most likely to explain a
// failure, skipping the progress chatter.
func firstMeaningfulLine(s string) string {
	var fallback string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "Error:") || strings.HasPrefix(t, "Warning:") {
			return t
		}
		if fallback == "" {
			fallback = t
		}
	}
	if fallback == "" {
		return "brew gave no output"
	}
	return fallback
}
