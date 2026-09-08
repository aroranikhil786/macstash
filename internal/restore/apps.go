package restore

import (
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
		if a.CaskToken == "" {
			if !appPresent(a.Name) {
				unmanaged = append(unmanaged, a.Name)
			}
			continue
		}
		installable = append(installable, AppInstall{
			Name:    a.Name,
			Token:   a.CaskToken,
			Present: appPresent(a.Name),
		})
	}
	sort.Slice(installable, func(i, j int) bool { return installable[i].Name < installable[j].Name })
	sort.Strings(unmanaged)
	return installable, unmanaged
}

// appPresent reports whether an app bundle is already on this machine.
func appPresent(name string) bool {
	dirs := []string{"/Applications", "/Applications/Utilities"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, name+".app")); err == nil {
			return true
		}
	}
	return false
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
		if n := len(installable) - len(todo); n > 0 {
			fmt.Fprintf(out, "\n%d already here.\n", n)
		}
		reportUnmanaged(unmanaged, out)
		fmt.Fprintln(out, "\nNothing was installed. Re-run with --apply --install-apps.")
		return nil
	}

	if len(todo) == 0 {
		fmt.Fprintln(out, "\nEvery application Homebrew can install is already here.")
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
	reportUnmanaged(unmanaged, out)
	return nil
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
