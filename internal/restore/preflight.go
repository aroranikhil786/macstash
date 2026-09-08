// Package restore rebuilds a machine from a bundle.
//
// Restore is never destructive: anything it would overwrite is moved into
// ~/.macstash/backups/<timestamp>/ with its structure preserved, and the whole
// sequence is idempotent, so re-running it after a failure is always safe.
package restore

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// ErrNeedsHomebrew signals that a bundle carries a Brewfile but the machine has
// no brew to install it with.
var ErrNeedsHomebrew = errors.New("homebrew is required but not installed")

// HomebrewInstallMessage is printed when brew is missing.
//
// macstash does not install Homebrew. Doing so would mean fetching and executing
// a script from a URL, which is precisely the thing this tool promises never to
// do; the promise is worth more than the saved step.
const HomebrewInstallMessage = `This bundle contains a Brewfile, but Homebrew is not installed.

macstash will not install Homebrew for you: that would mean downloading and running
a script from the internet, and this tool does not fetch code from URLs.

Install it yourself with the official command from https://brew.sh, then re-run
this restore — it is safe to run more than once:

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
`

// Preflight checks the machine is a safe target before anything is written.
func Preflight(man *bundle.Manifest, fromOtherUser bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("macstash restores onto macOS only (this is %s)", runtime.GOOS)
	}
	if os.Geteuid() == 0 {
		return errors.New("refusing to run as root: restore writes into a user's home directory, " +
			"and running it as root would leave root-owned files behind")
	}

	current, err := user.Current()
	if err != nil {
		return err
	}
	if man.Source.Username != "" && man.Source.Username != current.Username && !fromOtherUser {
		return fmt.Errorf(
			"this bundle was captured by %q but you are %q.\n\n"+
				"Restoring someone else's bundle runs their configuration on your machine: a .zshrc\n"+
				"is a program, and so is an ssh ProxyCommand or a git hook. If that is what you\n"+
				"intend, re-run with --from-other-user and read the --plan output first.",
			man.Source.Username, current.Username)
	}
	return nil
}

// CheckHomebrew reports whether the Brewfile in a bundle can be installed.
func CheckHomebrew(man *bundle.Manifest) error {
	if man.Brewfile == nil {
		return nil
	}
	if _, err := exec.LookPath("brew"); err != nil {
		return ErrNeedsHomebrew
	}
	return nil
}

// CodeExecutionWarning is shown when restoring another user's bundle.
func CodeExecutionWarning(man *bundle.Manifest) string {
	var b strings.Builder
	b.WriteString("warning: this bundle came from another user (")
	b.WriteString(man.Source.Username)
	b.WriteString(").\n")
	b.WriteString("         Shell config, ssh config and git config are executable in practice.\n")
	b.WriteString("         Review the --plan file list before applying.\n")
	return b.String()
}
