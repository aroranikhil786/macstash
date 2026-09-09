package restore

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// CloneRepos re-clones the repositories recorded at capture.
//
// This is a separate command from restore on purpose. Cloning needs SSH keys and
// often a VPN, and neither exists at the moment a machine is first set up —
// macstash never captures private keys, so the credentials required to clone are
// by construction not present during a restore. Bundling the two would guarantee
// a wall of authentication failures in the middle of an otherwise working
// restore.
func CloneRepos(home string, repos []bundle.Repo, apply bool, out io.Writer) error {
	if len(repos) == 0 {
		fmt.Fprintln(out, "No repositories were recorded in this bundle.")
		return nil
	}

	var cloned, skipped, failed, noRemote, unpushed int
	for _, r := range repos {
		dest := expandHome(home, r.Path)

		if r.Remote == "" {
			noRemote++
			fmt.Fprintf(out, "  SKIP  %s\n        had no remote on the old machine — this one exists nowhere else\n", r.Path)
			continue
		}
		if _, err := os.Stat(dest); err == nil {
			skipped++
			if apply {
				fmt.Fprintf(out, "  have  %s\n", r.Path)
			}
			continue
		}
		if !apply {
			fmt.Fprintf(out, "  clone %s  (branch %s)\n", r.Path, orDefault(r.Branch, "default"))
			continue
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}

		// The recorded branch may never have been pushed. git clone --branch
		// fails outright when the remote has no such branch, which skips the
		// whole repository and loses the code along with the branch — the
		// opposite of what someone re-cloning 45 repositories wants. So the
		// second attempt takes the remote's default branch.
		//
		// dest did not exist a moment ago, checked above, so clearing a partial
		// clone before retrying cannot remove anything that was already here.
		output, err := gitClone(r.Remote, dest, r.Branch)
		var fellBack bool
		if err != nil && r.Branch != "" && r.Branch != "HEAD" {
			os.RemoveAll(dest)
			if output, err = gitClone(r.Remote, dest, ""); err == nil {
				fellBack = true
			}
		}
		if err != nil {
			failed++
			fmt.Fprintf(out, "  FAIL  %s\n", r.Path)
			if line := gitError(output); line != "" {
				fmt.Fprintf(out, "        %s\n", line)
			}
			continue
		}
		cloned++
		if fellBack {
			unpushed++
			fmt.Fprintf(out, "  ok    %s\n        on the default branch: %q was never pushed, so its\n"+
				"        commits are only on the old machine\n", r.Path, r.Branch)
			continue
		}
		fmt.Fprintf(out, "  ok    %s\n", r.Path)
	}

	if !apply {
		fmt.Fprintf(out, "\n%d repositories to clone. Re-run with --apply.\n", len(repos)-skipped-noRemote)
		fmt.Fprintln(out, "You need your SSH key and any VPN in place first — neither is in the bundle.")
		return nil
	}
	fmt.Fprintf(out, "\ncloned %d, already present %d, failed %d, no remote %d\n", cloned, skipped, failed, noRemote)
	if noRemote > 0 {
		fmt.Fprintf(out, "\n%d repository(ies) had no remote. If the old machine is still alive, copy\nthem across by hand — nothing else can recover them.\n", noRemote)
	}
	if unpushed > 0 {
		fmt.Fprintf(out, "\n%d repository(ies) came back on the default branch because the branch you\nwere on was never pushed. Those commits exist only on the old machine.\n", unpushed)
	}
	return nil
}

// gitClone runs one clone attempt, capturing output so a first failure that is
// about to be retried does not print a wall of git noise.
func gitClone(remote, dest, branch string) (string, error) {
	args := []string{"clone"}
	if branch != "" && branch != "HEAD" {
		args = append(args, "--branch", branch)
	}
	args = append(args, remote, dest)

	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// gitError picks the line of git output that says what went wrong. git puts its
// diagnosis last, after the progress chatter, which is the opposite of brew.
func gitError(output string) string {
	var last string
	for _, line := range strings.Split(output, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "fatal:") || strings.HasPrefix(t, "error:") {
			return t
		}
		last = t
	}
	return last
}

func expandHome(home, p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
