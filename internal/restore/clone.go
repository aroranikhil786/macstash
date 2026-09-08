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

	var cloned, skipped, failed, noRemote int
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
		args := []string{"clone"}
		if r.Branch != "" && r.Branch != "HEAD" {
			args = append(args, "--branch", r.Branch)
		}
		args = append(args, r.Remote, dest)

		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		cmd.Stdout, cmd.Stderr = out, out
		if err := cmd.Run(); err != nil {
			failed++
			fmt.Fprintf(out, "  FAIL  %s (%v)\n", r.Path, err)
			continue
		}
		cloned++
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
	return nil
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
