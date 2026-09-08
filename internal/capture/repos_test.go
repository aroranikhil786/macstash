package capture

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "t@example.com"},
		{"config", "user.name", "T"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
}

func gitCommit(t *testing.T, dir, msg string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "commit", "-q", "--allow-empty", "-m", msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit: %v %s", err, out)
	}
}

// A branch created with `git checkout -b` and never pushed has no upstream, so
// `rev-list @{u}..` fails and the count silently stays zero. A clean tree with a
// month of unpushed work then reports as safe — the exact loss this report is
// meant to prevent.
func TestUnpushedWorkOnBranchWithNoUpstreamIsAtRisk(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	gitCommit(t, dir, "initial")

	// Give it a remote so NoRemote is false and cannot mask the result.
	if out, err := exec.Command("git", "-C", dir, "remote", "add", "origin",
		"https://github.com/example/repo.git").CombinedOutput(); err != nil {
		t.Fatalf("remote add: %v %s", err, out)
	}
	if out, err := exec.Command("git", "-C", dir, "checkout", "-q", "-b", "refactor").CombinedOutput(); err != nil {
		t.Fatalf("checkout: %v %s", err, out)
	}
	gitCommit(t, dir, "work that exists only here")

	r := inspectRepo(filepath.Dir(dir), dir)
	if r.NoRemote {
		t.Fatal("remote was not detected")
	}
	if !r.AtRisk() {
		t.Errorf("repo with unpushed work on an untracked branch reported as safe: %+v", r)
	}
}

// "origin" is a convention. A repo whose remote is named something else has one,
// and must not be reported as having none — that both cries wolf and makes
// clone refuse to fetch it.
func TestNonOriginRemoteIsFound(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	gitCommit(t, dir, "initial")
	if out, err := exec.Command("git", "-C", dir, "remote", "add", "github",
		"https://github.com/example/repo.git").CombinedOutput(); err != nil {
		t.Fatalf("remote add: %v %s", err, out)
	}

	r := inspectRepo(filepath.Dir(dir), dir)
	if r.NoRemote {
		t.Error("a remote named 'github' was reported as no remote at all")
	}
	if r.Remote != "https://github.com/example/repo.git" {
		t.Errorf("remote = %q", r.Remote)
	}
}

// A genuinely remoteless repo must still be flagged.
func TestRepoWithNoRemoteAtAllIsAtRisk(t *testing.T) {
	dir := t.TempDir()
	gitInit(t, dir)
	gitCommit(t, dir, "initial")

	r := inspectRepo(filepath.Dir(dir), dir)
	if !r.NoRemote || !r.AtRisk() {
		t.Errorf("repo with no remote not flagged: %+v", r)
	}
}
