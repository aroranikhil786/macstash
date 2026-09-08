package restore

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// makeOriginRepo builds a real bare repository with one commit on a named
// branch, so clone tests exercise git itself rather than a mock. A local path
// is a valid git remote, so this needs no network.
func makeOriginRepo(t *testing.T, branch string) string {
	t.Helper()
	dir := t.TempDir()
	work := filepath.Join(dir, "work")
	bare := filepath.Join(dir, "origin.git")

	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=macstash", "GIT_AUTHOR_EMAIL=macstash@example.invalid",
			"GIT_COMMITTER_NAME=macstash", "GIT_COMMITTER_EMAIL=macstash@example.invalid",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}

	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	run(work, "init", "--initial-branch="+branch)
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(work, "add", "README.md")
	run(work, "commit", "-m", "initial")
	run(dir, "clone", "--bare", work, bare)
	return bare
}

func TestCloneReposPlanClonesNothing(t *testing.T) {
	home := t.TempDir()
	origin := makeOriginRepo(t, "main")
	var buf bytes.Buffer

	repos := []bundle.Repo{{Path: "~/code/project", Remote: origin, Branch: "main"}}
	if err := CloneRepos(home, repos, false, &buf); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(home, "code", "project")); !os.IsNotExist(err) {
		t.Fatal("a dry run must not create anything on disk")
	}
	if !strings.Contains(buf.String(), "Re-run with --apply") {
		t.Errorf("want the apply hint, got:\n%s", buf.String())
	}
	// The credentials needed to clone are, by construction, not in the bundle.
	// Saying so up front is the difference between a clear prerequisite and a
	// wall of authentication failures.
	if !strings.Contains(buf.String(), "SSH key") {
		t.Errorf("the dry run should warn about credentials, got:\n%s", buf.String())
	}
}

// The real thing: a clone that produces a working tree at the recorded path.
func TestCloneReposApplyClonesToTheRecordedPath(t *testing.T) {
	home := t.TempDir()
	origin := makeOriginRepo(t, "main")
	var buf bytes.Buffer

	repos := []bundle.Repo{{Path: "~/code/nested/project", Remote: origin, Branch: "main"}}
	if err := CloneRepos(home, repos, true, &buf); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}

	dest := filepath.Join(home, "code", "nested", "project")
	if _, err := os.Stat(filepath.Join(dest, "README.md")); err != nil {
		t.Fatalf("expected a working tree at %s: %v\n%s", dest, err, buf.String())
	}
	if !strings.Contains(buf.String(), "cloned 1") {
		t.Errorf("want a clone in the summary, got:\n%s", buf.String())
	}
}

// The branch that was checked out on the old machine is the one you want back;
// landing on the remote default silently loses that.
func TestCloneReposChecksOutTheRecordedBranch(t *testing.T) {
	home := t.TempDir()
	origin := makeOriginRepo(t, "develop")
	var buf bytes.Buffer

	repos := []bundle.Repo{{Path: "~/p", Remote: origin, Branch: "develop"}}
	if err := CloneRepos(home, repos, true, &buf); err != nil {
		t.Fatalf("%v\n%s", err, buf.String())
	}

	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	cmd.Dir = filepath.Join(home, "p")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "develop" {
		t.Errorf("checked out %q, want develop", got)
	}
}

// Restore is meant to be safe to repeat. A second run must not touch a tree that
// already exists — re-cloning over local work would destroy it.
func TestCloneReposIsIdempotentAndNeverOverwritesAnExistingTree(t *testing.T) {
	home := t.TempDir()
	origin := makeOriginRepo(t, "main")

	repos := []bundle.Repo{{Path: "~/p", Remote: origin, Branch: "main"}}
	var first bytes.Buffer
	if err := CloneRepos(home, repos, true, &first); err != nil {
		t.Fatalf("%v\n%s", err, first.String())
	}

	// Local work that only exists here, exactly what a re-clone would lose.
	local := filepath.Join(home, "p", "uncommitted.txt")
	if err := os.WriteFile(local, []byte("precious\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var second bytes.Buffer
	if err := CloneRepos(home, repos, true, &second); err != nil {
		t.Fatalf("%v\n%s", err, second.String())
	}

	data, err := os.ReadFile(local)
	if err != nil || string(data) != "precious\n" {
		t.Fatalf("a second run destroyed local work: %v", err)
	}
	if !strings.Contains(second.String(), "already present 1") {
		t.Errorf("want the existing tree reported as present, got:\n%s", second.String())
	}
}

// A repository with no remote cannot be cloned by anyone. It is the single most
// dangerous thing in a migration and must be called out, not counted as done.
func TestCloneReposRefusesAndFlagsRepositoriesWithNoRemote(t *testing.T) {
	home := t.TempDir()
	var buf bytes.Buffer

	repos := []bundle.Repo{{Path: "~/orphan", NoRemote: true}}
	if err := CloneRepos(home, repos, true, &buf); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "exists nowhere else") {
		t.Errorf("want an explicit warning, got:\n%s", out)
	}
	if !strings.Contains(out, "no remote 1") {
		t.Errorf("want it counted separately from successes, got:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, "orphan")); !os.IsNotExist(err) {
		t.Error("nothing should have been created for a repo with no remote")
	}
}

// One unreachable remote must not abort the rest. On a real migration some
// remotes are behind a VPN that is not up yet.
func TestCloneReposContinuesAfterAFailure(t *testing.T) {
	home := t.TempDir()
	origin := makeOriginRepo(t, "main")
	var buf bytes.Buffer

	repos := []bundle.Repo{
		{Path: "~/broken", Remote: filepath.Join(t.TempDir(), "does-not-exist.git"), Branch: "main"},
		{Path: "~/good", Remote: origin, Branch: "main"},
	}
	if err := CloneRepos(home, repos, true, &buf); err != nil {
		t.Fatalf("a single failure must not abort the run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, "good", "README.md")); err != nil {
		t.Fatalf("the reachable repo should still have been cloned: %v\n%s", err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "failed 1") {
		t.Errorf("the failure must be reported, got:\n%s", out)
	}
}

func TestCloneReposWithNothingRecordedSaysSo(t *testing.T) {
	var buf bytes.Buffer

	if err := CloneRepos(t.TempDir(), nil, true, &buf); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(buf.String(), "No repositories") {
		t.Errorf("want an explicit empty state, got:\n%s", buf.String())
	}
}

// A path outside the home is recorded verbatim, and an absolute one must not be
// re-rooted into the new home.
func TestExpandHomeOnlyRewritesTheTildePrefix(t *testing.T) {
	home := "/Users/someone"
	cases := map[string]string{
		"~/code/x":     "/Users/someone/code/x",
		"/opt/thing":   "/opt/thing",
		"relative/dir": "relative/dir",
	}
	for in, want := range cases {
		if got := expandHome(home, in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}
