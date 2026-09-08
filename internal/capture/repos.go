package capture

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// repoScanRoots are the directories worth searching. Scanning all of $HOME is
// both slow and pointless — nobody keeps source in ~/Library.
func repoScanRoots(home string) []string {
	var roots []string
	for _, name := range []string{
		"Documents", "Developer", "Projects", "projects", "code", "Code",
		"src", "work", "repos", "dev", "git", "go/src",
	} {
		p := filepath.Join(home, name)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			roots = append(roots, p)
		}
	}
	return roots
}

// skipDuringRepoScan are directories that never contain a repository worth
// recording but do contain enough files to make a scan crawl.
var skipDuringRepoScan = map[string]bool{
	"node_modules": true, "vendor": true, "Pods": true, ".Trash": true,
	"Library": true, ".build": true, "target": true, "dist": true,
	".venv": true, "venv": true, "__pycache__": true, ".next": true,
	"DerivedData": true, ".gradle": true, ".cache": true,
}

// ScanRepos finds git working trees and records what it would take to get them
// back. maxDepth bounds how far below each root it will look.
func ScanRepos(home string, maxDepth int) []bundle.Repo {
	var repos []bundle.Repo
	for _, root := range repoScanRoots(home) {
		rootDepth := strings.Count(root, string(filepath.Separator))

		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil //nolint:nilerr // an unreadable directory is not fatal
			}
			base := d.Name()
			if skipDuringRepoScan[base] {
				return filepath.SkipDir
			}
			if strings.Count(p, string(filepath.Separator))-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(p, ".git")); err != nil {
				return nil
			}
			repos = append(repos, inspectRepo(home, p))
			// Do not descend into a repository. Submodules and vendored checkouts
			// come back with the parent clone, and listing them separately turns a
			// useful list into noise.
			return filepath.SkipDir
		})
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].Path < repos[j].Path })
	return repos
}

// inspectRepo reads a repository's state. Every command here is local: nothing
// contacts the remote, which is what lets the whole scan run inside the
// no-network capture sandbox.
func inspectRepo(home, dir string) bundle.Repo {
	r := bundle.Repo{Path: shortPath(home, dir)}

	// "origin" is a convention, not a guarantee. A repo created with
	// `git remote add github ...`, or one where origin was renamed, has a
	// perfectly good remote under another name — reporting it as having none
	// both cries wolf in the at-risk list and makes `clone` refuse to fetch it.
	if url, ok := primaryRemote(dir); ok {
		r.Remote = url
	} else {
		r.NoRemote = true
	}
	if out, err := git(dir, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		r.Branch = out
	}
	if out, err := git(dir, "status", "--porcelain"); err == nil && out != "" {
		r.Dirty = true
	}
	// Count commits that exist on no remote. `rev-list @{u}..` only works when
	// the current branch has an upstream, and a branch made with `git checkout
	// -b` and never pushed has none — so the command fails, the count silently
	// stays zero, and a branch holding a month of work is reported as safe. That
	// is precisely the work this report exists to stop someone from wiping.
	if out, err := git(dir, "rev-list", "@{u}..", "--count"); err == nil {
		if n, convErr := strconv.Atoi(out); convErr == nil {
			r.Unpushed = n
		}
	} else {
		r.NoUpstream = true
		// Fall back to "on a local branch but on no remote", which needs no
		// upstream and also covers detached HEAD.
		if out, err := git(dir, "rev-list", "--branches", "--not", "--remotes", "--count"); err == nil {
			if n, convErr := strconv.Atoi(out); convErr == nil {
				r.Unpushed = n
			}
		}
	}
	return r
}

// primaryRemote returns a remote URL, preferring origin but accepting any.
func primaryRemote(dir string) (string, bool) {
	if url, err := git(dir, "remote", "get-url", "origin"); err == nil && url != "" {
		return url, true
	}
	names, err := git(dir, "remote")
	if err != nil {
		return "", false
	}
	for _, name := range lines(names) {
		if url, err := git(dir, "remote", "get-url", name); err == nil && url != "" {
			return url, true
		}
	}
	return "", false
}

func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	// A repository configured with a credential helper or an ssh signing key must
	// not cause a prompt during a scan.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func shortPath(home, p string) string {
	if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}

// RepoRisks returns the repositories that would lose work in a migration.
func RepoRisks(repos []bundle.Repo) []bundle.Repo {
	var out []bundle.Repo
	for _, r := range repos {
		if r.AtRisk() {
			out = append(out, r)
		}
	}
	return out
}
