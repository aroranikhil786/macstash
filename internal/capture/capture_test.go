package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/catalog"
	"github.com/aroranikhil786/macstash/internal/classify"
)

// Every planted secret carries a unique marker. After a capture, the entire
// bundle tree is grepped for all of them: any hit is a leak, and it does not
// matter which code path put it there.
var planted = map[string]string{
	"aws access key":       "AKIAPLANTEDAWSKEY01",
	"npm token":            "npm_PLANTEDTOKEN0123456789",
	"ssh private key":      "PLANTEDSSHPRIVATEKEYMATERIAL",
	"dotenv secret":        "PLANTED_DOTENV_SECRET_VALUE",
	"docker registry auth": "cGxhbnRlZDpkb2NrZXJhdXRo",
	"git inline token":     "ghp_PLANTEDGITHUBTOKEN0123",
	"shell history token":  "PLANTED_HISTORY_TOKEN",
	"gh cli token":         "PLANTED_GH_CLI_TOKEN",
	"neon token":           "PLANTED_NEON_TOKEN",
	"kubeconfig secret":    "PLANTED_KUBE_CLIENT_KEY",
}

// fixtureHome builds a $HOME that looks like a real developer machine: useful
// config interleaved with credentials in all the usual places.
func fixtureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()

	files := map[string]string{
		// Things that must be captured.
		".zshrc":              "export EDITOR=vim\nalias gs='git status'\n",
		".tmux.conf":          "set -g mouse on\n",
		".ssh/config":         "Host github.com\n  User git\n",
		".ssh/known_hosts":    "github.com ssh-ed25519 AAAAC3Nz\n",
		".ssh/id_ed25519.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1 teddy@mac\n",

		// Things that must be scrubbed but kept.
		".npmrc": "registry=https://registry.npmjs.org/\n" +
			"//registry.npmjs.org/:_authToken=" + planted["npm token"] + "\n" +
			"save-exact=true\n",
		".docker/config.json": `{"auths":{"ghcr.io":{"auth":"` + planted["docker registry auth"] + `"}},` +
			`"credsStore":"desktop","currentContext":"orbstack"}`,
		".gitconfig": "[user]\n\tname = Test User\n" +
			"[url \"https://x-access-token:" + planted["git inline token"] + "@github.com/\"]\n" +
			"\tinsteadOf = https://github.com/\n",

		// Things that must never be captured.
		".aws/credentials":                 "[default]\naws_secret_access_key=" + planted["aws access key"] + "\n",
		".ssh/id_ed25519":                  planted["ssh private key"],
		".zsh_history":                     "export TOKEN=" + planted["shell history token"] + "\n",
		".config/gh/hosts.yml":             "github.com:\n  oauth_token: " + planted["gh cli token"] + "\n",
		".config/neonctl/credentials.json": `{"token":"` + planted["neon token"] + `"}`,
		".kube/config":                     "client-key-data: " + planted["kubeconfig secret"] + "\n",
		// A .env sitting inside a catalog-named directory: the basename rule has to
		// catch it wherever it turns up.
		"Library/Application Support/Code/User/snippets/.env": planted["dotenv secret"],
		"Library/Application Support/Code/User/settings.json": `{"editor.fontSize":13}`,
	}

	for rel, content := range files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// captureInto runs a full scan-and-write against a fixture home.
func captureInto(t *testing.T, home string) (string, *bundle.Manifest) {
	t.Helper()
	entries, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := Scan(home, entries)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	w, err := bundle.NewWriter(dir, bundle.Source{Username: "test", Hostname: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish("2026-09-08T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	return dir, w.Manifest()
}

// The headline guarantee: nothing secret reaches the bundle, by any route.
func TestNoPlantedSecretReachesTheBundle(t *testing.T) {
	home := fixtureHome(t)
	dir, _ := captureInto(t, home)

	var leaks []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		for name, marker := range planted {
			if strings.Contains(string(content), marker) {
				leaks = append(leaks, name+" leaked into "+rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range leaks {
		t.Error(l)
	}
}

// Excluding secrets is only half the job; the useful configuration has to survive.
func TestUsefulConfigIsCaptured(t *testing.T) {
	home := fixtureHome(t)
	dir, _ := captureInto(t, home)

	want := map[string]string{
		".zshrc":              "alias gs='git status'",
		".tmux.conf":          "set -g mouse on",
		".ssh/config":         "Host github.com",
		".ssh/known_hosts":    "ssh-ed25519",
		".npmrc":              "registry=https://registry.npmjs.org/",
		".docker/config.json": "orbstack",
		".gitconfig":          "insteadOf = https://github.com/",
		"Library/Application Support/Code/User/settings.json": "editor.fontSize",
	}
	for rel, substr := range want {
		p := filepath.Join(dir, "home", filepath.FromSlash(rel))
		content, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("%s was not captured: %v", rel, err)
			continue
		}
		if !strings.Contains(string(content), substr) {
			t.Errorf("%s captured but lost %q:\n%s", rel, substr, content)
		}
	}
}

// A public .pub key is exactly the kind of thing worth carrying across, and sits
// one directory away from material that must never move. Both outcomes matter.
func TestSSHPublicKeyKeptPrivateKeyExcluded(t *testing.T) {
	home := fixtureHome(t)
	dir, man := captureInto(t, home)

	if _, err := os.Stat(filepath.Join(dir, "home/.ssh/id_ed25519")); !os.IsNotExist(err) {
		t.Error("the SSH private key was captured")
	}
	excluded := map[string]string{}
	for _, e := range man.Excluded {
		excluded[e.Rel] = e.Reason
	}
	for _, rel := range []string{".aws/credentials", ".ssh/id_ed25519", ".zsh_history", ".kube/config"} {
		if _, ok := excluded[rel]; !ok {
			t.Errorf("%s was not recorded as excluded; the user has no way to know it was seen and skipped", rel)
		}
	}
}

// The scrub records are what lets doctor explain a 401 later, so they have to be
// specific rather than merely present.
func TestScrubRecordsNameTheFileAndReason(t *testing.T) {
	home := fixtureHome(t)
	_, man := captureInto(t, home)

	byFile := map[string][]string{}
	for _, r := range man.Scrubs {
		byFile[r.File] = append(byFile[r.File], r.Reason)
		if r.Count < 1 {
			t.Errorf("scrub record for %s has count %d", r.File, r.Count)
		}
	}
	for _, rel := range []string{".npmrc", ".docker/config.json", ".gitconfig"} {
		if len(byFile[rel]) == 0 {
			t.Errorf("no scrub record for %s", rel)
		}
	}
}

// Manifest items must reflect the scrubbed bytes, not the originals, or restore
// verification fails against every scrubbed file.
func TestManifestChecksumsMatchCapturedBytes(t *testing.T) {
	home := fixtureHome(t)
	dir, man := captureInto(t, home)

	if len(man.Items) == 0 {
		t.Fatal("manifest indexed nothing")
	}
	for _, item := range man.Items {
		p := filepath.Join(dir, "home", filepath.FromSlash(item.Rel))
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("manifest lists %s but it is not in the bundle", item.Rel)
			continue
		}
		if info.Size() != item.Size {
			t.Errorf("%s: manifest size %d, on-disk %d", item.Rel, item.Size, info.Size())
		}
		if item.Class == classify.Never {
			t.Errorf("%s: a never-classified item reached the manifest", item.Rel)
		}
	}
}

// A git clone inside a captured tree is somebody else's software, not
// configuration. On a real machine, powerlevel10k under ~/.oh-my-zsh/custom
// accounted for most of a 795-file capture and produced five of six
// secret-scanner findings from its own source — while the catalog entry's own
// note already said such clones must be cloned again rather than copied.
func TestCaptureSkipsGitClonesInsideACapturedTree(t *testing.T) {
	home := t.TempDir()
	custom := filepath.Join(home, ".oh-my-zsh", "custom")
	theme := filepath.Join(custom, "themes", "powerlevel10k")
	if err := os.MkdirAll(filepath.Join(theme, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The marker that makes it a clone.
	if err := os.MkdirAll(filepath.Join(theme, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(theme, "internal", "p10k.zsh"), "# thousands of lines\n")
	write(t, filepath.Join(theme, "powerlevel10k.zsh-theme"), "# theme\n")
	// The user's own file, beside it, which must still be captured.
	write(t, filepath.Join(custom, "mine.zsh"), "alias gs='git status'\n")

	p := &Plan{Home: home}
	entry := catalog.Entry{ID: "ohmyzsh"}
	cp := catalog.Path{Path: "~/.oh-my-zsh/custom", Class: "public"}
	if err := p.walkDir(home, entry, cp, custom, custom, map[string]bool{}); err != nil {
		t.Fatal(err)
	}

	for _, f := range p.Files {
		if strings.Contains(f.Rel, "powerlevel10k") {
			t.Errorf("a vendored clone should not be captured, got %s", f.Rel)
		}
	}
	var mine bool
	for _, f := range p.Files {
		if strings.HasSuffix(f.Rel, "mine.zsh") {
			mine = true
		}
	}
	if !mine {
		t.Error("the user's own file beside the clone must still be captured")
	}

	// Skipping silently would be the same bug in a different place.
	var reported bool
	for _, e := range p.Excluded {
		if strings.Contains(e.Rel, "powerlevel10k") {
			reported = true
			if !strings.Contains(e.Reason, "clone") {
				t.Errorf("the reason should say it is a clone, got %q", e.Reason)
			}
		}
	}
	if !reported {
		t.Error("a skipped clone must be reported, not silently dropped")
	}
}

// A directory that merely contains a file called .git-something is not a clone.
func TestIsGitCloneNeedsAnActualGitEntry(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".gitignore"), "x\n")

	if isGitClone(dir) {
		t.Error("a .gitignore does not make a directory a clone")
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isGitClone(dir) {
		t.Error("a .git directory does make it one")
	}
}

// A worktree or submodule uses a .git *file* rather than a directory.
func TestIsGitCloneAcceptsAGitFile(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".git"), "gitdir: /elsewhere/.git/modules/x\n")

	if !isGitClone(dir) {
		t.Error("a .git file marks a worktree or submodule and is still a clone")
	}
}
