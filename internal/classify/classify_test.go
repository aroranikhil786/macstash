package classify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsNever(t *testing.T) {
	cases := []struct {
		rel  string
		want bool
	}{
		// Credential files seen on real machines.
		{".aws/credentials", true},
		{".zsh_history", true},
		{".netrc", true},
		{".git-credentials", true},
		{".kube/config", true},
		{".config/gh/hosts.yml", true},

		// Token stores under ~/.config. neonctl is the one no published exclude
		// list mentions; it is why capture is allowlist-only and this list is only
		// the backstop.
		{".config/neonctl/credentials.json", true},
		{".config/configstore/update-notifier-npm.json", true},
		{".config/op/config", true},
		{".config/fly/config.yml", true},

		// SSH: private keys out, public keys and config in.
		{".ssh/id_ed25519", true},
		{".ssh/id_rsa", true},
		{".ssh/id_ed25519.pub", true},
		{".ssh/config", false},
		{".ssh/known_hosts", false},

		// Basename globs, at any depth, files or directories.
		{".env", true},
		{".env.local", true},
		{"project/.env.production", true},
		{".config/iterm2/cert.pem", true},
		{"work/service.key", true},
		{"a/b/c/keys.jks", true},
		{".env/notes.txt", true},

		// Editor secret storage.
		{"Library/Application Support/Code/User/globalStorage/state.vscdb", true},
		{"Library/Keychains/login.keychain-db", true},

		// Things that must survive, or the tool has no reason to exist.
		{".zshrc", false},
		{".gitconfig", false},
		{".tmux.conf", false},
		{".aws/config", false},
		{".npmrc", false},
		{".docker/config.json", false},
		{"Library/Application Support/Code/User/settings.json", false},
	}
	for _, c := range cases {
		got, reason := IsNever(c.rel)
		if got != c.want {
			t.Errorf("IsNever(%q) = %v (%s), want %v", c.rel, got, reason, c.want)
		}
		if got && reason == "" {
			t.Errorf("IsNever(%q) excluded with no reason given", c.rel)
		}
	}
}

// Public keys are not carried. The private half stays behind, so restoring the
// public half authorises nothing and only makes ~/.ssh look as though a working
// key is there — while the fingerprint recorded in the manifest still names the
// key to revoke.
func TestPublicKeysAreNotCarried(t *testing.T) {
	for _, rel := range []string{
		".ssh/id_ed25519.pub",
		".ssh/id_rsa.pub",
		".ssh/my_new_key.pub",
	} {
		never, reason := IsNever(rel)
		if !never {
			t.Errorf("IsNever(%q) = false, want the public key left behind", rel)
		}
		// The reason is printed to the user, and "treated as key material" would
		// be a lie about a public key.
		if strings.Contains(reason, "key material") {
			t.Errorf("IsNever(%q) reason %q misdescribes a public key", rel, reason)
		}
	}
}

// A catalog entry naming a symlink must not become a way to reach a never path.
func TestResolveFollowsSymlinksIntoNeverPaths(t *testing.T) {
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".aws"))
	write(t, filepath.Join(home, ".aws/credentials"), "[default]\naws_access_key_id=AKIAFAKE\n")

	link := filepath.Join(home, ".config-backup")
	if err := os.Symlink(filepath.Join(home, ".aws/credentials"), link); err != nil {
		t.Fatal(err)
	}

	got := Resolve(home, link, Public)
	if got.Class != Never {
		t.Fatalf("symlink to ~/.aws/credentials classified %q, want never", got.Class)
	}
}

// A symlink pointing out of $HOME is refused rather than followed.
func TestResolveRefusesEscapingSymlink(t *testing.T) {
	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere")
	write(t, outside, "x")

	link := filepath.Join(home, ".zshrc")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	got := Resolve(home, link, Public)
	if got.Class != Never || !got.Escaped {
		t.Fatalf("escaping symlink = %+v, want never/escaped", got)
	}
}

// The never list overrides whatever the catalog declared.
func TestResolveNeverBeatsDeclaredClass(t *testing.T) {
	home := t.TempDir()
	mkdir(t, filepath.Join(home, ".aws"))
	p := filepath.Join(home, ".aws/credentials")
	write(t, p, "secret")

	if got := Resolve(home, p, Scrub); got.Class != Never {
		t.Fatalf("declared scrub on a never path = %q, want never", got.Class)
	}
	if got := Resolve(home, p, Public); got.Class != Never {
		t.Fatalf("declared public on a never path = %q, want never", got.Class)
	}
}

func TestResolvePassesThroughDeclaredClass(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, ".npmrc")
	write(t, p, "registry=https://registry.npmjs.org/\n")

	if got := Resolve(home, p, Scrub); got.Class != Scrub {
		t.Fatalf("~/.npmrc = %q, want scrub", got.Class)
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A private key does not have to be called id_something. The first real machine
// this ran against had one called my_new_key; an id_* rule would have missed it,
// and the only reason it did not leak was that the catalog never named ~/.ssh as
// a directory. Relying on that is relying on nobody ever broadening the catalog.
func TestSSHDirectoryIsDefaultDeny(t *testing.T) {
	excluded := []string{
		".ssh/my_new_key",
		".ssh/work-github",
		".ssh/deploy_key_prod",
		".ssh/id_ed25519",
		".ssh/agent",
		".ssh/anything_at_all",
	}
	for _, rel := range excluded {
		if never, _ := IsNever(rel); !never {
			t.Errorf("IsNever(%q) = false; everything in ~/.ssh that is not explicitly allowed must be excluded", rel)
		}
	}

	allowed := []string{
		".ssh/config",
		".ssh/known_hosts",
		".ssh/known_hosts.old",
		".ssh/authorized_keys",
		".ssh/config.d/work",
	}
	for _, rel := range allowed {
		if never, reason := IsNever(rel); never {
			t.Errorf("IsNever(%q) = true (%s); this is configuration worth migrating", rel, reason)
		}
	}
}
