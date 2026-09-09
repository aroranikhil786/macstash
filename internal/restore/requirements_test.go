package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// An insteadOf rule pointing at SSH is correct config that cannot work without
// a key. Restoring it onto a fresh machine broke git and Homebrew together, and
// restore knew both halves without connecting them.
func TestGitRewritesToSSHIsDetected(t *testing.T) {
	cases := map[string]bool{
		"[url \"git@github.com:\"]\n\tinsteadOf = https://github.com/\n":     true,
		"[url \"ssh://git@gerrit.internal/\"]\n\tinsteadOf = https://g/\n":   true,
		"[url \"https://github.com/\"]\n\tinsteadOf = git@github.com:\n":     false,
		"[user]\n\tname = Someone\n":                                         false,
		"[url \"git@github.com:\"]\n\tpushInsteadOf = https://github.com/\n": true,
		"": false,
	}
	for cfg, want := range cases {
		home := t.TempDir()
		if cfg != "" {
			if err := os.WriteFile(filepath.Join(home, ".gitconfig"), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got := GitRewritesToSSH(home); got != want {
			t.Errorf("GitRewritesToSSH(%q) = %v, want %v", cfg, got, want)
		}
	}
}

// A public key on its own authenticates nothing, so it must not count as having
// a key. That is the same reasoning that stopped macstash carrying them.
func TestHasSSHKeyIgnoresPublicHalves(t *testing.T) {
	home := t.TempDir()
	if HasSSHKey(home) {
		t.Error("no .ssh directory at all, so no key")
	}

	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519.pub", "config", "known_hosts"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if HasSSHKey(home) {
		t.Error("a public key without its private half is not a usable key")
	}

	if err := os.WriteFile(filepath.Join(dir, "id_ed25519"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !HasSSHKey(home) {
		t.Error("the private key is there now")
	}
}

// The catalog calls it iTerm2 and System Settings lists iTerm. Printing the
// catalog's word sends someone scanning the privacy list for a name that is not
// in it, which is exactly what happened.
func TestPermissionChecklistNamesAppsAsMacOSDoes(t *testing.T) {
	out := PermissionChecklist([]bundle.Requirement{
		{Entry: "iterm2", Name: "iTerm2", AppName: "iTerm", Permissions: []string{"full_disk_access"}},
	})

	if !strings.Contains(out, "Full Disk Access") {
		t.Errorf("want the System Settings wording, got:\n%s", out)
	}
	if strings.Contains(out, "full_disk_access") {
		t.Errorf("the raw identifier leaked, got:\n%s", out)
	}
	if !strings.Contains(out, "iTerm\n") {
		t.Errorf("want the application named as macOS names it, got:\n%s", out)
	}
}
