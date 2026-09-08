package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// LaunchAgent file names come out of the manifest, which is attacker-controlled
// for any bundle the user did not create themselves — and restoring another
// user's bundle is a documented flow. filepath.Join cleans ".." rather than
// rejecting it, so an unvalidated name writes anywhere under ~/Library.
func TestLaunchAgentNamesCannotEscapeTheDirectory(t *testing.T) {
	hostile := []string{
		"../Application Support/Code/User/settings.json",
		"../../.zshrc",
		"../Services/evil.workflow",
		"sub/dir.plist",
		"/etc/passwd",
		"..",
		"",
		"noplistsuffix",
	}
	for _, name := range hostile {
		if validAgentFile(name) {
			t.Errorf("validAgentFile(%q) = true; this name escapes or is not a plist", name)
		}
	}

	legitimate := []string{
		"com.acme.updater.plist",
		"in.rentsorted.daily-ig.plist",
		"a.plist",
	}
	for _, name := range legitimate {
		if !validAgentFile(name) {
			t.Errorf("validAgentFile(%q) = false; this is a normal LaunchAgent name", name)
		}
	}
}

// End to end: a crafted manifest must not write outside ~/Library/LaunchAgents.
func TestRestoreLaunchAgentsRefusesTraversal(t *testing.T) {
	home := t.TempDir()
	staging := t.TempDir()

	// Plant the payload where the traversal would read it from.
	payload := filepath.Join(staging, "Application Support", "Code", "User")
	if err := os.MkdirAll(payload, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(payload, "settings.json"), []byte(`{"evil":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A victim file the traversal would overwrite.
	victim := filepath.Join(home, "Library", "Application Support", "Code", "User")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"editor.fontSize":13}`)
	if err := os.WriteFile(filepath.Join(victim, "settings.json"), original, 0o600); err != nil {
		t.Fatal(err)
	}

	agents := []bundle.LaunchAgent{{
		Label: "evil",
		File:  "../Application Support/Code/User/settings.json",
	}}

	var out bytes.Buffer
	if err := RestoreLaunchAgents(home, agents, staging, true, true, &out); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(victim, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("a crafted LaunchAgent name overwrote a file outside LaunchAgents: %s", got)
	}
	if !strings.Contains(out.String(), "REFUSED") {
		t.Errorf("the traversal was not reported to the user:\n%s", out.String())
	}
}
