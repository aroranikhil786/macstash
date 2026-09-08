package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMCP(t *testing.T, home, rel string, doc any) {
	t.Helper()
	path := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// The whole point of the inventory: the names of the variables a server needs
// travel, and their values never do.
func TestScanMCPServersRecordsEnvKeysButNeverValues(t *testing.T) {
	home := t.TempDir()
	const secret = "postgresql://user:sup3rs3cr3t@db.example.com/prod"
	writeMCP(t, home, ".cursor/mcp.json", map[string]any{
		"mcpServers": map[string]any{
			"postgres": map[string]any{
				"command": "docker",
				"args":    []string{"run", "-i", "crystaldba/postgres-mcp"},
				"env":     map[string]string{"DATABASE_URI": secret},
			},
		},
	})

	got := ScanMCPServers(home)

	if len(got) != 1 {
		t.Fatalf("want 1 server, got %d: %+v", len(got), got)
	}
	s := got[0]
	if s.Name != "postgres" || s.Command != "docker" {
		t.Errorf("server = %+v", s)
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "DATABASE_URI" {
		t.Errorf("env keys = %v, want [DATABASE_URI]", s.EnvKeys)
	}
	// The credential must not appear anywhere in the recorded struct, by any
	// field, however it got there.
	blob, _ := json.Marshal(s)
	for _, leak := range []string{secret, "sup3rs3cr3t", "db.example.com"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("the recorded server carries %q:\n%s", leak, blob)
		}
	}
}

// A remote server's headers are where its token lives, and its URL can carry
// one in the query string. Only the host survives.
func TestScanMCPServersKeepsOnlyTheHostOfARemoteServer(t *testing.T) {
	home := t.TempDir()
	writeMCP(t, home, ".claude.json", map[string]any{
		"mcpServers": map[string]any{
			"Neon": map[string]any{
				"type":    "http",
				"url":     "https://mcp.neon.tech/sse?access_token=napi_livetoken123456",
				"headers": map[string]string{"Authorization": "Bearer napi_livetoken123456"},
			},
		},
	})

	got := ScanMCPServers(home)

	if len(got) != 1 {
		t.Fatalf("want 1 server, got %d", len(got))
	}
	s := got[0]
	if s.Host != "mcp.neon.tech" {
		t.Errorf("host = %q, want mcp.neon.tech", s.Host)
	}
	if s.Transport != "http" {
		t.Errorf("transport = %q, want http", s.Transport)
	}
	// The header name is useful; the bearer token is not allowed anywhere.
	blob, _ := json.Marshal(s)
	for _, leak := range []string{"napi_livetoken123456", "access_token", "Bearer"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("the recorded server carries %q:\n%s", leak, blob)
		}
	}
	if len(s.EnvKeys) != 1 || s.EnvKeys[0] != "header:Authorization" {
		t.Errorf("env keys = %v, want the header name only", s.EnvKeys)
	}
}

// VS Code spells the top-level key "servers"; everyone else uses "mcpServers".
func TestScanMCPServersReadsBothTopLevelKeys(t *testing.T) {
	home := t.TempDir()
	writeMCP(t, home, "Library/Application Support/Code/User/mcp.json", map[string]any{
		"servers": map[string]any{
			"vscode-one": map[string]any{"command": "npx"},
		},
	})

	got := ScanMCPServers(home)

	if len(got) != 1 || got[0].Name != "vscode-one" {
		t.Fatalf("VS Code's schema was not read: %+v", got)
	}
}

func TestScanMCPServersReadsEveryKnownLocation(t *testing.T) {
	home := t.TempDir()
	for i, rel := range []string{".cursor/mcp.json", ".claude.json", ".claude/mcp.json"} {
		writeMCP(t, home, rel, map[string]any{
			"mcpServers": map[string]any{
				"server" + string(rune('a'+i)): map[string]any{"command": "npx"},
			},
		})
	}

	if got := ScanMCPServers(home); len(got) != 3 {
		t.Fatalf("want one server per config file, got %d: %+v", len(got), got)
	}
}

// The same server wired into two editors is one fact, not two.
func TestScanMCPServersDeduplicatesAcrossConfigs(t *testing.T) {
	home := t.TempDir()
	entry := map[string]any{
		"mcpServers": map[string]any{
			"context7": map[string]any{"command": "npx", "args": []string{"-y", "@upstash/context7-mcp"}},
		},
	}
	writeMCP(t, home, ".cursor/mcp.json", entry)
	writeMCP(t, home, ".claude.json", entry)

	if got := ScanMCPServers(home); len(got) != 1 {
		t.Fatalf("want the duplicate collapsed, got %d: %+v", len(got), got)
	}
}

func TestScanMCPServersWithNoConfigsReturnsNothing(t *testing.T) {
	if got := ScanMCPServers(t.TempDir()); len(got) != 0 {
		t.Fatalf("want none, got %+v", got)
	}
}

// A hand-edited config must not take the capture down with it.
func TestScanMCPServersSurvivesMalformedJSON(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeMCP(t, home, ".claude.json", map[string]any{
		"mcpServers": map[string]any{"good": map[string]any{"command": "npx"}},
	})

	got := ScanMCPServers(home)

	if len(got) != 1 || got[0].Name != "good" {
		t.Fatalf("a broken config should be skipped, not fatal: %+v", got)
	}
}

// The real package specifiers seen on a working machine, each of which the
// first version of this rule rejected.
func TestSafePackageAcceptsRealPackageSpecifiers(t *testing.T) {
	cases := map[string]string{
		"@upstash/context7-mcp@latest":         "@upstash/context7-mcp@latest",
		"@agentdeskai/browser-tools-mcp@1.2.0": "@agentdeskai/browser-tools-mcp@1.2.0",
		"@mettamatt/code-reasoning":            "@mettamatt/code-reasoning",
		"crystaldba/postgres-mcp":              "crystaldba/postgres-mcp",
		"tavily-mcp@0.1.3":                     "tavily-mcp@0.1.3",
		"mcp-server-fetch":                     "mcp-server-fetch",
	}
	for arg, want := range cases {
		if got := safePackage([]string{"-y", arg}); got != want {
			t.Errorf("safePackage(%q) = %q, want %q", arg, got, want)
		}
	}
}

// The reason args cannot be copied wholesale. Each of these is a shape a
// credential actually takes when passed positionally.
//
// The vendor-prefixed fixtures are deliberately malformed past the prefix —
// no digit groups, no plausible body. A fixture that reproduces a vendor's
// real token format trips GitHub push protection and blocks the repository,
// which one of these did. The prefix is the only part the code under test
// looks at, so keep them obviously synthetic.
func TestSafePackageRejectsCredentialShapes(t *testing.T) {
	for _, arg := range []string{
		"sk-ant-api03-fake-not-a-real-key",
		"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		"github_pat_11ABCDEFG0abcdefghij",
		"xoxb-fake-fake-not-a-real-token",
		"AKIAIOSFODNN7EXAMPLE",
		"550e8400-e29b-41d4-a716-446655440000",   // UUID
		"a3f5c9d2e1b874605fa2c3d4e5b6a7c8",       // hex key
		"dGhpcyBpcyBhIHNlY3JldCB0b2tlbiBoZXJlCg", // base64-ish
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",   // JWT header
		"postgresql://user:pass@host/db",
	} {
		if got := safePackage([]string{arg}); got != "" {
			t.Errorf("safePackage(%q) = %q, want it rejected", arg, got)
		}
	}
}

// The value after a flag is exactly what must not be taken: --token <secret>
// would otherwise record the secret as the package.
func TestSafePackageNeverTakesAFlagsValue(t *testing.T) {
	got := safePackage([]string{"--api-key", "sk-ant-api03-fake-not-a-real-key", "@scope/real-package"})

	if got != "@scope/real-package" {
		t.Errorf("safePackage = %q, want the package and not the key", got)
	}
}

func TestLooksLikePackageDiscriminatesOnStructure(t *testing.T) {
	yes := []string{"@scope/name", "crystaldba/postgres-mcp", "mcp-server-fetch", "server.py"}
	no := []string{"aBcDeFgHiJkLmNoP", "abcdef0123456789", "run", "postgres"}

	for _, s := range yes {
		if !looksLikePackage(s) {
			t.Errorf("looksLikePackage(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikePackage(s) {
			t.Errorf("looksLikePackage(%q) = true, want false", s)
		}
	}
}

// Whatever else changes, no value from a config file may reach the manifest.
// This is the invariant the whole inventory approach exists to guarantee.
func TestScanMCPServersNeverCarriesAnyConfiguredValue(t *testing.T) {
	home := t.TempDir()
	secrets := []string{
		"sup3rs3cr3t-password",
		"sk-ant-api03-leakcanary",
		"https://evil.example.com/callback?token=abc123",
	}
	writeMCP(t, home, ".cursor/mcp.json", map[string]any{
		"mcpServers": map[string]any{
			"kitchen-sink": map[string]any{
				"command": "npx",
				"args":    []string{"-y", "@scope/pkg", "--password", secrets[0], secrets[1]},
				"env":     map[string]string{"TOKEN": secrets[1], "CALLBACK": secrets[2]},
				"headers": map[string]string{"Authorization": secrets[1]},
			},
		},
	})

	blob, err := json.Marshal(ScanMCPServers(home))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(blob), s) {
			t.Fatalf("a configured value reached the manifest (%q):\n%s", s, blob)
		}
	}
	// It still has to be useful: the name and the variable names survive.
	for _, want := range []string{"kitchen-sink", "TOKEN", "CALLBACK", "@scope/pkg"} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("want %q recorded, got:\n%s", want, blob)
		}
	}
}
