package capture

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// mcpConfigLocations are the files that define MCP servers, $HOME-relative.
//
// Every one of these is on the never list or holds credentials inline, so none
// of them is ever captured as a file. They are read here to extract names only.
var mcpConfigLocations = []string{
	".cursor/mcp.json",
	".claude/mcp.json",
	".claude.json",
	"Library/Application Support/Claude/claude_desktop_config.json",
	"Library/Application Support/Code/User/mcp.json",
	".codeium/windsurf/mcp_config.json",
	".config/Code/User/mcp.json",
	".vscode/mcp.json",
}

// mcpFile is the subset of an MCP config worth parsing. Editors disagree on the
// top-level key — VS Code uses "servers", everything else uses "mcpServers" —
// so both are read.
type mcpFile struct {
	MCPServers map[string]mcpEntry `json:"mcpServers"`
	Servers    map[string]mcpEntry `json:"servers"`
}

type mcpEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
}

// ScanMCPServers records which MCP servers are configured, without carrying any
// of their configuration.
//
// MCP config files cannot be captured. A server definition holds its
// credentials inline — the file on the machine this was written against had a
// postgres URI, password included, inside `env` — and they can appear in `env`,
// in `args`, in a URL query string or in an auth header. There is no position a
// scrub rule could reliably clear, so the files stay on the never list.
//
// What is recoverable is the part that is actually hard to rebuild: that you
// had a postgres server wired up at all, and that it needed DATABASE_URI. The
// value is in a password manager or a dashboard; the knowledge that it was ever
// connected is only here. So this follows the same model as repositories and
// Docker images — listed, never copied.
func ScanMCPServers(home string) []bundle.MCPServer {
	var out []bundle.MCPServer
	seen := map[string]bool{}

	for _, rel := range mcpConfigLocations {
		path := filepath.Join(home, filepath.FromSlash(rel))
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var f mcpFile
		if err := json.Unmarshal(data, &f); err != nil {
			continue
		}
		for _, servers := range []map[string]mcpEntry{f.MCPServers, f.Servers} {
			for name, e := range servers {
				// The same server configured in two editors is one fact, not two.
				key := name + "\x00" + e.Command + "\x00" + e.URL
				if seen[key] {
					continue
				}
				seen[key] = true
				out = append(out, summariseMCP(name, rel, e))
			}
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// summariseMCP reduces one server definition to the facts that carry no secret.
func summariseMCP(name, source string, e mcpEntry) bundle.MCPServer {
	s := bundle.MCPServer{
		Name:    name,
		Source:  "~/" + source,
		Command: e.Command,
		Package: safePackage(e.Args),
	}

	// Env values are the commonest hiding place for a credential, so only the
	// variable names cross over. Knowing a server needs DATABASE_URI is the
	// useful half; the value is re-obtainable and must not travel.
	for k := range e.Env {
		s.EnvKeys = append(s.EnvKeys, k)
	}
	sort.Strings(s.EnvKeys)

	// A remote server's URL can carry a token in its query string, and its
	// headers almost always carry one. Only the host is recorded.
	if e.URL != "" {
		s.Transport = orFallback(e.Type, "remote")
		if u, err := url.Parse(e.URL); err == nil && u.Host != "" {
			s.Host = u.Host
		}
		for k := range e.Headers {
			s.EnvKeys = append(s.EnvKeys, "header:"+k)
		}
		sort.Strings(s.EnvKeys)
	}
	return s
}

func orFallback(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// packageShape matches an npm/PyPI package specifier or a plain path component.
// The inner @ is required for the common scoped-and-versioned form,
// @upstash/context7-mcp@latest, which is most of what MCP servers look like.
var packageShape = regexp.MustCompile(`^@?[A-Za-z0-9][A-Za-z0-9._/@-]*$`)

// credentialPrefixes are vendor token prefixes that happen to fit packageShape.
var credentialPrefixes = []string{
	"sk-", "pk-", "ghp_", "gho_", "ghu_", "ghs_", "github_pat_",
	"xoxb-", "xoxp-", "npm_", "glpat-", "AKIA", "ASIA", "hf_", "dop_v1_",
}

// safePackage picks the package specifier out of a server's args.
//
// Args cannot be copied wholesale: plenty of servers take their credential as a
// positional argument. Entropy alone cannot separate the two — a 32-character
// hex token scores about 3.9 bits per character and @upstash/context7-mcp
// scores about 3.8 — so the test is structural instead. A package specifier
// carries separators that a random token does not: a scope slash, a path
// slash, or lowercase words joined by hyphens or dots.
//
// The bias is deliberate. A rejected package name costs a web search; an
// accepted token costs a rotation.
func safePackage(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue // a flag, and the value after it is exactly what not to take
		}
		if len(a) > 80 || !packageShape.MatchString(a) {
			continue
		}
		if hasCredentialPrefix(a) || !looksLikePackage(a) {
			continue
		}
		if looksLikeHexBlob(a) {
			continue
		}
		return a
	}
	return ""
}

// looksLikePackage reports whether a string has the shape of a package
// specifier rather than a secret.
//
// A slash means a scope, a path or a container image, none of which a token
// has. Failing that, lowercase words joined by a hyphen or a dot are the npm
// and PyPI naming convention; a random token is either mixed-case or
// unseparated, and fails both tests.
func looksLikePackage(s string) bool {
	if strings.Contains(s, "/") {
		return true
	}
	if strings.ToLower(s) != s {
		return false
	}
	return strings.Contains(s, "-") || strings.Contains(s, ".")
}

func hasCredentialPrefix(s string) bool {
	for _, p := range credentialPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hexBlob matches a long run of hex digits and dashes: a UUID, a hex API key,
// a commit-like digest.
var hexBlob = regexp.MustCompile(`^[0-9a-f-]{24,}$`)

// looksLikeHexBlob catches the one secret shape that survives the structural
// test. A UUID is lowercase and hyphen-separated, so it reads as a package
// name; nothing else about it does. Entropy cannot be used here — a UUID draws
// from sixteen symbols and scores lower than a real package name.
func looksLikeHexBlob(s string) bool {
	return hexBlob.MatchString(s)
}
