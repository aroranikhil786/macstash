package classify

import "testing"

// These were found on a real machine during a coverage audit, each one a
// credential store that no published exclude list mentions. They are the
// plan's own thesis restated: the never list is always one CLI behind, which
// is why allowlist capture is the primary control and this is the backstop.
func TestNeverListCoversCredentialStoresFoundInTheWild(t *testing.T) {
	cases := map[string]string{
		".claude.json":                         "Claude Code project history",
		".claude.json.backup":                  "Claude Code project history",
		".gemini/oauth_creds.json":             "Gemini CLI OAuth",
		".gemini/google_accounts.json":         "Google account identifiers",
		".mcp-auth/mcp-remote-0.1.37/tok.json": "MCP remote OAuth tokens",
		".emulator_console_auth_token":         "Android emulator token",
		".copilot/command-history-state.json":  "Copilot prompt history",
		".gem/credentials":                     "RubyGems API key",
		".m2/settings.xml":                     "Maven repository passwords",
		".cocoapods/trunk/me.json":             "CocoaPods trunk token",
	}
	for path, what := range cases {
		if never, _ := IsNever(path); !never {
			t.Errorf("%s (%s) is not on the never list", path, what)
		}
	}
}

// An MCP config holds its credentials inside a nested `env` object, out of
// reach of a top-level key drop, so the whole file has to stay out — at any
// depth, under any tool's directory.
func TestNeverListKeepsMCPConfigsOutAtAnyDepth(t *testing.T) {
	for _, path := range []string{
		".cursor/mcp.json",
		".claude/mcp.json",
		".config/some-future-tool/mcp.json",
	} {
		if never, _ := IsNever(path); !never {
			t.Errorf("%s should never be captured: env blocks carry secrets", path)
		}
	}
}

// The entries added alongside these must not have swallowed the safe files the
// catalog now depends on, or three catalog entries silently capture nothing.
func TestNewlyCatalogedConfigFilesAreStillCapturable(t *testing.T) {
	for _, path := range []string{
		".gemini/settings.json",
		".copilot/config.json",
		".copilot/permissions-config.json",
		".cursor/hooks.json",
	} {
		if never, reason := IsNever(path); never {
			t.Errorf("%s is catalogued but blocked by the never list (%s)", path, reason)
		}
	}
}
