package classify

// The never list. It lives in Go rather than YAML on purpose: a catalog entry —
// including one arriving as a drive-by pull request — must not be able to add a
// credential path or downgrade one of these (plan R10).
//
// This list is the second line of defence, not the first. The primary control is
// that directories are captured allowlist-only, because an exclude list is always
// one release behind the next CLI that decides to store a token in ~/.config. That
// is not hypothetical: the machine this was first developed on had a
// ~/.config/neonctl token store that no published exclude list mentions.

// neverExact are $HOME-relative paths that are never captured and never restored.
var neverExact = map[string]string{
	".netrc":                             "machine credentials",
	".claude/config.json":                "may hold API key approvals",
	".claude/.credentials.json":          "agent auth token",
	".git-credentials":                   "git credential store",
	".aws/credentials":                   "AWS access keys",
	".kube/config":                       "cluster credentials",
	".cargo/credentials.toml":            "crates.io token",
	".terraform.d/credentials.tfrc.json": "Terraform Cloud token",
	".config/gh/hosts.yml":               "GitHub CLI token",
	".m2/settings-security.xml":          "Maven master password",
	".zsh_history":                       "shell history may contain pasted tokens",
	".bash_history":                      "shell history may contain pasted tokens",
	".local/share/fish/fish_history":     "shell history may contain pasted tokens",
}

// neverDirs are $HOME-relative directory prefixes. Everything beneath them is
// excluded, at any depth.
var neverDirs = map[string]string{
	// Keychain, cookies, browser profiles
	"Library/Keychains":                         "macOS keychain",
	"Library/Cookies":                           "cookie store",
	"Library/Safari":                            "browser profile",
	"Library/Containers":                        "sandboxed app containers",
	"Library/Application Support/Google/Chrome": "browser profile",
	"Library/Application Support/Firefox":       "browser profile",
	"Library/Application Support/Arc":           "browser profile",
	"Library/Application Support/BraveSoftware": "browser profile",

	// Private key material
	".gnupg/private-keys-v1.d": "GPG private keys",

	// Cloud credentials
	".aws/sso/cache": "AWS SSO cache",
	".aws/cli/cache": "AWS CLI credential cache",
	".azure":         "Azure tokens",
	".config/gcloud": "gcloud credentials",
	".kube/cache":    "kube cache",

	// CLI token stores
	".config/op":          "1Password CLI",
	".config/doctl":       "DigitalOcean token",
	".config/configstore": "npm-configstore token store",
	".config/neonctl":     "Neon auth token",
	".wrangler":           "Cloudflare token",
	".vercel":             "Vercel token",
	".netlify":            "Netlify token",
	".docker/contexts":    "may embed endpoint credentials",

	// Editor secret stores. state.vscdb is the archetype of "looks like state,
	// is a token store".
	"Library/Application Support/Code/User/globalStorage":   "VS Code secret storage",
	"Library/Application Support/Cursor/User/globalStorage": "Cursor secret storage",

	// Session state
	".zsh_sessions": "shell session history",

	// Agent/CLI working state. ~/.claude holds genuinely useful configuration
	// alongside 44MB of conversation transcripts and a prompt history, and the
	// transcripts contain whatever has ever been pasted into them.
	".claude/projects":        "conversation transcripts",
	".claude/history.jsonl":   "prompt history may contain pasted tokens",
	".claude/paste-cache":     "pasted content",
	".claude/file-history":    "file snapshots",
	".claude/shell-snapshots": "captured shell environments",
	".claude/todos":           "working state",
	".claude/cache":           "cache",
	".claude/downloads":       "downloaded files",
	".claude/backups":         "backups of other files",
	".claude/ide":             "editor session state",
	".claude/statsig":         "feature-flag state",

	// Android debug bridge keys are private keys with an unhelpful name.
	".android/adbkey": "ADB private key",
}

// neverDirGlobs are $HOME-relative directory prefixes matched as globs, for
// families of tools that version their config directory.
var neverDirGlobs = map[string]string{
	".config/fly*":    "Fly.io token",
	".claude/daemon*": "daemon auth state",
}

// neverBasenames are matched against the file name at any depth inside any
// captured tree.
var neverBasenames = map[string]string{
	".env":               "environment file",
	".env.*":             "environment file",
	"*.pem":              "private key or certificate",
	"*.key":              "private key",
	"*.p12":              "key bundle",
	"*.pfx":              "key bundle",
	"*.jks":              "Java keystore",
	"*.keystore":         "keystore",
	"secring.gpg":        "GPG secret keyring",
	"state.vscdb":        "editor secret storage",
	"state.vscdb.backup": "editor secret storage",
}
