// Package bundle reads and writes macstash bundles.
package bundle

import (
	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/scanner"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

// SchemaVersion is bumped whenever the manifest shape changes incompatibly.
const SchemaVersion = 1

// ManifestName is the manifest file at the root of every bundle.
const ManifestName = "macstash.json"

// Manifest is the index of a bundle. It records what was captured, what was
// deliberately left out, and what was edited on the way in. It never contains
// file contents.
type Manifest struct {
	SchemaVersion int            `json:"schema_version"`
	CreatedAt     string         `json:"created_at"`
	Source        Source         `json:"source"`
	Items         []Item         `json:"items"`
	Brewfile      *Brew          `json:"brewfile,omitempty"`
	Scrubs        []scrub.Record `json:"scrubs,omitempty"`
	// Excluded records paths that were seen and deliberately not captured. This is
	// transparency rather than bookkeeping: a user comparing two machines should be
	// able to see that ~/.aws/credentials was found and left behind on purpose,
	// not that macstash never looked.
	Excluded []Excluded `json:"excluded,omitempty"`
	// Notes are per-entry restore caveats carried from the catalog.
	Notes []Note `json:"notes,omitempty"`
	// Requirements are per-entry restore preconditions (quit_first, permissions).
	Requirements []Requirement `json:"requirements,omitempty"`
	// Applications is the full inventory, including the many that Homebrew did
	// not install and a restore therefore cannot bring back on its own.
	Applications []App `json:"applications,omitempty"`
	// Repos records how to clone each working tree back, never its contents.
	Repos []Repo `json:"repos,omitempty"`
	// System is the list-shaped inventory: versions, packages, extensions.
	System System `json:"system,omitempty"`
	// LaunchAgents are background jobs. Never restored without an explicit flag.
	LaunchAgents []LaunchAgent `json:"launch_agents,omitempty"`
	// ScanFindings are things the secret scanner wants a human to look at. They
	// were captured, not removed — the scanner only ever reports.
	ScanFindings []scanner.Finding `json:"scan_findings,omitempty"`
}

// Source identifies the machine a bundle came from.
type Source struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Shell    string `json:"shell"`
	Version  string `json:"macstash_version"`
}

// Item is one captured file.
type Item struct {
	Entry  string         `json:"entry"`
	Rel    string         `json:"rel"`
	Class  classify.Class `json:"class"`
	Mode   uint32         `json:"mode"`
	Size   int64          `json:"size"`
	SHA256 string         `json:"sha256"`
}

// Excluded is one path that the never list kept out of the bundle.
type Excluded struct {
	Rel    string `json:"rel"`
	Reason string `json:"reason"`
}

// Note is a restore caveat from a catalog entry.
type Note struct {
	Entry string `json:"entry"`
	Text  string `json:"text"`
}

// Requirement is what a catalog entry needs at restore time.
//
// These are the accumulated facts the plan calls the actual product: which apps
// rewrite their config on quit and must therefore be closed first, and which
// need a permission that only a human clicking in System Settings can grant.
// Capturing them and then not acting on them is the same as not knowing them.
type Requirement struct {
	Entry string `json:"entry"`
	Name  string `json:"name"`
	// QuitFirst means the app rewrites its own config when it exits, so
	// restoring while it runs silently loses the restore.
	QuitFirst bool `json:"quit_first,omitempty"`
	// Permissions are macOS privacy permissions a human must grant by hand.
	Permissions []string `json:"permissions,omitempty"`
	// Category groups entries in `macstash catalog`.
	Category string `json:"category,omitempty"`
}

// App is one application found on the machine.
type App struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Version  string `json:"version,omitempty"`
	BundleID string `json:"bundle_id,omitempty"`
	// Source is how the app got here, and therefore whether a restore can bring
	// it back automatically.
	Source string `json:"source"`
	// CaskToken is the Homebrew cask that can install this app, where one
	// exists. An app downloaded as a disk image is not thereby uninstallable by
	// Homebrew — most of them have a cask — so this is resolved at capture and
	// carried, turning a hand-reinstall checklist into something restore can do.
	CaskToken string `json:"cask_token,omitempty"`
}

// Repo is one git working tree. Only what is needed to clone it again is kept;
// the working tree itself is never captured.
type Repo struct {
	Path     string `json:"path"`
	Remote   string `json:"remote,omitempty"`
	Branch   string `json:"branch,omitempty"`
	Dirty    bool   `json:"dirty,omitempty"`
	Unpushed int    `json:"unpushed,omitempty"`
	NoRemote bool   `json:"no_remote,omitempty"`
	// NoUpstream means the checked-out branch tracks nothing, so its commits
	// exist only on this machine however clean the tree looks.
	NoUpstream bool `json:"no_upstream,omitempty"`
}

// AtRisk reports whether this repository holds work a migration would destroy.
func (r Repo) AtRisk() bool {
	return r.NoRemote || r.Dirty || r.Unpushed > 0 || r.NoUpstream
}

// System is everything that is a list rather than a file: runtime versions,
// globally installed packages, editor extensions and the settings that live
// outside any single config file. Nothing here is copied — it is recorded so the
// same things can be installed again from the same public sources.
type System struct {
	SDKs         map[string][]string `json:"sdks,omitempty"`
	Toolchains   map[string][]string `json:"toolchains,omitempty"`
	Extensions   map[string][]string `json:"editor_extensions,omitempty"`
	LoginItems   []string            `json:"login_items,omitempty"`
	KubeContexts []string            `json:"kube_contexts,omitempty"`
	// DockerImages are names only. Images are never bundled: they are large and
	// re-pullable, and a bundle is meant to fit on a USB stick.
	DockerContexts []string          `json:"docker_contexts,omitempty"`
	DockerImages   []string          `json:"docker_images,omitempty"`
	Keyboard       map[string]string `json:"keyboard,omitempty"`
	DefaultApps    map[string]string `json:"default_apps,omitempty"`
	HostsEntries   []string          `json:"hosts_entries,omitempty"`
	// MCPServers is which MCP servers were configured, never how. The config
	// files themselves are on the never list.
	MCPServers []MCPServer `json:"mcp_servers,omitempty"`
	// Prefs are exported preference domains, catalog-named only.
	Prefs []string `json:"exported_pref_domains,omitempty"`
	// PrefOwners maps a catalog entry id to the preference domains it owns, so
	// restore can tell whether a domain belongs to an app that must be quit.
	PrefOwners map[string][]string `json:"pref_owners,omitempty"`
}

// MCPServer is one configured MCP server, reduced to the facts that carry no
// secret.
//
// The definition is never captured. Credentials appear in `env`, in positional
// args, in a URL query string and in auth headers, so there is no position a
// scrub rule could reliably clear. What travels is the name, what launched it,
// and the names of the variables it needed — enough to wire it up again.
type MCPServer struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Command string `json:"command,omitempty"`
	Package string `json:"package,omitempty"`
	// EnvKeys are variable names only, never values.
	EnvKeys []string `json:"env_keys,omitempty"`
	// Transport and Host describe a remote server. The full URL is not kept:
	// it can carry a token in its query string.
	Transport string `json:"transport,omitempty"`
	Host      string `json:"host,omitempty"`
}

// LaunchAgent is one per-user background job.
//
// Content is carried so the agent can be restored, but restore refuses to write
// any of them without an explicit flag: a LaunchAgent runs code at every login,
// and that is not something to reinstate by accident.
type LaunchAgent struct {
	Label            string   `json:"label"`
	File             string   `json:"file"`
	ProgramArguments []string `json:"program_arguments,omitempty"`
	RunAtLoad        bool     `json:"run_at_load,omitempty"`
	KeepAlive        bool     `json:"keep_alive,omitempty"`
	Content          []byte   `json:"-"`
}

// Brew summarises the captured Brewfile, and carries the counts that capture
// cross-checked so restore and inspect can re-verify them.
type Brew struct {
	Formulae int `json:"formulae"`
	Casks    int `json:"casks"`
	Taps     int `json:"taps"`
	// Packages are the names, so doctor can say which one is missing rather than
	// only that a count no longer matches.
	Packages  []string `json:"packages,omitempty"`
	Casknames []string `json:"casknames,omitempty"`
}
