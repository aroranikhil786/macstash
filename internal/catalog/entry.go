package catalog

import (
	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

// Entry is one tool macstash knows about. The accumulated quit_first flags,
// permission lists and scrub patterns across these entries are the actual
// product — they are the part nobody else has written down.
type Entry struct {
	ID       string  `yaml:"id"`
	Name     string  `yaml:"name"`
	Category string  `yaml:"category"`
	Detect   Detect  `yaml:"detect"`
	Capture  Capture `yaml:"capture"`
	Restore  Restore `yaml:"restore"`
}

// Detect describes how to tell whether this tool is present on a machine. Any
// one match is enough.
type Detect struct {
	App      string `yaml:"app"`
	BrewCask string `yaml:"brew_cask"`
	Command  string `yaml:"command"`
	Path     string `yaml:"path"`
}

// Capture lists what to collect. Directories are allowlist-only: naming a
// directory captures the files under it, but there is no wholesale capture of a
// container directory like ~/.config.
type Capture struct {
	Paths []Path `yaml:"paths"`
	// Defaults are preference domains to export. Third-party domains are exported
	// only when a catalog entry names them; there is no wholesale sweep of
	// `defaults domains`, which on a normal Mac returns several hundred.
	Defaults []DefaultsDomain `yaml:"defaults"`
}

// DefaultsDomain is one preference domain named by a catalog entry.
type DefaultsDomain struct {
	Domain string `yaml:"domain"`
}

// Path is a single captured file or directory and its declared class. The
// declaration is an upper bound only — classify.Resolve can downgrade it to
// never, and nothing can upgrade a never path.
type Path struct {
	Path  string         `yaml:"path"`
	Class classify.Class `yaml:"class"`
	Scrub []scrub.Rule   `yaml:"scrub"`
	// Skip are glob patterns, relative to Path, excluded when Path is a directory.
	Skip []string `yaml:"skip"`
	// TextOnly excludes binaries. Directories like ~/.local/bin hold a mix of
	// personal shell scripts, which are worth migrating, and vendored binaries
	// installed by other tools, which are not: they are large, architecture
	// specific, and their installer will put them back.
	TextOnly bool `yaml:"text_only"`
	// MaxSize caps individual file size in bytes; 0 means the global default.
	MaxSize int64 `yaml:"max_size"`
}

// Restore carries the knowledge that makes a restore actually work rather than
// merely complete.
type Restore struct {
	// QuitFirst marks apps that rewrite their own config on quit, and would
	// therefore overwrite whatever we just restored the moment they close.
	QuitFirst   bool     `yaml:"quit_first"`
	Permissions []string `yaml:"permissions"`
	Note        string   `yaml:"note"`
}
