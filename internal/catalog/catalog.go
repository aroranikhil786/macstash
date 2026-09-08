// Package catalog holds everything macstash knows about specific tools, as
// static YAML embedded in the binary. There is no inference and no network
// lookup: what the binary shipped with is what it knows.
package catalog

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/aroranikhil786/macstash/internal/classify"
)

//go:embed entries/*.yaml
var entriesFS embed.FS

// Load parses every embedded catalog entry. It fails rather than skipping a bad
// entry: a silently dropped entry is a tool that quietly does not migrate.
func Load() ([]Entry, error) {
	files, err := fs.Glob(entriesFS, "entries/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	seen := make(map[string]string, len(files))
	entries := make([]Entry, 0, len(files))
	for _, f := range files {
		data, err := entriesFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var e Entry
		if err := yaml.Unmarshal(data, &e); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if prev, dup := seen[e.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate entry id %q (also in %s)", f, e.ID, prev)
		}
		seen[e.ID] = f
		entries = append(entries, e)
	}
	return entries, nil
}

// Validate enforces the invariants that CI also checks, so a malformed or
// malicious entry cannot reach a capture even in a locally built binary.
func (e Entry) Validate() error {
	if e.ID == "" {
		return fmt.Errorf("entry has no id")
	}
	if e.Name == "" {
		return fmt.Errorf("%s: entry has no name", e.ID)
	}
	if len(e.Capture.Paths) == 0 {
		return fmt.Errorf("%s: entry captures nothing", e.ID)
	}
	for _, p := range e.Capture.Paths {
		if p.Path == "" {
			return fmt.Errorf("%s: path entry with empty path", e.ID)
		}
		switch p.Class {
		case classify.Public, classify.Scrub:
		case classify.Never:
			return fmt.Errorf("%s: %s declares class never; omit the path instead", e.ID, p.Path)
		default:
			return fmt.Errorf("%s: %s has unknown class %q", e.ID, p.Path, p.Class)
		}
		// A catalog entry must never name a path on the never list. This is the
		// check that stops a drive-by pull request from adding a credential path
		// (plan R10); CI runs the same assertion.
		rel := homeRelative(p.Path)
		if never, reason := classify.IsNever(rel); never {
			return fmt.Errorf("%s: %s is on the never list (%s)", e.ID, p.Path, reason)
		}
		if p.Class == classify.Scrub && len(p.Scrub) == 0 {
			return fmt.Errorf("%s: %s is class scrub but defines no scrub rules", e.ID, p.Path)
		}
		if p.Class == classify.Public && len(p.Scrub) > 0 {
			return fmt.Errorf("%s: %s is class public but defines scrub rules", e.ID, p.Path)
		}
		for _, r := range p.Scrub {
			if r.Reason == "" {
				return fmt.Errorf("%s: %s has a scrub rule with no reason; the reason is what doctor tells the user", e.ID, p.Path)
			}
		}
	}
	return nil
}

// homeRelative strips the leading ~/ from a catalog path.
func homeRelative(p string) string {
	if len(p) >= 2 && p[0] == '~' && p[1] == '/' {
		return p[2:]
	}
	return p
}
