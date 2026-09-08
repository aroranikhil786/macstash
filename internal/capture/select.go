package capture

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/selection"
)

// Selection category names. These are the section headers in the edited file
// and are part of its format: renaming one invalidates saved selections.
const (
	CatConfigs    = "configs"
	CatApps       = "applications"
	CatRepos      = "repositories"
	CatFormulae   = "brew-formulae"
	CatCasks      = "brew-casks"
	CatExtensions = "editor-extensions"
	CatToolchains = "global-packages"
	CatMCP        = "mcp-servers"
)

// SelectionDocument describes everything in a plan that a person might
// reasonably not want to carry.
//
// Not everything is offered. Captured files are offered by catalog entry rather
// than individually, because the entries are already the unit people think in
// and a per-file list would run to hundreds of lines. Preference domains,
// LaunchAgents and login items are left out: they are already gated or small
// enough that pruning them is not worth an editing pass.
func (p *Plan) SelectionDocument() selection.Document {
	var d selection.Document

	if entries := p.entryCounts(); len(entries) > 0 {
		items := make([]selection.Item, 0, len(entries))
		for _, e := range sortedKeys(entries) {
			items = append(items, selection.Item{
				Key:      e,
				Note:     fmt.Sprintf("%d file(s)", entries[e]),
				Selected: true,
			})
		}
		d.Categories = append(d.Categories, selection.Category{
			Name:  CatConfigs,
			Help:  "Configuration. Excluding one leaves its files out of the bundle entirely.",
			Items: items,
		})
	}

	if len(p.Applications) > 0 {
		var items []selection.Item
		for _, a := range p.Applications {
			// Homebrew and Apple already account for these; there is nothing to
			// decide about them.
			if a.Source == SourceHomebrew || a.Source == SourceSystem {
				continue
			}
			note := a.Version
			if a.CaskToken != "" {
				note = strings.TrimSpace(note + "  (cask: " + a.CaskToken + ")")
			}
			items = append(items, selection.Item{Key: a.Name, Note: note, Selected: true})
		}
		if len(items) > 0 {
			d.Categories = append(d.Categories, selection.Category{
				Name:  CatApps,
				Help:  "Applications. Excluded ones are neither recorded nor offered at restore.",
				Items: items,
			})
		}
	}

	if len(p.Repos) > 0 {
		items := make([]selection.Item, 0, len(p.Repos))
		for _, r := range p.Repos {
			var flags []string
			if r.NoRemote {
				flags = append(flags, "NO REMOTE")
			}
			if r.Dirty {
				flags = append(flags, "uncommitted")
			}
			if r.Unpushed > 0 {
				flags = append(flags, fmt.Sprintf("%d unpushed", r.Unpushed))
			}
			items = append(items, selection.Item{
				Key: r.Path, Note: strings.Join(flags, ", "), Selected: true,
			})
		}
		d.Categories = append(d.Categories, selection.Category{
			Name: CatRepos,
			Help: "Repositories. Only the remote and branch are recorded, never contents.\n" +
				"A repository marked NO REMOTE exists nowhere else — excluding it removes\n" +
				"the only record that it was ever here.",
			Items: items,
		})
	}

	if p.Brew != nil {
		formulae, casks := parseBrewfile(p.Brew.Content)
		if len(formulae) > 0 {
			d.Categories = append(d.Categories, selection.Category{
				Name:  CatFormulae,
				Help:  "Homebrew formulae, as `brew bundle dump` found them.",
				Items: itemsFor(formulae),
			})
		}
		if len(casks) > 0 {
			d.Categories = append(d.Categories, selection.Category{
				Name:  CatCasks,
				Items: itemsFor(casks),
			})
		}
	}

	if n := len(p.System.Extensions); n > 0 {
		var items []selection.Item
		for _, editor := range sortedKeys(p.System.Extensions) {
			for _, id := range p.System.Extensions[editor] {
				items = append(items, selection.Item{
					Key: editor + ":" + id, Selected: true,
				})
			}
		}
		d.Categories = append(d.Categories, selection.Category{
			Name:  CatExtensions,
			Help:  "Editor extensions, listed as editor:extension-id.",
			Items: items,
		})
	}

	if len(p.System.Toolchains) > 0 {
		var items []selection.Item
		for _, manager := range sortedKeys(p.System.Toolchains) {
			for _, pkg := range p.System.Toolchains[manager] {
				items = append(items, selection.Item{
					Key: manager + ":" + pkg, Selected: true,
				})
			}
		}
		d.Categories = append(d.Categories, selection.Category{
			Name:  CatToolchains,
			Help:  "Globally installed packages, listed as manager:package.",
			Items: items,
		})
	}

	if len(p.System.MCPServers) > 0 {
		items := make([]selection.Item, 0, len(p.System.MCPServers))
		for _, m := range p.System.MCPServers {
			items = append(items, selection.Item{
				Key: mcpKey(m), Note: m.Source, Selected: true,
			})
		}
		d.Categories = append(d.Categories, selection.Category{
			Name:  CatMCP,
			Help:  "MCP servers. Names and required variable names only — never their values.",
			Items: items,
		})
	}

	return d
}

// mcpKey identifies a server uniquely; the same name can appear in two editors.
func mcpKey(m bundle.MCPServer) string {
	return strings.TrimPrefix(m.Source, "~/") + "::" + m.Name
}

// ApplySelection drops everything the user deselected.
func (p *Plan) ApplySelection(d selection.Document) {
	sel := d.Selected()

	if keep, ok := sel[CatConfigs]; ok {
		var files []Planned
		for _, f := range p.Files {
			if keep[f.Entry] {
				files = append(files, f)
			}
		}
		p.Files = files
		// The cached read/scrub pass is keyed to the old file list.
		p.analysed = nil

		var notes []bundle.Note
		for _, n := range p.Notes {
			if keep[n.Entry] {
				notes = append(notes, n)
			}
		}
		p.Notes = notes

		var reqs []bundle.Requirement
		for _, r := range p.Requirements {
			if keep[r.Entry] {
				reqs = append(reqs, r)
			}
		}
		p.Requirements = reqs

		for _, owner := range sortedKeys(p.System.PrefOwners) {
			if keep[owner] {
				continue
			}
			for _, domain := range p.System.PrefOwners[owner] {
				delete(p.Prefs, domain)
			}
			delete(p.System.PrefOwners, owner)
		}
		p.System.Prefs = sortedKeys(p.Prefs)
	}

	if keep, ok := sel[CatApps]; ok {
		var apps []bundle.App
		for _, a := range p.Applications {
			if a.Source == SourceHomebrew || a.Source == SourceSystem || keep[a.Name] {
				apps = append(apps, a)
			}
		}
		p.Applications = apps
	}

	if keep, ok := sel[CatRepos]; ok {
		var repos []bundle.Repo
		for _, r := range p.Repos {
			if keep[r.Path] {
				repos = append(repos, r)
			}
		}
		p.Repos = repos
	}

	if p.Brew != nil {
		formulae, formulaeOK := sel[CatFormulae]
		casks, casksOK := sel[CatCasks]
		if formulaeOK || casksOK {
			content, counts := filterBrewfile(p.Brew.Content, formulae, formulaeOK, casks, casksOK)
			p.Brew.Content = content
			p.Brew.Counts = counts
		}
	}

	if keep, ok := sel[CatExtensions]; ok {
		p.System.Extensions = filterNamespaced(p.System.Extensions, keep)
	}
	if keep, ok := sel[CatToolchains]; ok {
		p.System.Toolchains = filterNamespaced(p.System.Toolchains, keep)
	}

	if keep, ok := sel[CatMCP]; ok {
		var servers []bundle.MCPServer
		for _, m := range p.System.MCPServers {
			if keep[mcpKey(m)] {
				servers = append(servers, m)
			}
		}
		p.System.MCPServers = servers
	}
}

// filterNamespaced prunes a manager -> packages map against keys of the form
// "manager:package", dropping managers left with nothing.
func filterNamespaced(in map[string][]string, keep map[string]bool) map[string][]string {
	if in == nil {
		return nil
	}
	out := map[string][]string{}
	for manager, values := range in {
		var kept []string
		for _, v := range values {
			if keep[manager+":"+v] {
				kept = append(kept, v)
			}
		}
		if len(kept) > 0 {
			out[manager] = kept
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (p *Plan) entryCounts() map[string]int {
	counts := map[string]int{}
	for _, f := range p.Files {
		counts[f.Entry]++
	}
	return counts
}

func itemsFor(names []string) []selection.Item {
	items := make([]selection.Item, 0, len(names))
	for _, n := range names {
		items = append(items, selection.Item{Key: n, Selected: true})
	}
	return items
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
