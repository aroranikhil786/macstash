package restore

import (
	"fmt"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/selection"
)

// Selection categories at restore. The names match capture's deliberately, so a
// selection file saved at capture can be handed back to restore.
const (
	CatConfigs = "configs"
	CatApps    = "applications"
	CatRepos   = "repositories"
)

// SelectionDocument describes what a restore could apply, so a person can prune
// it before anything is written.
//
// Restore is the better place to decide about applications. Pruning at capture
// is irreversible in practice — changing your mind means going back to a machine
// that may already be wiped — whereas a bundle carries the full list at
// negligible cost and can be applied repeatedly with different choices.
//
// Items already present on this machine are pre-deselected rather than hidden.
// Hiding them would misrepresent what the bundle contains; deselecting them
// means the common case needs no edits at all.
func SelectionDocument(p *Plan, home string) selection.Document {
	var d selection.Document

	if entries := entryCounts(p); len(entries) > 0 {
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
			Help:  "Configuration to write. Anything overwritten is backed up first.",
			Items: items,
		})
	}

	if p.Manifest != nil {
		installable, _ := PlanApps(p.Manifest.Applications)
		if len(installable) > 0 {
			items := make([]selection.Item, 0, len(installable))
			for _, a := range installable {
				note := "brew install --cask " + a.Token
				if a.Present {
					note = "already installed"
				}
				items = append(items, selection.Item{
					Key: a.Name, Note: note, Selected: !a.Present,
				})
			}
			d.Categories = append(d.Categories, selection.Category{
				Name: CatApps,
				Help: "Applications Homebrew can install. Ones already here are\n" +
					"pre-excluded; re-enable a line to reinstall it anyway.",
				Items: items,
			})
		}

		if len(p.Manifest.Repos) > 0 {
			items := make([]selection.Item, 0, len(p.Manifest.Repos))
			for _, r := range p.Manifest.Repos {
				note := ""
				if r.Remote == "" {
					note = "no remote — cannot be cloned"
				}
				items = append(items, selection.Item{
					Key: r.Path, Note: note, Selected: r.Remote != "",
				})
			}
			d.Categories = append(d.Categories, selection.Category{
				Name:  CatRepos,
				Help:  "Repositories to clone. Needs your SSH key and any VPN already in place.",
				Items: items,
			})
		}
	}

	return d
}

// ApplySelection prunes the plan and returns the applications and repositories
// left enabled.
func ApplySelection(p *Plan, d selection.Document) (apps []bundle.App, repos []bundle.Repo) {
	sel := d.Selected()

	if keep, ok := sel[CatConfigs]; ok {
		byRel := entryByRel(p)
		var actions []Action
		for _, a := range p.Actions {
			if keep[byRel[a.Rel]] {
				actions = append(actions, a)
			}
		}
		p.Actions = actions
	}

	if p.Manifest == nil {
		return nil, nil
	}

	if keep, ok := sel[CatApps]; ok {
		for _, a := range p.Manifest.Applications {
			if keep[a.Name] {
				apps = append(apps, a)
			}
		}
	} else {
		apps = p.Manifest.Applications
	}

	if keep, ok := sel[CatRepos]; ok {
		for _, r := range p.Manifest.Repos {
			if keep[r.Path] {
				repos = append(repos, r)
			}
		}
	} else {
		repos = p.Manifest.Repos
	}

	return apps, repos
}

// entryByRel maps a restored path back to the catalog entry that owns it.
// Action does not carry the entry, so it is recovered from the manifest, the
// same way Filter does.
func entryByRel(p *Plan) map[string]string {
	byRel := map[string]string{}
	if p.Manifest == nil {
		return byRel
	}
	for _, item := range p.Manifest.Items {
		byRel[item.Rel] = item.Entry
	}
	return byRel
}

func entryCounts(p *Plan) map[string]int {
	byRel := entryByRel(p)
	counts := map[string]int{}
	for _, a := range p.Actions {
		entry := byRel[a.Rel]
		if a.Kind == Refused || entry == "" {
			continue
		}
		counts[entry]++
	}
	return counts
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Summary describes a selection for printing.
func Summary(d selection.Document) string {
	if d.Empty() {
		return ""
	}
	var parts []string
	for _, c := range d.Categories {
		selected := 0
		for _, it := range c.Items {
			if it.Selected {
				selected++
			}
		}
		parts = append(parts, fmt.Sprintf("%s %d/%d", c.Name, selected, len(c.Items)))
	}
	return "Selected: " + strings.Join(parts, ", ")
}
