package capture

import (
	"slices"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/catalog"
	"github.com/aroranikhil786/macstash/internal/selection"
)

func planWithInventory() *Plan {
	return &Plan{
		Files: []Planned{
			{Entry: "zsh", Rel: ".zshrc"},
			{Entry: "zsh", Rel: ".zprofile"},
			{Entry: "git", Rel: ".gitconfig"},
		},
		Notes:        []bundle.Note{{Entry: "zsh", Text: "n"}, {Entry: "git", Text: "n"}},
		Requirements: []bundle.Requirement{{Entry: "git", Name: "Git"}},
		Applications: []bundle.App{
			{Name: "Arc", Source: SourceManual, CaskToken: "arc"},
			{Name: "Telegram", Source: SourceManual, CaskToken: "telegram"},
			{Name: "ripgrep", Source: SourceHomebrew},
			{Name: "Safari", Source: SourceSystem},
		},
		Repos: []bundle.Repo{
			{Path: "~/code/keep", Remote: "git@example.com:a/b.git"},
			{Path: "~/code/drop", Remote: "git@example.com:c/d.git"},
		},
		System: bundle.System{
			Toolchains: map[string][]string{"npm": {"typescript", "eslint"}},
			Extensions: map[string][]string{"code": {"golang.go", "vscodevim.vim"}},
			MCPServers: []bundle.MCPServer{
				{Name: "postgres", Source: "~/.cursor/mcp.json"},
				{Name: "context7", Source: "~/.cursor/mcp.json"},
			},
		},
		Brew: &BrewResult{Content: []byte(`tap "homebrew/cask"
brew "ripgrep"
brew "jq"
cask "iterm2"
`)},
	}
}

func TestSelectionDocumentOffersEveryCategory(t *testing.T) {
	d := planWithInventory().SelectionDocument()

	want := []string{CatConfigs, CatApps, CatRepos, CatFormulae, CatCasks, CatExtensions, CatToolchains, CatMCP}
	got := map[string]bool{}
	for _, c := range d.Categories {
		got[c.Name] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("category %q was not offered", w)
		}
	}
}

// Homebrew and Apple already account for these, so there is nothing to decide.
func TestSelectionDocumentOmitsManagedAndSystemApps(t *testing.T) {
	d := planWithInventory().SelectionDocument()

	for _, c := range d.Categories {
		if c.Name != CatApps {
			continue
		}
		for _, it := range c.Items {
			if it.Key == "ripgrep" || it.Key == "Safari" {
				t.Errorf("%q should not be offered for selection", it.Key)
			}
		}
	}
}

func TestApplySelectionDropsDeselectedConfigsAndTheirNotes(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatConfigs, "git")

	p.ApplySelection(d)

	for _, f := range p.Files {
		if f.Entry == "git" {
			t.Errorf("git files should be gone, got %s", f.Rel)
		}
	}
	if len(p.Files) != 2 {
		t.Errorf("want the two zsh files, got %d", len(p.Files))
	}
	for _, n := range p.Notes {
		if n.Entry == "git" {
			t.Error("a deselected entry's note should go with it")
		}
	}
	for _, r := range p.Requirements {
		if r.Entry == "git" {
			t.Error("a deselected entry's requirement should go with it")
		}
	}
}

func TestApplySelectionDropsDeselectedAppsButKeepsManagedOnes(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatApps, "Telegram")

	p.ApplySelection(d)

	names := map[string]bool{}
	for _, a := range p.Applications {
		names[a.Name] = true
	}
	if names["Telegram"] {
		t.Error("Telegram was deselected and should be gone")
	}
	if !names["Arc"] {
		t.Error("Arc was selected and should remain")
	}
	// These were never offered, so they must survive regardless.
	if !names["ripgrep"] || !names["Safari"] {
		t.Errorf("unofferable apps must not be dropped: %v", names)
	}
}

func TestApplySelectionDropsDeselectedRepos(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatRepos, "~/code/drop")

	p.ApplySelection(d)

	if len(p.Repos) != 1 || p.Repos[0].Path != "~/code/keep" {
		t.Fatalf("repos = %+v, want only ~/code/keep", p.Repos)
	}
}

// The Brewfile is a file, so filtering means rewriting it — and the counts must
// be recomputed, or the cross-check would describe the pre-filter file and
// reintroduce the mismatch the dump validation exists to catch.
func TestApplySelectionRewritesTheBrewfileAndItsCounts(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatFormulae, "jq")

	p.ApplySelection(d)

	content := string(p.Brew.Content)
	if strings.Contains(content, `brew "jq"`) {
		t.Errorf("jq should have been removed:\n%s", content)
	}
	if !strings.Contains(content, `brew "ripgrep"`) || !strings.Contains(content, `cask "iterm2"`) {
		t.Errorf("selected packages must survive:\n%s", content)
	}
	if !strings.Contains(content, `tap "homebrew/cask"`) {
		t.Errorf("taps are not selectable and must survive:\n%s", content)
	}
	if p.Brew.Counts.Formulae != 1 || p.Brew.Counts.Casks != 1 || p.Brew.Counts.Taps != 1 {
		t.Errorf("counts = %+v, want 1 formula, 1 cask, 1 tap", p.Brew.Counts)
	}
}

func TestApplySelectionPrunesNamespacedLists(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatToolchains, "npm:eslint")
	deselect(&d, CatExtensions, "code:vscodevim.vim")

	p.ApplySelection(d)

	if got := p.System.Toolchains["npm"]; len(got) != 1 || got[0] != "typescript" {
		t.Errorf("toolchains = %v, want [typescript]", got)
	}
	if got := p.System.Extensions["code"]; len(got) != 1 || got[0] != "golang.go" {
		t.Errorf("extensions = %v, want [golang.go]", got)
	}
}

// A manager left with nothing should disappear rather than linger empty.
func TestApplySelectionRemovesAManagerWithNothingLeft(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatToolchains, "npm:typescript")
	deselect(&d, CatToolchains, "npm:eslint")

	p.ApplySelection(d)

	if _, ok := p.System.Toolchains["npm"]; ok {
		t.Errorf("an empty manager should be dropped, got %v", p.System.Toolchains)
	}
}

func TestApplySelectionPrunesMCPServers(t *testing.T) {
	p := planWithInventory()
	d := p.SelectionDocument()
	deselect(&d, CatMCP, ".cursor/mcp.json::context7")

	p.ApplySelection(d)

	if len(p.System.MCPServers) != 1 || p.System.MCPServers[0].Name != "postgres" {
		t.Fatalf("servers = %+v, want only postgres", p.System.MCPServers)
	}
}

// Selecting everything must be a no-op, or the default path silently changes
// what a plain capture produces.
func TestApplySelectionWithEverythingSelectedChangesNothing(t *testing.T) {
	p := planWithInventory()
	before := len(p.Files)

	p.ApplySelection(p.SelectionDocument())

	if len(p.Files) != before {
		t.Errorf("files = %d, want %d", len(p.Files), before)
	}
	if len(p.Applications) != 4 || len(p.Repos) != 2 {
		t.Errorf("apps=%d repos=%d, want 4 and 2", len(p.Applications), len(p.Repos))
	}
	if p.Brew.Counts.Formulae != 2 {
		t.Errorf("formulae = %d, want 2", p.Brew.Counts.Formulae)
	}
}

func TestParseBrewfileReadsDeclarations(t *testing.T) {
	formulae, casks := parseBrewfile([]byte("tap \"a/b\"\nbrew \"ripgrep\"\n# brew \"commented\"\ncask \"iterm2\"\n"))

	if len(formulae) != 1 || formulae[0] != "ripgrep" {
		t.Errorf("formulae = %v", formulae)
	}
	if len(casks) != 1 || casks[0] != "iterm2" {
		t.Errorf("casks = %v", casks)
	}
}

// deselect flips one item off, standing in for the user commenting a line out.
func deselect(d *selection.Document, category, key string) {
	for ci := range d.Categories {
		if d.Categories[ci].Name != category {
			continue
		}
		for ii := range d.Categories[ci].Items {
			if d.Categories[ci].Items[ii].Key == key {
				d.Categories[ci].Items[ii].Selected = false
				return
			}
		}
	}
	panic("deselect: no item " + key + " in " + category)
}

// An entry that captures no files still has something to lose. iTerm2 is the
// case that caught this: on a typical Mac its configuration is a preference
// domain and nothing else, so building the selection list from files alone left
// it unoffered — and therefore treated as deselected, which silently removed
// its preferences and its quit-first requirement from the bundle.
func TestSelectionOffersEntriesThatOnlyHavePreferences(t *testing.T) {
	p := &Plan{
		Files: []Planned{{Entry: "zsh", Rel: ".zshrc"}},
		Prefs: map[string][]byte{"com.googlecode.iterm2": []byte("x")},
		Requirements: []bundle.Requirement{
			{Entry: "iterm2", Name: "iTerm2", QuitFirst: true},
		},
		System: bundle.System{
			PrefOwners: map[string][]string{"iterm2": {"com.googlecode.iterm2"}},
			Prefs:      []string{"com.googlecode.iterm2"},
		},
	}

	d := p.SelectionDocument()

	var offered []string
	for _, c := range d.Categories {
		if c.Name != CatConfigs {
			continue
		}
		for _, it := range c.Items {
			offered = append(offered, it.Key)
		}
	}
	if !containsString(offered, "iterm2") {
		t.Fatalf("a prefs-only entry must be offered, got %v", offered)
	}

	// And selecting everything must leave it fully intact.
	p.ApplySelection(d)
	if len(p.Prefs) != 1 {
		t.Errorf("preferences were dropped: %v", p.Prefs)
	}
	if len(p.Requirements) != 1 {
		t.Errorf("the quit-first requirement was dropped: %v", p.Requirements)
	}
	if _, ok := p.System.PrefOwners["iterm2"]; !ok {
		t.Errorf("pref ownership was dropped: %v", p.System.PrefOwners)
	}
}

// Deselecting a prefs-only entry should still work — the point is that it is a
// choice, not an accident.
func TestDeselectingAPrefsOnlyEntryRemovesItsPreferences(t *testing.T) {
	p := &Plan{
		Prefs: map[string][]byte{"com.googlecode.iterm2": []byte("x"), "NSGlobalDomain": []byte("y")},
		System: bundle.System{
			PrefOwners: map[string][]string{"iterm2": {"com.googlecode.iterm2"}},
		},
	}
	d := p.SelectionDocument()
	deselect(&d, CatConfigs, "iterm2")

	p.ApplySelection(d)

	if _, ok := p.Prefs["com.googlecode.iterm2"]; ok {
		t.Error("the deselected entry's preference should be gone")
	}
	// A domain nobody owns must not be swept up with it.
	if _, ok := p.Prefs["NSGlobalDomain"]; !ok {
		t.Error("an unowned preference domain must survive")
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// The Oh My Zsh skip list is only useful if it matches the files it names.
// "example.zsh" matched neither stub the framework ships, so both travelled in
// every bundle.
func TestOhMyZshExampleStubsAreSkipped(t *testing.T) {
	skip := []string{"*/.git", "example.zsh-theme", "example.plugin.zsh"}
	for _, rel := range []string{
		"themes/example.zsh-theme",
		"plugins/example/example.plugin.zsh",
	} {
		if !matchesAny(rel, skip) {
			t.Errorf("%q should be skipped", rel)
		}
	}
	if matchesAny("themes/powerlevel10k/powerlevel10k.zsh-theme", skip) {
		t.Error("a real theme must not be skipped by the example patterns")
	}
}

// The patterns in the catalog must be the ones the test above proves work.
func TestOhMyZshCatalogUsesThePatternsThatMatch(t *testing.T) {
	entries, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.ID != "ohmyzsh" {
			continue
		}
		for _, p := range e.Capture.Paths {
			if !strings.Contains(p.Path, "custom") {
				continue
			}
			for _, want := range []string{"example.zsh-theme", "example.plugin.zsh"} {
				if !slices.Contains(p.Skip, want) {
					t.Errorf("catalog skip list %v is missing %q", p.Skip, want)
				}
			}
		}
		return
	}
	t.Fatal("no ohmyzsh entry in the catalog")
}
