package restore

import (
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/selection"
)

func restorePlan() *Plan {
	return &Plan{
		Manifest: &bundle.Manifest{
			Items: []bundle.Item{
				{Entry: "zsh", Rel: ".zshrc"},
				{Entry: "zsh", Rel: ".zprofile"},
				{Entry: "git", Rel: ".gitconfig"},
			},
			Applications: []bundle.App{
				{Name: "macstash-test-absent-one", Source: "manual", CaskToken: "one"},
				{Name: "macstash-test-absent-two", Source: "manual", CaskToken: "two"},
			},
			Repos: []bundle.Repo{
				{Path: "~/code/keep", Remote: "git@example.com:a/b.git"},
				{Path: "~/code/drop", Remote: "git@example.com:c/d.git"},
				{Path: "~/code/orphan", NoRemote: true},
			},
		},
		Actions: []Action{
			{Rel: ".zshrc", Kind: Create},
			{Rel: ".zprofile", Kind: Create},
			{Rel: ".gitconfig", Kind: Create},
		},
	}
}

func pick(d selection.Document, category, key string, on bool) selection.Document {
	for ci := range d.Categories {
		if d.Categories[ci].Name != category {
			continue
		}
		for ii := range d.Categories[ci].Items {
			if d.Categories[ci].Items[ii].Key == key {
				d.Categories[ci].Items[ii].Selected = on
				return d
			}
		}
	}
	panic("no item " + key + " in " + category)
}

func TestRestoreSelectionOffersConfigsAppsAndRepos(t *testing.T) {
	d := SelectionDocument(restorePlan(), t.TempDir())

	got := map[string]int{}
	for _, c := range d.Categories {
		got[c.Name] = len(c.Items)
	}
	if got[CatConfigs] != 2 {
		t.Errorf("configs = %d, want 2 entries", got[CatConfigs])
	}
	if got[CatApps] != 2 {
		t.Errorf("applications = %d, want 2", got[CatApps])
	}
	if got[CatRepos] != 3 {
		t.Errorf("repositories = %d, want 3", got[CatRepos])
	}
}

// A repository with no remote cannot be cloned, so offering it selected would
// guarantee a failure the user did not ask for.
func TestRestoreSelectionPreDeselectsRemotelessRepos(t *testing.T) {
	d := SelectionDocument(restorePlan(), t.TempDir())

	for _, c := range d.Categories {
		if c.Name != CatRepos {
			continue
		}
		for _, it := range c.Items {
			if it.Key == "~/code/orphan" && it.Selected {
				t.Error("a repo with no remote should be pre-deselected")
			}
			if it.Key == "~/code/keep" && !it.Selected {
				t.Error("a cloneable repo should be pre-selected")
			}
		}
	}
}

func TestApplySelectionPrunesActionsByEntry(t *testing.T) {
	p := restorePlan()
	d := pick(SelectionDocument(p, t.TempDir()), CatConfigs, "git", false)

	ApplySelection(p, d)

	if len(p.Actions) != 2 {
		t.Fatalf("actions = %d, want the two zsh files", len(p.Actions))
	}
	for _, a := range p.Actions {
		if a.Rel == ".gitconfig" {
			t.Error(".gitconfig should have been pruned")
		}
	}
}

func TestApplySelectionReturnsOnlySelectedAppsAndRepos(t *testing.T) {
	p := restorePlan()
	d := SelectionDocument(p, t.TempDir())
	d = pick(d, CatApps, "macstash-test-absent-two", false)
	d = pick(d, CatRepos, "~/code/drop", false)

	apps, repos := ApplySelection(p, d)

	if len(apps) != 1 || apps[0].Name != "macstash-test-absent-one" {
		t.Fatalf("apps = %+v, want only the selected one", apps)
	}
	if len(repos) != 1 || repos[0].Path != "~/code/keep" {
		t.Fatalf("repos = %+v, want only ~/code/keep", repos)
	}
}

// With no selection categories at all, everything must pass through — this is
// the path a plain restore takes.
func TestApplySelectionWithNoCategoriesKeepsEverything(t *testing.T) {
	p := restorePlan()

	apps, repos := ApplySelection(p, selection.Document{})

	if len(p.Actions) != 3 {
		t.Errorf("actions = %d, want 3", len(p.Actions))
	}
	if len(apps) != 2 || len(repos) != 3 {
		t.Errorf("apps=%d repos=%d, want 2 and 3", len(apps), len(repos))
	}
}

func TestSummaryReportsCountsPerCategory(t *testing.T) {
	p := restorePlan()
	d := pick(SelectionDocument(p, t.TempDir()), CatConfigs, "git", false)

	got := Summary(d)

	if got == "" {
		t.Fatal("want a summary")
	}
	if want := "configs 1/2"; !contains(got, want) {
		t.Errorf("summary = %q, want it to contain %q", got, want)
	}
}

func TestSummaryOfAnEmptyDocumentIsEmpty(t *testing.T) {
	if got := Summary(selection.Document{}); got != "" {
		t.Errorf("want empty, got %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
