package catalog

import (
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("loaded %d entries, want the 8 Slice A entries", len(entries))
	}
	want := map[string]bool{
		"zsh": false, "git": false, "ssh": false, "tmux": false,
		"iterm2": false, "npm": false, "docker": false, "vscode": false,
	}
	for _, e := range entries {
		if _, ok := want[e.ID]; ok {
			want[e.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("catalog entry %q missing", id)
		}
	}
}

// The whole point of putting the never list in code is that a catalog entry
// cannot reach around it. This is the regression test for plan R10.
func TestEntryNamingNeverPathIsRejected(t *testing.T) {
	e := Entry{
		ID:   "malicious",
		Name: "Malicious",
		Capture: Capture{Paths: []Path{
			{Path: "~/.aws/credentials", Class: classify.Public},
		}},
	}
	err := e.Validate()
	if err == nil {
		t.Fatal("a catalog entry naming ~/.aws/credentials was accepted")
	}
	if !strings.Contains(err.Error(), "never list") {
		t.Errorf("error did not explain the never list: %v", err)
	}
}

func TestEntryCannotDeclareClassNever(t *testing.T) {
	e := Entry{
		ID: "x", Name: "X",
		Capture: Capture{Paths: []Path{{Path: "~/.foo", Class: classify.Never}}},
	}
	if err := e.Validate(); err == nil {
		t.Fatal("class never was accepted in a catalog entry")
	}
}

// A scrub path with no rules would be captured whole, which is worse than not
// capturing it at all.
func TestScrubClassRequiresRules(t *testing.T) {
	e := Entry{
		ID: "x", Name: "X",
		Capture: Capture{Paths: []Path{{Path: "~/.npmrc", Class: classify.Scrub}}},
	}
	if err := e.Validate(); err == nil {
		t.Fatal("class scrub with no rules was accepted")
	}
}

func TestScrubRuleRequiresReason(t *testing.T) {
	e := Entry{
		ID: "x", Name: "X",
		Capture: Capture{Paths: []Path{{
			Path:  "~/.npmrc",
			Class: classify.Scrub,
			Scrub: []scrub.Rule{{Kind: scrub.DropLine, Pattern: "token"}},
		}}},
	}
	if err := e.Validate(); err == nil {
		t.Fatal("a scrub rule with no reason was accepted")
	}
}

// Every scrub rule in the shipped catalog must compile and behave, or capture
// fails open on a real machine.
func TestShippedScrubRulesAreValid(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		for _, p := range e.Capture.Paths {
			if len(p.Scrub) == 0 {
				continue
			}
			if _, _, err := scrub.Apply([]byte("probe\n"), p.Scrub, p.Path); err != nil {
				// drop_json_key on non-JSON is a legitimate error, skip those.
				if p.Scrub[0].Kind == scrub.DropJSONKey {
					continue
				}
				t.Errorf("%s: scrub rules failed on probe input: %v", e.ID, err)
			}
		}
	}
}
