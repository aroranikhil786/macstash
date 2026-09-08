package selection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func doc() Document {
	return Document{Categories: []Category{
		{
			Name: "applications",
			Help: "Excluded apps are still recorded, just not installed.",
			Items: []Item{
				{Key: "IntelliJ IDEA", Note: "2026.2.1", Selected: true},
				{Key: "MemoryAnalyzer", Note: "1.16.1", Selected: true},
				{Key: "Slack", Note: "4.47.65", Selected: true},
			},
		},
		{
			Name: "repositories",
			Items: []Item{
				{Key: "~/Documents/github/npvr-hubble", Selected: true},
				{Key: "~/Documents/github/backstage", Selected: true},
			},
		},
	}}
}

// The property everything else depends on: what is rendered must parse back to
// exactly what went in. If this drifts, a selection silently changes meaning.
func TestRenderParseRoundTrips(t *testing.T) {
	in := doc()

	out, err := Parse(Render(in), in)
	if err != nil {
		t.Fatal(err)
	}

	for ci, c := range in.Categories {
		for ii, want := range c.Items {
			got := out.Categories[ci].Items[ii]
			if got.Key != want.Key || got.Selected != want.Selected {
				t.Errorf("[%s] %q: selected=%v, want key=%q selected=%v",
					c.Name, got.Key, got.Selected, want.Key, want.Selected)
			}
		}
	}
}

// A key containing single spaces must survive the note column. Most
// application names have one.
func TestParseKeepsKeysContainingSpaces(t *testing.T) {
	in := doc()

	out, err := Parse(Render(in), in)
	if err != nil {
		t.Fatal(err)
	}

	sel := out.Selected()["applications"]
	if !sel["IntelliJ IDEA"] {
		t.Errorf("a key with a space did not survive: %v", sel)
	}
}

func TestCommentingALineOutDeselectsIt(t *testing.T) {
	in := doc()
	edited := strings.ReplaceAll(string(Render(in)), "  MemoryAnalyzer", "# MemoryAnalyzer")

	out, err := Parse([]byte(edited), in)
	if err != nil {
		t.Fatal(err)
	}

	sel := out.Selected()["applications"]
	if sel["MemoryAnalyzer"] {
		t.Error("a commented line should be deselected")
	}
	if !sel["Slack"] || !sel["IntelliJ IDEA"] {
		t.Errorf("commenting one line must not affect the others: %v", sel)
	}
}

// Deleting a line is what people actually do in an editor, so it has to mean
// the same as commenting it out.
func TestDeletingALineDeselectsIt(t *testing.T) {
	in := doc()
	var kept []string
	for _, line := range strings.Split(string(Render(in)), "\n") {
		if !strings.Contains(line, "MemoryAnalyzer") {
			kept = append(kept, line)
		}
	}

	out, err := Parse([]byte(strings.Join(kept, "\n")), in)
	if err != nil {
		t.Fatal(err)
	}

	if out.Selected()["applications"]["MemoryAnalyzer"] {
		t.Error("a deleted line should be deselected")
	}
}

// A mangled key must stop the run. Silently dropping whatever it was meant to
// name is the failure mode this whole tool is built around.
func TestParseRejectsAnUnknownKey(t *testing.T) {
	in := doc()
	edited := strings.ReplaceAll(string(Render(in)), "Slack", "Slakc")

	_, err := Parse([]byte(edited), in)

	if err == nil {
		t.Fatal("a typo must be an error, not a silent exclusion")
	}
	if !strings.Contains(err.Error(), "Slakc") {
		t.Errorf("the error should quote the bad key, got %v", err)
	}
	// The message has to say what to do instead.
	if !strings.Contains(err.Error(), "comment") {
		t.Errorf("the error should suggest commenting out, got %v", err)
	}
}

func TestParseRejectsAnUnknownSection(t *testing.T) {
	in := doc()
	edited := string(Render(in)) + "\n[nonsense]\n  whatever\n"

	if _, err := Parse([]byte(edited), in); err == nil {
		t.Fatal("an unknown section must be an error")
	}
}

func TestParseRejectsAnItemBeforeAnySection(t *testing.T) {
	if _, err := Parse([]byte("  orphan\n"), doc()); err == nil {
		t.Fatal("an item outside a section must be an error")
	}
}

// Emptying the file is the documented way to back out.
func TestParseOfAnEmptyFileSelectsNothing(t *testing.T) {
	out, err := Parse(nil, doc())
	if err != nil {
		t.Fatal(err)
	}

	if selected, total := out.Counts(); selected != 0 || total != 5 {
		t.Fatalf("selected=%d total=%d, want 0 of 5", selected, total)
	}
}

// A file that is only comments — someone who commented everything out rather
// than deleting — must read the same as an empty one.
func TestParseOfAnAllCommentedFileSelectsNothing(t *testing.T) {
	in := doc()
	var out []string
	for _, line := range strings.Split(string(Render(in)), "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "[") {
			line = "# " + strings.TrimSpace(line)
		}
		out = append(out, line)
	}

	parsed, err := Parse([]byte(strings.Join(out, "\n")), in)
	if err != nil {
		t.Fatal(err)
	}
	if selected, _ := parsed.Counts(); selected != 0 {
		t.Fatalf("want nothing selected, got %d", selected)
	}
}

// Parse must not write through to the document it was given, or a caller that
// keeps the original sees it mutate underneath them.
func TestParseDoesNotMutateTheOfferedDocument(t *testing.T) {
	in := doc()

	if _, err := Parse(nil, in); err != nil {
		t.Fatal(err)
	}

	for _, c := range in.Categories {
		for _, it := range c.Items {
			if !it.Selected {
				t.Fatalf("Parse deselected %q in the caller's document", it.Key)
			}
		}
	}
}

func TestRenderMarksDeselectedItemsAsComments(t *testing.T) {
	in := doc()
	in.Categories[0].Items[1].Selected = false

	out := string(Render(in))

	if !strings.Contains(out, "# MemoryAnalyzer") {
		t.Errorf("a deselected item should render commented out:\n%s", out)
	}
}

func TestRenderIncludesCategoryHelpAsComments(t *testing.T) {
	out := string(Render(doc()))

	if !strings.Contains(out, "# Excluded apps are still recorded") {
		t.Errorf("category help should be rendered as a comment:\n%s", out)
	}
}

func TestRenderSkipsEmptyCategories(t *testing.T) {
	d := Document{Categories: []Category{{Name: "empty"}, {Name: "full", Items: []Item{{Key: "x", Selected: true}}}}}

	out := string(Render(d))

	if strings.Contains(out, "[empty]") {
		t.Errorf("an empty category should not be rendered:\n%s", out)
	}
	if !strings.Contains(out, "[full]") {
		t.Errorf("a non-empty category should be rendered:\n%s", out)
	}
}

func TestEmptyAndCounts(t *testing.T) {
	if !(Document{}).Empty() {
		t.Error("a document with no categories is empty")
	}
	if doc().Empty() {
		t.Error("a document with items is not empty")
	}
	if selected, total := doc().Counts(); selected != 5 || total != 5 {
		t.Errorf("counts = %d/%d, want 5/5", selected, total)
	}
}

// Edit writes where it is told, so the file can be found again after a parse
// error rather than vanishing with a temporary directory.
func TestEditWritesTheFileWhereItIsToldAndParsesTheResult(t *testing.T) {
	dir := t.TempDir()
	// A no-op "editor" that leaves the file exactly as rendered.
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "true")

	out, err := Edit(doc(), dir)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "selection.conf")); err != nil {
		t.Errorf("the selection file should remain for reuse: %v", err)
	}
	if selected, total := out.Counts(); selected != total {
		t.Errorf("an unedited file should keep everything, got %d/%d", selected, total)
	}
}

// An editor that fails must not be read as "the user deselected everything".
func TestEditRefusesWhenTheEditorFails(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "false")

	if _, err := Edit(doc(), t.TempDir()); err == nil {
		t.Fatal("a failing editor must abort rather than proceed")
	}
}

func TestEditReportsAMissingEditorUsefully(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "macstash-no-such-editor-binary")

	_, err := Edit(doc(), t.TempDir())

	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "--selection") {
		t.Errorf("the error should offer the non-interactive route, got %v", err)
	}
}

func TestEditOnAnEmptyDocumentDoesNothing(t *testing.T) {
	t.Setenv("EDITOR", "false") // would fail if it were run

	if _, err := Edit(Document{}, t.TempDir()); err != nil {
		t.Fatalf("nothing to select should be a no-op, got %v", err)
	}
}

func TestLoadReadsASavedSelection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "saved.conf")
	in := doc()
	edited := strings.ReplaceAll(string(Render(in)), "  Slack", "# Slack")
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := Load(path, in)
	if err != nil {
		t.Fatal(err)
	}

	if out.Selected()["applications"]["Slack"] {
		t.Error("the saved exclusion should be honoured")
	}
	if !out.Selected()["applications"]["IntelliJ IDEA"] {
		t.Error("the saved inclusions should be honoured")
	}
}

func TestFirstNonEmptyPrefersVisualThenEditor(t *testing.T) {
	if got := firstNonEmpty("", "  ", "vi"); got != "vi" {
		t.Errorf("got %q, want vi", got)
	}
	if got := firstNonEmpty("code -w", "vim"); got != "code -w" {
		t.Errorf("got %q, want the first", got)
	}
}

// Editors are commonly configured with flags, so the value must be split.
func TestSplitKeyHandlesNotesAndBareKeys(t *testing.T) {
	cases := map[string]string{
		"IntelliJ IDEA   2026.2.1":                 "IntelliJ IDEA",
		"~/Documents/github/npvr-hubble":           "~/Documents/github/npvr-hubble",
		"ripgrep  14.1.0":                          "ripgrep",
		"Microsoft Outlook 10.21.03 AM   16.112.3": "Microsoft Outlook 10.21.03 AM",
	}
	for line, want := range cases {
		if got := splitKey(line); got != want {
			t.Errorf("splitKey(%q) = %q, want %q", line, got, want)
		}
	}
}
