package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// A count with no list is useless: the ids are the only thing the user can act
// on when the editor's CLI is missing.
func TestRestoreExtensionsListsTheIdsWhenTheEditorIsMissing(t *testing.T) {
	var buf bytes.Buffer
	p := &Plan{Manifest: &bundle.Manifest{System: bundle.System{
		Extensions: map[string][]string{
			"macstash-no-such-editor": {"golang.go", "vscodevim.vim"},
		},
	}}}

	p.RestoreExtensions(&buf, false, "")

	out := buf.String()
	if !strings.Contains(out, "not installed here") {
		t.Errorf("want the missing editor reported, got:\n%s", out)
	}
	for _, id := range []string{"golang.go", "vscodevim.vim"} {
		if !strings.Contains(out, id) {
			t.Errorf("want %q listed so it can be installed by hand, got:\n%s", id, out)
		}
	}
}

// A run where every install failed used to look exactly like a run where every
// one succeeded, because the exit status was discarded.
func TestRestoreExtensionsCountsAndNamesFailures(t *testing.T) {
	dir := t.TempDir()
	editor := "macstash-fake-editor"
	script := filepath.Join(dir, editor)
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))

	var buf bytes.Buffer
	p := &Plan{Manifest: &bundle.Manifest{System: bundle.System{
		Extensions: map[string][]string{editor: {"golang.go", "vscodevim.vim"}},
	}}}

	p.RestoreExtensions(&buf, true, "")

	out := buf.String()
	if !strings.Contains(out, "installed 0, failed 2") {
		t.Errorf("want the failures counted, got:\n%s", out)
	}
	if !strings.Contains(out, "failed: golang.go") {
		t.Errorf("want the failures named, got:\n%s", out)
	}
}

// The editor's command-line tool is not on PATH by default — adding it is a
// manual step inside the editor. Refusing to install extensions on that basis,
// when the binary ships inside the application, is the wrong answer.
func TestEditorCommandIsFoundInsideTheApplication(t *testing.T) {
	const app = "Visual Studio Code - Insiders"
	bin := "/Applications/" + app + ".app/Contents/Resources/app/bin"
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("%s is not installed here", app)
	}

	path, ok := editorCommand("code-insiders")

	if !ok {
		t.Fatalf("the bundled command was not found under %s", bin)
	}
	if !strings.HasPrefix(path, bin) {
		t.Errorf("found %q, want something under the application bundle", path)
	}
	// It is called "code" in Insiders, so a name guess would have missed it.
	if strings.Contains(path, "tunnel") {
		t.Errorf("found the tunnel helper %q rather than the editor command", path)
	}
}

func TestEditorCommandOnAnUnknownEditor(t *testing.T) {
	if _, ok := editorCommand("macstash-no-such-editor"); ok {
		t.Error("an unknown editor must not resolve to a command")
	}
}

// fakeEditor puts an executable named after a known editor on PATH, so
// editorCommand finds it without an application bundle existing.
func fakeEditor(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "installed.log")
	body := "#!/bin/sh\necho \"$@\" >> " + log + "\n" + script
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return log
}

// The reason this exists: a bundle captured from VS Code stable landed on a
// machine running only Insiders, and 26 extensions printed as a list instead of
// installing. They take the same ids, so the user should be able to say where
// they go.
func TestExtensionsGoWhereTheUserAsks(t *testing.T) {
	log := fakeEditor(t, "code-insiders", "exit 0\n")

	var buf bytes.Buffer
	p := &Plan{Manifest: &bundle.Manifest{System: bundle.System{
		Extensions: map[string][]string{
			"code":          {"golang.go", "eamodio.gitlens"},
			"code-insiders": {"golang.go"},
		},
	}}}

	p.RestoreExtensions(&buf, true, "code-insiders")

	installed, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("the editor was never invoked: %v", err)
	}
	for _, id := range []string{"golang.go", "eamodio.gitlens"} {
		if !strings.Contains(string(installed), id) {
			t.Errorf("%q was not installed into the chosen editor:\n%s", id, installed)
		}
	}
	// golang.go is recorded under both editors. Installing it twice is only
	// slower.
	if n := strings.Count(string(installed), "golang.go"); n != 1 {
		t.Errorf("golang.go installed %d times, want 1", n)
	}
	if out := buf.String(); !strings.Contains(out, "installed 2, failed 0") {
		t.Errorf("want both counted, got:\n%s", out)
	}
}

// A dead end is worse than a second command: when the recorded editor is
// absent, the output has to name the editors that could take the list instead.
func TestAMissingEditorOffersTheOnesThatAreHere(t *testing.T) {
	fakeEditor(t, "cursor", "exit 0\n")

	var buf bytes.Buffer
	p := &Plan{Manifest: &bundle.Manifest{System: bundle.System{
		Extensions: map[string][]string{"code": {"golang.go"}},
	}}}

	p.RestoreExtensions(&buf, false, "")

	if out := buf.String(); !strings.Contains(out, "--extensions-to cursor") {
		t.Errorf("want the flag offered for the editor that is here, got:\n%s", out)
	}
}

// A typo must fail before the restore writes anything, not after.
func TestCheckEditorTarget(t *testing.T) {
	fakeEditor(t, "cursor", "exit 0\n")

	if err := CheckEditorTarget("cursor"); err != nil {
		t.Errorf("cursor is on PATH here: %v", err)
	}
	err := CheckEditorTarget("vscode")
	if err == nil {
		t.Fatal("an editor macstash does not know must be rejected")
	}
	if !strings.Contains(err.Error(), "code-insiders") {
		t.Errorf("the error should list the known editors, got %q", err)
	}
	if err := CheckEditorTarget("windsurf"); err == nil {
		t.Error("an editor that is not installed must be rejected")
	}
}
