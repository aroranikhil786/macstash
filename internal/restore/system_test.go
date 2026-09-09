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

// Settings written to the VS Code stable directory on a machine running only
// Insiders restore the file and configure nothing: that editor never reads that
// path. The flag that moves the extensions has to move these too.
func TestEditorSettingsFollowTheExtensions(t *testing.T) {
	staging := t.TempDir()
	home := t.TempDir()
	rel := "Library/Application Support/Code/User/settings.json"
	src := filepath.Join(staging, "home", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(`{"editor.fontSize":14}`), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &Plan{
		Staging: staging,
		Actions: []Action{
			{Rel: rel, Kind: Create},
			{Rel: ".zshrc", Kind: Overwrite},
		},
	}

	moved := p.RedirectEditorFiles(home, "code-insiders")

	want := "Library/Application Support/Code - Insiders/User/settings.json"
	if len(moved) != 1 || moved[0] != want {
		t.Fatalf("moved = %v, want just %q", moved, want)
	}
	if got := p.Actions[0].Target(); got != want {
		t.Errorf("target = %q, want %q", got, want)
	}
	// The staging copy is still found at the original path, which is why Dest
	// cannot simply overwrite Rel.
	if p.Actions[0].Rel != rel {
		t.Errorf("Rel = %q, want it left alone at %q", p.Actions[0].Rel, rel)
	}
	// A shell config is nobody's editor directory.
	if p.Actions[1].Dest != "" {
		t.Errorf(".zshrc was moved to %q", p.Actions[1].Dest)
	}
}

// Redirecting onto a file that is already there has to be classified again, or
// the plan reports "create" over something it is about to overwrite.
func TestRedirectReclassifiesAgainstTheNewLocation(t *testing.T) {
	staging := t.TempDir()
	home := t.TempDir()
	rel := "Library/Application Support/Code/User/settings.json"
	src := filepath.Join(staging, "home", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(src), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("incoming"), 0o600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(home, "Library/Application Support/Cursor/User/settings.json")
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("already here"), 0o600); err != nil {
		t.Fatal(err)
	}

	p := &Plan{Staging: staging, Actions: []Action{{Rel: rel, Kind: Create}}}
	p.RedirectEditorFiles(home, "cursor")

	if p.Actions[0].Kind != Overwrite {
		t.Errorf("kind = %q, want overwrite: something is already at the destination", p.Actions[0].Kind)
	}
}

func TestMissingToolsNamesTheCommand(t *testing.T) {
	got := MissingTools(map[string][]string{"macstash-no-such-tool": {"1.0"}, "go/versions": {"go1.24.4"}})

	var hasGo bool
	for _, c := range got {
		if c == "brew install go" {
			hasGo = true
		}
	}
	// Skipped rather than asserted when Go is installed on the test machine.
	if !hasGo && !commandAvailable("go") {
		t.Errorf("commands = %v, want the brew line for go", got)
	}
	for _, c := range got {
		if strings.Contains(c, "brew install macstash-no-such-tool") {
			t.Error("a tool with no known formula must not get a made-up brew command")
		}
	}
}
