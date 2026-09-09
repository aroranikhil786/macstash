package capture

import (
	"os"
	"path/filepath"
	"testing"
)

// The manifest is the point of the whole change: no PATH, no running editor,
// no exec.
func TestExtensionsComeFromTheManifestWithoutAnyCommand(t *testing.T) {
	dir := t.TempDir()
	ext := filepath.Join(dir, "extensions")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `[
	  {"identifier":{"id":"gruntfuggly.todo-tree"},"version":"0.0.226"},
	  {"identifier":{"id":"anthropic.claude-code"},"version":"2.1.211"},
	  {"identifier":{"id":"anthropic.claude-code"},"version":"2.1.193"}
	]`
	if err := os.WriteFile(filepath.Join(ext, "extensions.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	got := extensionsFromManifest(dir)

	// Two ids, not three: the same extension at two versions is one extension.
	want := []string{"anthropic.claude-code", "gruntfuggly.todo-tree"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

func TestExtensionsFromManifestSurvivesRubbish(t *testing.T) {
	dir := t.TempDir()
	if got := extensionsFromManifest(dir); got != nil {
		t.Errorf("a missing manifest should yield nothing, got %v", got)
	}

	ext := filepath.Join(dir, "extensions")
	if err := os.MkdirAll(ext, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ext, "extensions.json"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := extensionsFromManifest(dir); got != nil {
		t.Errorf("an unreadable manifest should yield nothing, got %v", got)
	}
}

// Every editor macstash restores to must be one it can also capture from, or a
// bundle records extensions it has no way to reinstall.
func TestEveryEditorHasADataDirectory(t *testing.T) {
	for _, editor := range []string{"code", "code-insiders", "cursor", "windsurf"} {
		if _, ok := editorDataDirs[editor]; !ok {
			t.Errorf("%s has no extensions directory mapped", editor)
		}
	}
}
