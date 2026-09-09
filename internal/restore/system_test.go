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

	p.RestoreExtensions(&buf, false)

	out := buf.String()
	if !strings.Contains(out, "not on PATH") {
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

	p.RestoreExtensions(&buf, true)

	out := buf.String()
	if !strings.Contains(out, "installed 0, failed 2") {
		t.Errorf("want the failures counted, got:\n%s", out)
	}
	if !strings.Contains(out, "failed: golang.go") {
		t.Errorf("want the failures named, got:\n%s", out)
	}
}
