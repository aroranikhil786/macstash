package capture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aroranikhil786/macstash/internal/catalog"
	"github.com/aroranikhil786/macstash/internal/classify"
)

// Managing dotfiles with stow or a chezmoi source tree makes ~/.config/<tool> a
// symlink to a directory. That is the normal setup for the people this tool
// targets, and skipping it silently — while still reporting the tool as
// detected — produces a bundle that looks complete and is not.
func TestSymlinkedConfigDirectoryIsCaptured(t *testing.T) {
	home := t.TempDir()

	real := filepath.Join(home, "dotfiles", "nvim")
	if err := os.MkdirAll(filepath.Join(real, "lua"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(real, "init.lua"), "vim.opt.number = true\n")
	write(t, filepath.Join(real, "lua", "plugins.lua"), "return {}\n")

	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".config", "nvim")); err != nil {
		t.Fatal(err)
	}

	entries := []catalog.Entry{{
		ID: "neovim", Name: "Neovim",
		Capture: catalog.Capture{Paths: []catalog.Path{
			{Path: "~/.config/nvim", Class: classify.Public},
		}},
	}}

	plan, err := Scan(home, entries)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	for _, f := range plan.Files {
		got[f.Rel] = true
	}
	for _, want := range []string{".config/nvim/init.lua", ".config/nvim/lua/plugins.lua"} {
		if !got[want] {
			t.Errorf("%s was not captured; files = %v", want, keys(got))
		}
	}

	// Reporting the tool as detected while capturing nothing is the failure that
	// makes this silent.
	if len(plan.Files) == 0 && len(plan.Detected) > 0 {
		t.Error("entry reported as detected but nothing was captured")
	}
}

// A symlink pointing at a never-listed path must not become a way to reach it.
func TestSymlinkedDirectoryCannotReachNeverPaths(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(home, ".aws", "credentials"), "AKIAPLANTED\n")
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".aws"), filepath.Join(home, ".config", "nvim")); err != nil {
		t.Fatal(err)
	}

	entries := []catalog.Entry{{
		ID: "neovim", Name: "Neovim",
		Capture: catalog.Capture{Paths: []catalog.Path{
			{Path: "~/.config/nvim", Class: classify.Public},
		}},
	}}
	plan, err := Scan(home, entries)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plan.Files {
		if filepath.Base(f.Rel) == "credentials" {
			t.Fatalf("reached a never-listed path through a symlinked directory: %s", f.Rel)
		}
	}
}

func write(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
