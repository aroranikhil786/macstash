package capture

import (
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

func hasCandidate(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

// The plain case: hyphenate and lowercase.
func TestCaskCandidatesDerivesTheObviousToken(t *testing.T) {
	got := caskCandidates(bundle.App{Name: "Android Studio"})

	if len(got) == 0 || got[0] != "android-studio" {
		t.Fatalf("candidates = %v, want android-studio first", got)
	}
}

// The aliases are the whole point: these are the ones no rule derives. Each was
// checked against `brew info --cask` on a real machine.
func TestCaskCandidatesUsesTheAliasFirst(t *testing.T) {
	cases := map[string]string{
		"iTerm":                         "iterm2",
		"GitHub Desktop":                "github",
		"Visual Studio Code - Insiders": "visual-studio-code@insiders",
		"Postman 2":                     "postman",
	}
	for name, want := range cases {
		got := caskCandidates(bundle.App{Name: name})
		if len(got) == 0 || got[0] != want {
			t.Errorf("%q: candidates = %v, want %q first", name, got, want)
		}
	}
}

// "Postman 2" should also reach "postman" by rule, not only by alias, so the
// next app that ships a version number in its name works without a code change.
func TestCaskCandidatesStripsATrailingVersionNumber(t *testing.T) {
	got := caskCandidates(bundle.App{Name: "Some Editor 3"})

	if !hasCandidate(got, "some-editor") {
		t.Errorf("candidates = %v, want a version-stripped form", got)
	}
}

// Stripping any trailing word would turn "Android Studio" into "android", which
// is a different, real cask. Only numeric words may be dropped.
func TestCaskCandidatesKeepsTrailingWordsThatAreNotNumbers(t *testing.T) {
	got := caskCandidates(bundle.App{Name: "Android Studio"})

	if hasCandidate(got, "android") {
		t.Errorf("candidates = %v, must not truncate to a different cask", got)
	}
}

func TestCaskCandidatesTriesTheBundleIDComponent(t *testing.T) {
	got := caskCandidates(bundle.App{Name: "Obsidian", BundleID: "md.obsidian"})

	if !hasCandidate(got, "obsidian") {
		t.Errorf("candidates = %v, want the bundle id component", got)
	}
}

func TestCaskCandidatesDoesNotRepeatItself(t *testing.T) {
	got := caskCandidates(bundle.App{Name: "Rectangle", BundleID: "com.rectangle.Rectangle"})

	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Fatalf("candidates = %v, %q appears twice", got, c)
		}
		seen[c] = true
	}
}

func TestCaskCandidatesHandlesAnEmptyName(t *testing.T) {
	if got := caskCandidates(bundle.App{}); len(got) != 0 {
		t.Errorf("candidates = %v, want none for an unnamed app", got)
	}
}

// Resolution must not touch apps Homebrew already manages or that ship with
// macOS: reinstalling Safari is not a migration step.
func TestResolveCasksLeavesManagedAndSystemAppsAlone(t *testing.T) {
	in := []bundle.App{
		{Name: "Safari", Source: SourceSystem},
		{Name: "ripgrep", Source: SourceHomebrew},
	}

	got := ResolveCasks(in)

	for _, a := range got {
		if a.CaskToken != "" {
			t.Errorf("%s (%s) should not be given a cask token, got %q", a.Name, a.Source, a.CaskToken)
		}
	}
}

// ResolveCasks must not mutate the slice it was handed; capture keeps using it.
func TestResolveCasksDoesNotMutateItsInput(t *testing.T) {
	in := []bundle.App{{Name: "Arc", Source: SourceManual}}

	_ = ResolveCasks(in)

	if in[0].CaskToken != "" {
		t.Error("ResolveCasks wrote through to its argument")
	}
}

func TestInstallableAppsSelectsOnlyAppsWithATokenThatBrewDoesNotAlreadyOwn(t *testing.T) {
	apps := []bundle.App{
		{Name: "Arc", Source: SourceManual, CaskToken: "arc"},
		{Name: "Handmade", Source: SourceManual},
		{Name: "ripgrep", Source: SourceHomebrew, CaskToken: "ripgrep"},
		{Name: "Safari", Source: SourceSystem, CaskToken: "safari"},
	}

	got := InstallableApps(apps)

	if len(got) != 1 || got[0].Name != "Arc" {
		t.Fatalf("installable = %+v, want just Arc", got)
	}
}

func TestUnmanagedAppsIsTheAppsWithNoCask(t *testing.T) {
	apps := []bundle.App{
		{Name: "Arc", Source: SourceManual, CaskToken: "arc"},
		{Name: "Handmade", Source: SourceManual},
		{Name: "Safari", Source: SourceSystem},
	}

	got := UnmanagedApps(apps)

	if len(got) != 1 || got[0].Name != "Handmade" {
		t.Fatalf("unmanaged = %+v, want just Handmade", got)
	}
}

// Every app has to land in exactly one bucket. An app that falls through both
// vanishes from the report, which is the failure mode this whole area exists to
// prevent.
func TestEveryUnmanagedAppIsInExactlyOneBucket(t *testing.T) {
	apps := []bundle.App{
		{Name: "Arc", Source: SourceManual, CaskToken: "arc"},
		{Name: "Handmade", Source: SourceManual},
		{Name: "Store App", Source: SourceAppStore},
		{Name: "ripgrep", Source: SourceHomebrew},
		{Name: "Safari", Source: SourceSystem},
	}

	counts := map[string]int{}
	for _, a := range InstallableApps(apps) {
		counts[a.Name]++
	}
	for _, a := range UnmanagedApps(apps) {
		counts[a.Name]++
	}

	for _, name := range []string{"Arc", "Handmade", "Store App"} {
		if counts[name] != 1 {
			t.Errorf("%s appears in %d buckets, want exactly 1", name, counts[name])
		}
	}
	for _, name := range []string{"ripgrep", "Safari"} {
		if counts[name] != 0 {
			t.Errorf("%s is already handled elsewhere and should be in neither bucket", name)
		}
	}
}

// The alias table is only useful if the tokens are real. This does not call
// brew — it guards against typos of the shape that would silently produce a
// "no cask" verdict for an app that has one.
func TestCaskAliasTokensAreWellFormed(t *testing.T) {
	for name, token := range caskAliases {
		if token == "" {
			t.Errorf("%q maps to an empty token", name)
		}
		if strings.ContainsAny(token, " _") || strings.ToLower(token) != token {
			t.Errorf("%q maps to %q, which is not a valid cask token shape", name, token)
		}
		if strings.ToLower(name) != name {
			t.Errorf("alias key %q must be lowercase or it will never match", name)
		}
	}
}
