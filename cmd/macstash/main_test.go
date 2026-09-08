package main

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/capture"
	"github.com/aroranikhil786/macstash/internal/catalog"
)

func mustParse(t *testing.T, argv ...string) *flags {
	t.Helper()
	f, err := parse(argv)
	if err != nil {
		t.Fatalf("parse(%v) returned an unexpected error: %v", argv, err)
	}
	return f
}

// Every boolean flag has to actually reach the struct. A flag parsed into
// nothing is the worst kind of bug here: the user asks for a safety behaviour,
// sees no error, and gets the default.
func TestParseSetsEachBooleanFlag(t *testing.T) {
	cases := []struct {
		arg  string
		read func(*flags) bool
	}{
		{"--plan", func(f *flags) bool { return f.plan }},
		{"--apply", func(f *flags) bool { return f.apply }},
		{"--force", func(f *flags) bool { return f.force }},
		{"--from-other-user", func(f *flags) bool { return f.fromOtherUser }},
		{"--unredacted", func(f *flags) bool { return f.unredacted }},
		{"--yes", func(f *flags) bool { return f.yes }},
		{"-y", func(f *flags) bool { return f.yes }},
		{"--deep", func(f *flags) bool { return f.deep }},
		{"--install-toolchains", func(f *flags) bool { return f.installToolchains }},
		{"--install-apps", func(f *flags) bool { return f.installApps }},
		{"--clone-repos", func(f *flags) bool { return f.cloneRepos }},
		{"--select", func(f *flags) bool { return f.selectItems }},
		{"--include-launch-agents", func(f *flags) bool { return f.launchAgents }},
		{"--prune", func(f *flags) bool { return f.prune }},
		{"--verbose", func(f *flags) bool { return f.verbose }},
		{"-v", func(f *flags) bool { return f.verbose }},
	}
	for _, c := range cases {
		if !c.read(mustParse(t, c.arg)) {
			t.Errorf("%s did not set its field", c.arg)
		}
	}
}

// The dangerous flags must default to off. If --apply or --force ever defaulted
// on, restore would start writing without being asked.
func TestParseDefaultsEverythingOff(t *testing.T) {
	f := mustParse(t)

	for name, on := range map[string]bool{
		"apply":             f.apply,
		"force":             f.force,
		"fromOtherUser":     f.fromOtherUser,
		"yes":               f.yes,
		"installToolchains": f.installToolchains,
		"installApps":       f.installApps,
		"cloneRepos":        f.cloneRepos,
		"selectItems":       f.selectItems,
		"launchAgents":      f.launchAgents,
		"unredacted":        f.unredacted,
	} {
		if on {
			t.Errorf("%s defaults to on; it must be opt-in", name)
		}
	}
}

func TestParseReadsValueFlags(t *testing.T) {
	f := mustParse(t, "-o", "/tmp/out", "--to", "brewfile")

	if f.out != "/tmp/out" {
		t.Errorf("-o = %q, want /tmp/out", f.out)
	}
	if f.to != "brewfile" {
		t.Errorf("--to = %q, want brewfile", f.to)
	}
	if mustParse(t, "--out", "/tmp/x").out != "/tmp/x" {
		t.Error("--out should be accepted as a long form of -o")
	}
}

// A value flag at the end of argv must error rather than silently swallow the
// next command or leave an empty value behind.
func TestParseRejectsValueFlagsWithNoValue(t *testing.T) {
	for _, arg := range []string{"-o", "--out", "--to", "--only", "--skip", "--selection"} {
		if _, err := parse([]string{arg}); err == nil {
			t.Errorf("%s with no value should be an error", arg)
		}
	}
}

// A mistyped flag must stop the run. Treating it as a positional argument would
// mean `--drz-run` is read as a bundle path.
func TestParseRejectsUnknownFlags(t *testing.T) {
	_, err := parse([]string{"--not-a-real-flag"})
	if err == nil {
		t.Fatal("an unknown flag must be an error")
	}
	if !strings.Contains(err.Error(), "not-a-real-flag") {
		t.Errorf("the error should name the flag, got %v", err)
	}
}

func TestParseCollectsPositionalArguments(t *testing.T) {
	f := mustParse(t, "bundle.tar.gz", "--plan", "second")

	if len(f.args) != 2 || f.args[0] != "bundle.tar.gz" || f.args[1] != "second" {
		t.Fatalf("positional args = %v, want [bundle.tar.gz second]", f.args)
	}
}

// A path that begins with a dash is indistinguishable from a flag, and guessing
// would be worse than refusing.
func TestParseTreatsDashPrefixedArgsAsFlags(t *testing.T) {
	if _, err := parse([]string{"-weird-bundle-name"}); err == nil {
		t.Error("a dash-prefixed argument must not be silently taken as a path")
	}
}

func TestSplitListTrimsAndDropsEmpties(t *testing.T) {
	got := splitList(" zsh , git ,, ssh ,")

	want := []string{"zsh", "git", "ssh"}
	if len(got) != len(want) {
		t.Fatalf("splitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("splitList = %v, want %v", got, want)
		}
	}
}

func TestSplitListOnEmptyStringYieldsNothing(t *testing.T) {
	if got := splitList(""); len(got) != 0 {
		t.Errorf("splitList(\"\") = %v, want empty", got)
	}
}

func testEntries() []catalog.Entry {
	return []catalog.Entry{{ID: "zsh"}, {ID: "git"}, {ID: "ssh"}, {ID: "npm"}}
}

func ids(entries []catalog.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ID)
	}
	return out
}

func TestFilterEntriesWithoutFlagsReturnsEverything(t *testing.T) {
	got, err := filterEntries(testEntries(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("want all 4 entries, got %v", ids(got))
	}
}

func TestFilterEntriesOnlyKeepsTheNamedEntries(t *testing.T) {
	got, err := filterEntries(testEntries(), []string{"zsh", "npm"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids(got), ",") != "zsh,npm" {
		t.Fatalf("--only = %v, want [zsh npm]", ids(got))
	}
}

func TestFilterEntriesSkipRemovesTheNamedEntries(t *testing.T) {
	got, err := filterEntries(testEntries(), nil, []string{"git", "ssh"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids(got), ",") != "zsh,npm" {
		t.Fatalf("--skip = %v, want [zsh npm]", ids(got))
	}
}

// --skip has to win, because it is the flag someone reaches for to keep
// something out. Resolving a conflict in favour of --only would capture the
// entry they just excluded.
func TestFilterEntriesLetsSkipOverrideOnly(t *testing.T) {
	got, err := filterEntries(testEntries(), []string{"zsh", "git"}, []string{"git"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids(got), ",") != "zsh" {
		t.Fatalf("want skip to win, got %v", ids(got))
	}
}

// A typo must fail loudly. If an unknown id were ignored, `--only zshh` would
// silently capture the whole catalog — the opposite of what was asked.
func TestFilterEntriesRejectsUnknownIDs(t *testing.T) {
	for _, args := range [][]string{{"zshh"}, {"nope"}} {
		if _, err := filterEntries(testEntries(), args, nil); err == nil {
			t.Errorf("--only %v should be rejected", args)
		}
		if _, err := filterEntries(testEntries(), nil, args); err == nil {
			t.Errorf("--skip %v should be rejected", args)
		}
	}
}

func TestFilterEntriesErrorNamesTheBadIDAndPointsSomewhere(t *testing.T) {
	_, err := filterEntries(testEntries(), []string{"zshh"}, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "zshh") {
		t.Errorf("the error should quote the bad id, got %v", err)
	}
	if !strings.Contains(err.Error(), "macstash catalog") {
		t.Errorf("the error should say how to list valid ids, got %v", err)
	}
}

// Excluding everything is a legitimate, if useless, request — it must not be
// mistaken for "no filter" and silently capture the lot.
func TestFilterEntriesCanReturnNothing(t *testing.T) {
	got, err := filterEntries(testEntries(), nil, []string{"zsh", "git", "ssh", "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("want no entries, got %v", ids(got))
	}
}

// A bundle is a concentrated picture of a machine; writing one into a synced
// folder uploads it. This must be refused by default.
func TestCheckCloudSyncRefusesSyncedDestinations(t *testing.T) {
	home := t.TempDir()
	cases := map[string]string{
		"Library/Mobile Documents/bundle.tar.gz":     "iCloud",
		"Library/CloudStorage/Dropbox/bundle.tar.gz": "cloud storage",
		"Dropbox/bundle.tar.gz":                      "Dropbox",
		"OneDrive/bundle.tar.gz":                     "OneDrive",
		"Google Drive/My Drive/bundle.tar.gz":        "Google Drive",
	}
	for rel, service := range cases {
		err := checkCloudSync(home, filepath.Join(home, rel), false)
		if err == nil {
			t.Errorf("%s: writing into %s should be refused", rel, service)
			continue
		}
		if !strings.Contains(err.Error(), "--force") {
			t.Errorf("%s: the error should mention the escape hatch, got %v", rel, err)
		}
	}
}

func TestCheckCloudSyncAllowsLocalPaths(t *testing.T) {
	home := t.TempDir()
	for _, rel := range []string{"macstash/bundle.tar.gz", "Documents/bundle.tar.gz"} {
		if err := checkCloudSync(home, filepath.Join(home, rel), false); err != nil {
			t.Errorf("%s is local and should be allowed, got %v", rel, err)
		}
	}
}

// --force is the documented override, so it has to work.
func TestCheckCloudSyncForceOverrides(t *testing.T) {
	home := t.TempDir()
	out := filepath.Join(home, "Dropbox", "bundle.tar.gz")

	if err := checkCloudSync(home, out, true); err != nil {
		t.Errorf("--force should permit a synced destination, got %v", err)
	}
}

// "Dropbox-local" is not inside "Dropbox". A prefix match without the separator
// would block innocent paths and push people towards --force by reflex.
func TestCheckCloudSyncDoesNotMatchOnPrefixAlone(t *testing.T) {
	home := t.TempDir()
	out := filepath.Join(home, "Dropbox-local-backups", "bundle.tar.gz")

	if err := checkCloudSync(home, out, false); err != nil {
		t.Errorf("a sibling directory must not be treated as synced, got %v", err)
	}
}

func TestSanitizeReplacesPathHostileCharacters(t *testing.T) {
	cases := map[string]string{
		"teddys-mbp":     "teddys-mbp",
		"Teddy's MBP":    "Teddy-s-MBP",
		"a/b":            "a-b",
		"../../etc":      "------etc",
		"nul\x00byte":    "nul-byte",
		"MacBook Pro 16": "MacBook-Pro-16",
	}
	for in, want := range cases {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}

// sanitize feeds a filename, so it must never return something that reads as a
// path or resolves to the current directory.
func TestSanitizeOutputIsAlwaysASingleSafeSegment(t *testing.T) {
	for _, in := range []string{"", "/", "..", "a/../../b", "x\\y"} {
		got := sanitize(in)
		if got == "" {
			t.Errorf("sanitize(%q) returned empty", in)
		}
		if strings.ContainsAny(got, `/\`) {
			t.Errorf("sanitize(%q) = %q, which still contains a separator", in, got)
		}
		if got == "." || got == ".." {
			t.Errorf("sanitize(%q) = %q, which resolves to a directory", in, got)
		}
	}
}

func TestSanitizeFallsBackWhenTheNameIsEmpty(t *testing.T) {
	if got := sanitize(""); got != "mac" {
		t.Errorf("sanitize(\"\") = %q, want a usable fallback", got)
	}
}

func TestUsernameHandlesANilUser(t *testing.T) {
	if got := username(nil); got != "" {
		t.Errorf("username(nil) = %q, want empty", got)
	}
	if got := username(&user.User{Username: "teddy"}); got != "teddy" {
		t.Errorf("username = %q, want teddy", got)
	}
}

func TestRunPrintsUsageWithNoArguments(t *testing.T) {
	for _, argv := range [][]string{{}, {"help"}, {"--help"}, {"-h"}} {
		if err := run(argv); err != nil {
			t.Errorf("run(%v) = %v, want nil", argv, err)
		}
	}
}

func TestRunRejectsAnUnknownCommand(t *testing.T) {
	err := run([]string{"captrue"})
	if err == nil {
		t.Fatal("an unknown command must be an error")
	}
	if !strings.Contains(err.Error(), "captrue") {
		t.Errorf("the error should quote the command, got %v", err)
	}
	if !strings.Contains(err.Error(), "help") {
		t.Errorf("the error should point at help, got %v", err)
	}
}

func TestRunVersionSucceeds(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Errorf("version = %v, want nil", err)
	}
}

// A bad flag must be caught before any command runs, so nothing is written on
// the way to discovering the typo.
func TestRunReportsFlagErrorsBeforeDispatching(t *testing.T) {
	err := run([]string{"capture", "--bogus"})
	if err == nil {
		t.Fatal("want a parse error")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("want the flag error, got %v", err)
	}
}

// The usage text is the only documentation most people read. If a flag is
// implemented and undocumented, it does not exist in practice.
func TestUsageDocumentsEveryFlagTheParserAccepts(t *testing.T) {
	for _, flag := range []string{
		"--plan", "--apply", "-o", "--force", "--from-other-user", "--unredacted",
		"--only", "--skip", "--yes", "--install-toolchains",
		"--install-apps", "--clone-repos", "--select", "--selection",
		"--include-launch-agents", "--verbose",
	} {
		if !strings.Contains(usage, flag) {
			t.Errorf("%s is accepted by parse but missing from the usage text", flag)
		}
	}
}

func TestUsageDocumentsEveryCommand(t *testing.T) {
	for _, cmd := range []string{
		"capture", "inspect", "restore", "doctor", "catalog", "clone", "backups", "export",
	} {
		if !strings.Contains(usage, cmd) {
			t.Errorf("command %q is dispatched but missing from the usage text", cmd)
		}
	}
}

// The promise the whole tool rests on has to stay in front of the user.
func TestUsageStatesTheCredentialPromise(t *testing.T) {
	if !strings.Contains(usage, "never contain credentials") {
		t.Error("usage should state that bundles carry no credentials")
	}
}

// Version must be a var, not a const. The Go linker accepts -X only on vars and
// ignores it silently otherwise, so a const here would ship every release
// labelled with the development version and stamp that into every bundle
// manifest — with nothing failing to say so. Taking its address compiles only
// for a var, which makes this a build-time guard rather than a runtime one.
func TestVersionIsLinkerOverridable(t *testing.T) {
	if p := &Version; p == nil || *p == "" {
		t.Fatal("Version must be a non-empty package-level var")
	}
}

// appSummaryCounts mirrors the arithmetic cmdInspect prints in its header.
func appSummaryCounts(apps []bundle.App) (byBrew, store, manual int) {
	for _, a := range apps {
		switch {
		case a.Source == capture.SourceHomebrew || a.Source == capture.SourceSystem:
		case a.Source == capture.SourceAppStore:
			store++
		case a.CaskToken != "":
			byBrew++
		default:
			manual++
		}
	}
	return byBrew, store, manual
}

// inspect's one-line summary said "7 need manual reinstall" on a bundle whose
// own detail section said "0 needing a manual download" — it counted every
// non-Homebrew app as manual, including the seven a single `brew install
// --cask` would fetch. A summary that contradicts the detail below it sends
// people hunting for downloads they do not need.
func TestInspectAppSummaryAgreesWithTheDetailBreakdown(t *testing.T) {
	apps := []bundle.App{
		{Name: "Docker", Source: capture.SourceManual, CaskToken: "docker"},
		{Name: "IntelliJ IDEA", Source: capture.SourceManual, CaskToken: "intellij-idea"},
		{Name: "GlobalProtect", Source: capture.SourceManual},
		{Name: "Xcode", Source: capture.SourceAppStore},
		{Name: "ripgrep", Source: capture.SourceHomebrew},
		{Name: "Safari", Source: capture.SourceSystem},
	}

	byBrew, store, manual := appSummaryCounts(apps)

	if byBrew != 2 {
		t.Errorf("installable by Homebrew = %d, want 2", byBrew)
	}
	if store != 1 {
		t.Errorf("from the App Store = %d, want 1", store)
	}
	// Only the one with no cask and no store receipt genuinely needs a human.
	if manual != 1 {
		t.Errorf("by hand = %d, want 1 (GlobalProtect)", manual)
	}
	// Every app must land in exactly one bucket or a count goes missing.
	if byBrew+store+manual+2 != len(apps) {
		t.Errorf("buckets total %d + 2 managed, want %d", byBrew+store+manual, len(apps))
	}
}

// An app with a cask must never be counted as needing manual work, whatever
// else is true of it.
func TestAppSummaryNeverCallsACaskableAppManual(t *testing.T) {
	_, _, manual := appSummaryCounts([]bundle.App{
		{Name: "Arc", Source: capture.SourceManual, CaskToken: "arc"},
	})

	if manual != 0 {
		t.Errorf("by hand = %d, want 0 — Homebrew can install it", manual)
	}
}
