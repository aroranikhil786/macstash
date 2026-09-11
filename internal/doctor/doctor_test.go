package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

// writeFile creates a file under dir and returns its sha256, so tests can build
// a manifest that genuinely matches (or deliberately does not match) the disk.
func writeFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// problems drops the confirmations, so a test about what went wrong is not
// rewritten every time doctor learns to say what went right.
func problems(checks []Check) []Check {
	var out []Check
	for _, c := range checks {
		if c.Status != OK {
			out = append(out, c)
		}
	}
	return out
}

func only(t *testing.T, checks []Check, area string) []Check {
	t.Helper()
	var out []Check
	for _, c := range checks {
		if c.Area == area {
			out = append(out, c)
		}
	}
	return out
}

// A file recorded in the manifest but absent from the machine is the plainest
// thing doctor exists to catch.
func TestCheckFilesReportsAMissingFile(t *testing.T) {
	home := t.TempDir()
	man := &bundle.Manifest{Items: []bundle.Item{
		{Entry: "zsh", Rel: ".zshrc", SHA256: "whatever"},
	}}

	checks := checkFiles(home, man)

	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(checks), checks)
	}
	if checks[0].Status != Missing {
		t.Errorf("want status %q, got %q", Missing, checks[0].Status)
	}
	if !strings.Contains(checks[0].Detail, ".zshrc") {
		t.Errorf("detail should name the file, got %q", checks[0].Detail)
	}
	// The fix has to be runnable as printed, scoped to the entry that owns the
	// file — a bare `restore --apply` would rewrite everything else too.
	if !strings.Contains(checks[0].Fix, "--only zsh") {
		t.Errorf("fix should scope to the entry, got %q", checks[0].Fix)
	}
}

// A file present and byte-identical is not worth telling anyone about.
func TestCheckFilesSaysNothingWhenTheFileMatches(t *testing.T) {
	home := t.TempDir()
	sum := writeFile(t, home, ".zshrc", "export EDITOR=vim\n")
	man := &bundle.Manifest{Items: []bundle.Item{
		{Entry: "zsh", Rel: ".zshrc", SHA256: sum},
	}}

	if p := problems(checkFiles(home, man)); len(p) != 0 {
		t.Fatalf("an unmodified file is not a problem, got %+v", p)
	}
}

// Editing your own config after a restore is the correct thing to do, so it is
// reported as OK rather than as damage. If this ever regresses to Missing,
// doctor starts nagging people for using their own machine.
func TestCheckFilesReportsAnEditedFileAsOKNotMissing(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".zshrc", "edited since the restore\n")
	man := &bundle.Manifest{Items: []bundle.Item{
		{Entry: "zsh", Rel: ".zshrc", SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
	}}

	checks := checkFiles(home, man)

	if p := problems(checks); len(p) != 0 {
		t.Fatalf("a user edit must not be reported as a problem, got %+v", p)
	}
	var edited bool
	for _, c := range checks {
		if strings.Contains(c.Detail, "edited") {
			edited = true
		}
	}
	if !edited {
		t.Errorf("the divergence should still be reported, got %+v", checks)
	}
}

// An item with no recorded hash can still be checked for existence.
func TestCheckFilesSkipsComparisonWhenNoHashWasRecorded(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".tmux.conf", "set -g mouse on\n")
	man := &bundle.Manifest{Items: []bundle.Item{
		{Entry: "tmux", Rel: ".tmux.conf"},
	}}

	if p := problems(checkFiles(home, man)); len(p) != 0 {
		t.Fatalf("a present file with no hash is not a problem, got %+v", p)
	}
}

// checkFiles must not follow a relative path out of the home it was given.
func TestCheckFilesResolvesRelativeToTheGivenHome(t *testing.T) {
	home := t.TempDir()
	other := t.TempDir()
	writeFile(t, other, ".zshrc", "not in home\n")

	man := &bundle.Manifest{Items: []bundle.Item{{Entry: "zsh", Rel: ".zshrc"}}}

	checks := checkFiles(home, man)
	if len(checks) != 1 || checks[0].Status != Missing {
		t.Fatalf("a file outside the given home must read as missing, got %+v", checks)
	}
}

// Every scrubbed credential must surface as an Action with a re-auth command.
// This is the check that pays for the scrub class existing at all: without it a
// stripped token becomes an unexplained 401 weeks later.
func TestCheckScrubsReportsEveryRemovedCredential(t *testing.T) {
	man := &bundle.Manifest{Scrubs: []scrub.Record{
		{File: ".npmrc", Reason: "registry auth token", Count: 2},
		{File: ".docker/config.json", Reason: "registry logins", Count: 1},
	}}

	checks := checkScrubs(man)

	if len(checks) != 2 {
		t.Fatalf("want one check per scrub record, got %d", len(checks))
	}
	for _, c := range checks {
		if c.Status != Action {
			t.Errorf("%s: scrubs need a human, want %q got %q", c.Detail, Action, c.Status)
		}
		if c.Fix == "" {
			t.Errorf("%s: every scrub needs a re-auth instruction", c.Detail)
		}
	}
	if !strings.Contains(checks[0].Detail, "2 occurrence") {
		t.Errorf("the count should reach the user, got %q", checks[0].Detail)
	}
	// The reason from capture must survive into the report, otherwise the user
	// is told a credential went missing but not which one.
	if !strings.Contains(checks[0].Detail, "registry auth token") {
		t.Errorf("the capture-time reason should be carried through, got %q", checks[0].Detail)
	}
}

func TestReauthCommandMapsKnownFormats(t *testing.T) {
	cases := map[string]string{
		".npmrc":                    "npm login",
		".docker/config.json":       "docker login",
		".gitconfig":                "credential helper",
		".gradle/gradle.properties": "gradle.properties",
		".pypirc":                   "PyPI",
	}
	for file, want := range cases {
		if got := reauthCommand(file); !strings.Contains(got, want) {
			t.Errorf("reauthCommand(%q) = %q, want it to mention %q", file, got, want)
		}
	}
	// Anything unrecognised still has to say something actionable rather than
	// return an empty string that renders as a blank line.
	if got := reauthCommand(".config/some-new-tool/auth"); got == "" {
		t.Error("an unknown format must still produce a non-empty instruction")
	}
}

// Apps that Homebrew installed, or that ship with macOS, are not the user's
// problem and must not appear on the hand-install list.
func TestCheckAppsIgnoresHomebrewAndSystemApps(t *testing.T) {
	man := &bundle.Manifest{Applications: []bundle.App{
		{Name: "macstash-test-brew-app", Source: "homebrew"},
		{Name: "macstash-test-system-app", Source: "system"},
	}}

	// Not merely absent from the problem list: these were never examined, so
	// doctor must not confirm them either.
	if checks := checkApps(man); len(checks) != 0 {
		t.Fatalf("homebrew and system apps are neither checked nor reported, got %+v", checks)
	}
}

func TestCheckAppsReportsHandInstalledAppsThatAreAbsent(t *testing.T) {
	man := &bundle.Manifest{Applications: []bundle.App{
		// A name no machine will have, so the check cannot pass by accident.
		{Name: "macstash-test-absent-app", Source: "manual"},
	}}

	checks := checkApps(man)

	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(checks), checks)
	}
	if checks[0].Status != Action {
		t.Errorf("want %q, got %q", Action, checks[0].Status)
	}
	if !strings.Contains(checks[0].Detail, "macstash-test-absent-app") {
		t.Errorf("the app should be named, got %q", checks[0].Detail)
	}
}

// Permissions can never be granted by a tool, so they always report, and always
// as Action. A silent pass here would be a lie.
func TestCheckPermissionsAlwaysReportsAsAction(t *testing.T) {
	man := &bundle.Manifest{Requirements: []bundle.Requirement{
		{Entry: "rectangle", Name: "Rectangle", Permissions: []string{"accessibility"}},
		{Entry: "karabiner", Name: "Karabiner", Permissions: []string{"input_monitoring", "accessibility"}},
		{Entry: "zsh", Name: "zsh"}, // no permissions, contributes nothing
	}}

	checks := checkPermissions(man)

	if len(checks) != 3 {
		t.Fatalf("want one check per permission, got %d: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Status != Action {
			t.Errorf("%q: want %q, got %q", c.Detail, Action, c.Status)
		}
		if !strings.Contains(c.Fix, "System Settings") {
			t.Errorf("%q: the fix should point at System Settings, got %q", c.Detail, c.Fix)
		}
	}
}

func TestCheckSDKsReportsAMissingVersionManager(t *testing.T) {
	man := &bundle.Manifest{System: bundle.System{SDKs: map[string][]string{
		"macstash-absent-version-manager": {"1.2.3", "4.5.6"},
	}}}

	checks := checkSDKs(man)

	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(checks), checks)
	}
	if checks[0].Status != Missing {
		t.Errorf("want %q, got %q", Missing, checks[0].Status)
	}
	// The count matters: "pyenv missing" is very different from "pyenv missing,
	// and with it 6 recorded Python versions".
	if !strings.Contains(checks[0].Detail, "2 recorded version") {
		t.Errorf("the version count should be reported, got %q", checks[0].Detail)
	}
}

// go and rust reach the machine through Homebrew, so reporting them here as
// well would double-count them in the summary.
func TestCheckSDKsDefersGoAndRustToHomebrew(t *testing.T) {
	man := &bundle.Manifest{System: bundle.System{SDKs: map[string][]string{
		"go":   {"1.25"},
		"rust": {"1.80"},
	}}}

	if p := problems(checkSDKs(man)); len(p) != 0 {
		t.Fatalf("go and rust are reported via homebrew, got %+v", p)
	}
}

func TestCheckToolchainsReportsAMissingPackageManager(t *testing.T) {
	man := &bundle.Manifest{System: bundle.System{Toolchains: map[string][]string{
		"macstash-absent-package-manager": {"a", "b", "c"},
	}}}

	checks := checkToolchains(man)

	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d", len(checks))
	}
	if !strings.Contains(checks[0].Detail, "3 global package") {
		t.Errorf("want the package count in the detail, got %q", checks[0].Detail)
	}
}

// A bundle captured on a machine without Homebrew has no Brewfile, and that is
// not an error.
func TestCheckBrewIsSilentWithoutABrewfile(t *testing.T) {
	if checks := checkBrew(&bundle.Manifest{}); len(checks) != 0 {
		t.Fatalf("no brewfile means nothing to check, got %+v", checks)
	}
}

func TestTruncateKeepsEverythingUnderTheLimit(t *testing.T) {
	in := []string{"a", "b", "c"}
	if got := truncate(in, 8); len(got) != 3 {
		t.Fatalf("want 3, got %d", len(got))
	}
}

func TestTruncateSaysHowManyItHid(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e"}

	got := truncate(in, 2)

	if len(got) != 3 {
		t.Fatalf("want 2 items plus a summary line, got %d: %v", len(got), got)
	}
	// Silent truncation would read as a complete list. The count has to show.
	if !strings.Contains(got[2], "+3 more") {
		t.Errorf("want the hidden count, got %q", got[2])
	}
}

func TestTruncateDoesNotMutateItsInput(t *testing.T) {
	in := []string{"a", "b", "c", "d"}
	_ = truncate(in, 2)
	for i, want := range []string{"a", "b", "c", "d"} {
		if in[i] != want {
			t.Fatalf("truncate modified its input: %v", in)
		}
	}
}

func TestSummariseCountsEachStatus(t *testing.T) {
	out := Summarise([]Check{
		{Area: "files", Status: Missing, Detail: "one"},
		{Area: "files", Status: Missing, Detail: "two"},
		{Area: "credentials", Status: Action, Detail: "three"},
		{Area: "files", Status: OK, Detail: "four"},
	}, false)

	if !strings.Contains(out, "4 checked, 2 missing, 1 needing you") {
		t.Errorf("summary line wrong, got:\n%s", out)
	}
	if !strings.Contains(out, "one") || !strings.Contains(out, "three") {
		t.Errorf("missing and action items must both be listed, got:\n%s", out)
	}
	// OK items are counted but not enumerated; listing them buries the problems.
	if strings.Contains(out, "four") {
		t.Errorf("OK items should not be listed individually, got:\n%s", out)
	}
}

func TestSummariseIncludesTheFixWhenThereIsOne(t *testing.T) {
	out := Summarise([]Check{
		{Area: "homebrew", Status: Missing, Detail: "ripgrep not installed", Fix: "brew install ripgrep"},
	}, false)

	if !strings.Contains(out, "brew install ripgrep") {
		t.Errorf("the fix should be printed, got:\n%s", out)
	}
}

// The empty case must not claim the machine is complete — doctor only knows
// what was captured, and saying otherwise is exactly the false assurance the
// whole tool is built to avoid.
func TestSummariseRefusesToClaimTheMachineIsComplete(t *testing.T) {
	out := Summarise(nil, false)

	if !strings.Contains(out, "Nothing outstanding") {
		t.Fatalf("want the empty-state message, got:\n%s", out)
	}
	if !strings.Contains(out, "not a guarantee") {
		t.Errorf("the empty state must carry its caveat, got:\n%s", out)
	}
}

func TestSummariseOrdersMissingBeforeAction(t *testing.T) {
	out := Summarise([]Check{
		{Area: "credentials", Status: Action, Detail: "re-auth npm"},
		{Area: "files", Status: Missing, Detail: "zshrc absent"},
	}, false)

	iMissing := strings.Index(out, "zshrc absent")
	iAction := strings.Index(out, "re-auth npm")
	if iMissing == -1 || iAction == -1 {
		t.Fatalf("both should appear, got:\n%s", out)
	}
	if iMissing > iAction {
		t.Errorf("missing items should come first, got:\n%s", out)
	}
}

// Run must wire every sub-check in. A check dropped from Run is invisible: the
// report simply gets shorter and nobody notices.
func TestRunIncludesEveryCheckCategory(t *testing.T) {
	home := t.TempDir()
	man := &bundle.Manifest{
		Items:  []bundle.Item{{Entry: "zsh", Rel: ".zshrc"}},
		Scrubs: []scrub.Record{{File: ".npmrc", Reason: "token", Count: 1}},
		Requirements: []bundle.Requirement{
			{Entry: "rectangle", Name: "Rectangle", Permissions: []string{"accessibility"}},
		},
		Applications: []bundle.App{{Name: "macstash-test-absent-app", Source: "manual"}},
		System: bundle.System{
			SDKs:       map[string][]string{"macstash-absent-version-manager": {"1.0"}},
			Toolchains: map[string][]string{"macstash-absent-package-manager": {"pkg"}},
		},
	}

	checks := Run(home, man, false)

	for _, area := range []string{"files", "credentials", "permissions", "applications", "runtimes", "toolchains"} {
		if len(only(t, checks, area)) == 0 {
			t.Errorf("Run produced no %q checks; is that category still wired in?", area)
		}
	}
}

// deep checks run real commands, so the shallow path must not.
func TestRunSkipsDeepChecksUnlessAsked(t *testing.T) {
	checks := Run(t.TempDir(), &bundle.Manifest{}, false)

	if got := only(t, checks, "deep"); len(got) != 0 {
		t.Fatalf("deep checks ran without --deep: %+v", got)
	}
}

// MCP definitions are never captured, so this check is the only trace a restore
// leaves of them. It has to be an Action: no tool can re-add them.
func TestCheckMCPReportsServersMissingHere(t *testing.T) {
	home := t.TempDir() // no MCP configs at all, so everything is missing
	man := &bundle.Manifest{System: bundle.System{MCPServers: []bundle.MCPServer{
		{Name: "postgres", Source: "~/.cursor/mcp.json", EnvKeys: []string{"DATABASE_URI"}},
		{Name: "context7", Source: "~/.cursor/mcp.json"},
	}}}

	checks := checkMCP(home, man)

	if len(checks) != 1 {
		t.Fatalf("want 1 check, got %d: %+v", len(checks), checks)
	}
	if checks[0].Status != Action {
		t.Errorf("want %q, got %q", Action, checks[0].Status)
	}
	if !strings.Contains(checks[0].Detail, "2 MCP server") {
		t.Errorf("want the count, got %q", checks[0].Detail)
	}
	// The variable names are the part worth carrying; the fix must name them.
	if !strings.Contains(checks[0].Fix, "DATABASE_URI") {
		t.Errorf("the fix should say what the server needs, got %q", checks[0].Fix)
	}
}

// A server already configured here is not a task. Telling someone to re-add it
// is how duplicate entries happen.
func TestCheckMCPIgnoresServersAlreadyConfigured(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{"mcpServers":{"context7":{"command":"npx"}}}`
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	man := &bundle.Manifest{System: bundle.System{MCPServers: []bundle.MCPServer{
		{Name: "context7", Source: "~/.cursor/mcp.json"},
	}}}

	if p := problems(checkMCP(home, man)); len(p) != 0 {
		t.Fatalf("an already-configured server is not outstanding: %+v", p)
	}
}

func TestCheckMCPIsSilentWhenNoneWereRecorded(t *testing.T) {
	if checks := checkMCP(t.TempDir(), &bundle.Manifest{}); len(checks) != 0 {
		t.Fatalf("want nothing, got %+v", checks)
	}
}

// The summary used to count only OK checks as "fine", and almost nothing
// produced one, so a healthy machine reported zero and looked unexamined.
func TestSummaryCountsWhatWasChecked(t *testing.T) {
	out := Summarise([]Check{
		{Area: "files", Status: OK, Detail: "12 restored file(s) still in place"},
		{Area: "homebrew", Status: OK, Detail: "all 14 recorded package(s) installed"},
	}, false)

	if !strings.Contains(out, "2 checked, 0 missing, 0 needing you") {
		t.Errorf("want the checked count, got:\n%s", out)
	}
	// The detail stays behind --verbose, but its existence must be visible.
	if !strings.Contains(out, "2 check(s) confirmed fine") {
		t.Errorf("want the confirmation count, got:\n%s", out)
	}
	if strings.Contains(out, "restored file(s) still in place") {
		t.Errorf("confirmations should not be listed without --verbose, got:\n%s", out)
	}
}

func TestVerboseListsTheConfirmations(t *testing.T) {
	out := Summarise([]Check{
		{Area: "files", Status: OK, Detail: "12 restored file(s) still in place"},
	}, true)

	if !strings.Contains(out, "12 restored file(s) still in place") {
		t.Errorf("--verbose must list what was confirmed, got:\n%s", out)
	}
}

// The permission line named the catalog's word for the app and the raw
// identifier for the permission. System Settings uses neither, so the person
// hunting through the privacy list did not find it.
func TestPermissionsAreNamedTheWayMacOSNamesThem(t *testing.T) {
	checks := checkPermissions(&bundle.Manifest{Requirements: []bundle.Requirement{
		{Entry: "iterm2", Name: "iTerm2", AppName: "iTerm", Permissions: []string{"full_disk_access"}},
	}})

	if len(checks) != 1 {
		t.Fatalf("checks = %+v, want one", checks)
	}
	if strings.Contains(checks[0].Detail, "full_disk_access") {
		t.Errorf("the raw identifier leaked into the output: %q", checks[0].Detail)
	}
	if !strings.Contains(checks[0].Detail, "Full Disk Access") {
		t.Errorf("want the System Settings wording, got %q", checks[0].Detail)
	}
	if !strings.Contains(checks[0].Detail, "iTerm ") && !strings.HasSuffix(checks[0].Detail, "iTerm") {
		t.Errorf("want the application named as macOS names it, got %q", checks[0].Detail)
	}
}

// A permission macstash cannot test must not be reported as though it had been.
func TestAnUntestablePermissionSaysSo(t *testing.T) {
	checks := checkPermissions(&bundle.Manifest{Requirements: []bundle.Requirement{
		{Entry: "rectangle", AppName: "Rectangle", Permissions: []string{"accessibility"}},
	}})

	if len(checks) != 1 || checks[0].Status != Action {
		t.Fatalf("checks = %+v, want one action", checks)
	}
	if !strings.Contains(checks[0].Detail, "cannot see whether it is granted") {
		t.Errorf("want the limit stated, got %q", checks[0].Detail)
	}
}

// The gap that prompted this check: a bundle from a JVM developer's machine
// recorded no Java at all, because the runtime scan only knew version managers.
// Now that the JDKs are recorded, the ones that did not survive the migration
// have to be named.
func TestJDKRecordedButNotInstalledIsReported(t *testing.T) {
	man := &bundle.Manifest{System: bundle.System{JDKs: []bundle.JDK{
		{Version: "99.0.1", Vendor: "Azul Systems, Inc.", Path: "/x"},
	}}}
	checks := problems(checkJDKs(t.TempDir(), man))
	if len(checks) != 1 {
		t.Fatalf("got %+v; want the missing JDK reported", checks)
	}
	if !strings.Contains(checks[0].Detail, "99") {
		t.Errorf("detail does not name the version: %q", checks[0].Detail)
	}
	if checks[0].Fix == "" {
		t.Error("no fix offered for a JDK Homebrew can install")
	}
}

// The shell configuration is the other half, and it fails independently: a
// machine can have every JDK the bundle recorded and still hold an alias asking
// for one it does not. java_home answers that with the default JDK and exits
// zero, so the alias reports success and hands over the wrong Java.
func TestShellConfigAskingForAnAbsentJavaIsReported(t *testing.T) {
	home := t.TempDir()
	writeFile(t, home, ".zshrc", "alias j99=\"export JAVA_HOME=$(/usr/libexec/java_home -v 99.0.1)\"\n")

	checks := problems(checkJDKs(home, &bundle.Manifest{}))
	if len(checks) != 1 {
		t.Fatalf("got %+v; want the unresolvable alias reported", checks)
	}
	if !strings.Contains(checks[0].Detail, "99.0.1") {
		t.Errorf("detail does not name the version the alias asks for: %q", checks[0].Detail)
	}
	if !strings.Contains(checks[0].Detail, "default") {
		t.Errorf("detail does not explain the silent fallback: %q", checks[0].Detail)
	}
}

// A machine with no Java anywhere, and a bundle that records none, must not
// invent a problem to report.
func TestNoJavaAnywhereReportsNothing(t *testing.T) {
	if checks := checkJDKs(t.TempDir(), &bundle.Manifest{}); len(checks) != 0 {
		t.Errorf("got %+v; want nothing said about Java", checks)
	}
}
