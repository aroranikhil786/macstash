package restore

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// Absent names, so the presence check cannot pass by accident on whatever
// machine runs the tests.
const (
	absentWithCask = "macstash-test-absent-cask-app"
	absentNoCask   = "macstash-test-absent-manual-app"
)

func TestPlanAppsSeparatesInstallableFromUnmanaged(t *testing.T) {
	apps := []bundle.App{
		{Name: absentWithCask, Source: "manual", CaskToken: "some-token"},
		{Name: absentNoCask, Source: "manual"},
		{Name: "ripgrep", Source: "homebrew"},
		{Name: "Safari", Source: "system"},
	}

	installable, unmanaged := PlanApps(apps)

	if len(installable) != 1 || installable[0].Token != "some-token" {
		t.Fatalf("installable = %+v, want the one with a cask token", installable)
	}
	if len(unmanaged) != 1 || unmanaged[0] != absentNoCask {
		t.Fatalf("unmanaged = %v, want the one without", unmanaged)
	}
}

// Apps Homebrew or macOS already handle must not appear at all — restore would
// otherwise reinstall over the top of them.
func TestPlanAppsIgnoresHomebrewAndSystemApps(t *testing.T) {
	apps := []bundle.App{
		{Name: "ripgrep", Source: "homebrew", CaskToken: "ripgrep"},
		{Name: "Safari", Source: "system"},
	}

	installable, unmanaged := PlanApps(apps)

	if len(installable) != 0 || len(unmanaged) != 0 {
		t.Fatalf("want nothing to do, got installable=%+v unmanaged=%v", installable, unmanaged)
	}
}

// A dry run must not install anything, and must say so.
func TestInstallAppsPlanWritesNothingAndSaysHow(t *testing.T) {
	var buf bytes.Buffer
	apps := []bundle.App{{Name: absentWithCask, Source: "manual", CaskToken: "some-token"}}

	if err := InstallApps(apps, false, &buf); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "Nothing was installed") {
		t.Errorf("a dry run must state that nothing happened, got:\n%s", out)
	}
	if !strings.Contains(out, "--install-apps") {
		t.Errorf("the dry run should name the flag that applies it, got:\n%s", out)
	}
	// The exact command has to be printed: someone who does not want the flag
	// should still be able to copy the line and run it.
	if !strings.Contains(out, "brew install --cask some-token") {
		t.Errorf("want a runnable command, got:\n%s", out)
	}
}

// The apps with no cask are the only ones that genuinely need a human, so they
// have to be called out separately rather than buried in one long list.
func TestInstallAppsPlanReportsUnmanagedAppsSeparately(t *testing.T) {
	var buf bytes.Buffer
	apps := []bundle.App{
		{Name: absentWithCask, Source: "manual", CaskToken: "some-token"},
		{Name: absentNoCask, Source: "manual"},
	}

	if err := InstallApps(apps, false, &buf); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "no Homebrew cask") {
		t.Errorf("unmanaged apps need their own explanation, got:\n%s", out)
	}
	if !strings.Contains(out, absentNoCask) {
		t.Errorf("the unmanaged app should be named, got:\n%s", out)
	}
}

func TestInstallAppsWithNothingToDoSaysSo(t *testing.T) {
	var buf bytes.Buffer

	if err := InstallApps(nil, false, &buf); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(buf.String(), "No applications") {
		t.Errorf("want an explicit empty-state message, got:\n%s", buf.String())
	}
}

// Apps only in the manifest as homebrew/system entries mean there is genuinely
// nothing to do, and the apply path must not claim otherwise.
func TestInstallAppsApplyWithNothingMissingInstallsNothing(t *testing.T) {
	var buf bytes.Buffer
	apps := []bundle.App{{Name: "ripgrep", Source: "homebrew", CaskToken: "ripgrep"}}

	if err := InstallApps(apps, true, &buf); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if strings.Contains(out, "Installing") {
		t.Errorf("nothing should have been installed, got:\n%s", out)
	}
}

func TestFirstMeaningfulLinePrefersTheError(t *testing.T) {
	out := "==> Downloading something\n==> Verifying\nError: Cask 'x' is unavailable\n"

	if got := firstMeaningfulLine(out); !strings.HasPrefix(got, "Error:") {
		t.Errorf("firstMeaningfulLine = %q, want the error line", got)
	}
}

func TestFirstMeaningfulLineFallsBackToTheFirstLine(t *testing.T) {
	if got := firstMeaningfulLine("\n\n  something happened  \n"); got != "something happened" {
		t.Errorf("firstMeaningfulLine = %q", got)
	}
}

// Empty output must still produce a printable line, or the failure renders as a
// blank indented row and reads like a display bug.
func TestFirstMeaningfulLineHandlesEmptyOutput(t *testing.T) {
	if got := firstMeaningfulLine(""); got == "" {
		t.Error("want a non-empty explanation even with no brew output")
	}
}

// Exercises the real `brew install --cask` invocation without installing
// anything, by using a token no cask has. It proves the command is built and
// run, that a failure is caught rather than aborting, and that brew's reason
// reaches the user.
func TestInstallAppsApplyReportsAFailingCaskWithoutAborting(t *testing.T) {
	if _, err := exec.LookPath("brew"); err != nil {
		t.Skip("brew is not installed")
	}
	var buf bytes.Buffer
	apps := []bundle.App{
		{Name: absentWithCask, Source: "manual", CaskToken: "macstash-no-such-cask-exists"},
	}

	if err := InstallApps(apps, true, &buf); err != nil {
		t.Fatalf("a failing cask must not abort the restore: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "FAILED") {
		t.Errorf("want the failure reported, got:\n%s", out)
	}
	if !strings.Contains(out, "failed 1") {
		t.Errorf("want it counted, got:\n%s", out)
	}
	// A bare count with no reason leaves the user with nothing to act on.
	if !strings.Contains(strings.ToLower(out), "cask") {
		t.Errorf("brew's explanation should reach the user, got:\n%s", out)
	}
}
