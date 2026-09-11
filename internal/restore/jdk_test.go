package restore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// The versions a machine needs are written down in its shell configuration, one
// per alias, and that file was carried into the bundle whole while nothing read
// it. These five lines are the ones from the migration that found the gap.
func TestJavaVersionsWantedReadsTheAliases(t *testing.T) {
	home := t.TempDir()
	zshrc := "alias j17=\"export JAVA_HOME=`/usr/libexec/java_home -v 17.0.6`; java -version\"\n" +
		"alias j11=\"export JAVA_HOME=`/usr/libexec/java_home -v 11.0.17`; java -version\"\n" +
		"alias j8=\"export JAVA_HOME=`/usr/libexec/java_home -v 1.8.0_271`; java -version\"\n" +
		"alias openj11=\"export JAVA_HOME=`/usr/libexec/java_home -v 11.0.2`; java -version\"\n" +
		"alias j11z=\"export JAVA_HOME=`/usr/libexec/java_home -v 11.0.21`; java -version\"\n"
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte(zshrc), 0o600); err != nil {
		t.Fatal(err)
	}

	got := JavaVersionsWanted(home)
	want := []string{"1.8.0_271", "11.0.17", "11.0.2", "11.0.21", "17.0.6"}
	if len(got) != len(want) {
		t.Fatalf("found %v; want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("found %v; want %v", got, want)
			break
		}
	}
}

// Aliases live in Oh My Zsh's custom directory as often as in .zshrc, and the
// modern form uses $( ) rather than backticks.
func TestJavaVersionsWantedReadsOhMyZshAndModernSyntax(t *testing.T) {
	home := t.TempDir()
	custom := filepath.Join(home, ".oh-my-zsh", "custom")
	if err := os.MkdirAll(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "alias j21='export JAVA_HOME=$(/usr/libexec/java_home -v 21); java -version'\n" +
		"export JAVA_HOME=$(/usr/libexec/java_home --version \"17.0.9\")\n"
	if err := os.WriteFile(filepath.Join(custom, "java.zsh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(JavaVersionsWanted(home), ",")
	if got != "17.0.9,21" {
		t.Errorf("found %q; want the two versions named in custom/java.zsh", got)
	}
}

// A machine that collected three builds of Java 11 over the years does not need
// three of them back. Installing all three leaves java_home choosing between
// them, which is the ambiguity the aliases existed to avoid.
func TestMissingJDKsCollapsesOneCommandPerMajor(t *testing.T) {
	jdks := []bundle.JDK{
		{Version: "11.0.17", Vendor: "Oracle Corporation", Name: "Java SE 11.0.17"},
		{Version: "11.0.2", Vendor: "Oracle Corporation", Name: "OpenJDK 11.0.2"},
		{Version: "11.0.21", Vendor: "Azul Systems, Inc.", Name: "Zulu 11.68.17"},
		{Version: "17.0.6", Vendor: "Oracle Corporation", Name: "Java SE 17.0.6"},
	}
	gaps := missingJDKs(jdks, func(string) bool { return false })
	if len(gaps) != 2 {
		t.Fatalf("got %d command(s), want one per major: %+v", len(gaps), gaps)
	}
	if gaps[0].Major != "11" || gaps[1].Major != "17" {
		t.Errorf("majors = %q, %q; want 11 before 17", gaps[0].Major, gaps[1].Major)
	}
	// Azul is the one vendor of the three elevens that Homebrew can supply, so
	// it wins over substituting Temurin for an Oracle build.
	if gaps[0].Command != "brew install --cask zulu@11" || !gaps[0].SameVendor {
		t.Errorf("Java 11 = %+v; want the Azul cask, marked as the original vendor", gaps[0])
	}
}

// A major that is already here is not reinstalled.
func TestMissingJDKsSkipsWhatIsInstalled(t *testing.T) {
	jdks := []bundle.JDK{{Version: "17.0.6", Vendor: "Oracle Corporation"}}
	if gaps := missingJDKs(jdks, func(string) bool { return true }); len(gaps) != 0 {
		t.Errorf("got %+v; want nothing to install", gaps)
	}
}

// Oracle publishes no free cask for 8 or 11, so those have to be substituted.
// The substitution is reported rather than hidden: a developer who needs the
// Oracle build specifically has to be able to see that they did not get it.
func TestOracleElevenIsSubstitutedVisibly(t *testing.T) {
	gaps := missingJDKs(
		[]bundle.JDK{{Version: "11.0.17", Vendor: "Oracle Corporation", Name: "Java SE 11.0.17"}},
		func(string) bool { return false })
	if len(gaps) != 1 {
		t.Fatalf("got %+v", gaps)
	}
	if gaps[0].Command != "brew install --cask temurin@11" {
		t.Errorf("command = %q; want the Temurin cask", gaps[0].Command)
	}
	if gaps[0].SameVendor {
		t.Error("a Temurin cask standing in for an Oracle build is marked as the same vendor")
	}
}

// Without -F, java_home answers a version it does not have with the default JDK
// and exits zero. A check written the obvious way therefore passes on a machine
// with no matching JDK at all.
func TestJDKInstalledRejectsAVersionThatIsNotHere(t *testing.T) {
	if JDKInstalled("99") {
		t.Error("JDKInstalled(99) is true; java_home's fallback is being taken for a match")
	}
}

func TestRestoreJDKsNamesWhatIsMissingAndHowToGetIt(t *testing.T) {
	p := &Plan{Manifest: &bundle.Manifest{System: bundle.System{JDKs: []bundle.JDK{
		{Version: "99.0.1", Vendor: "Azul Systems, Inc.", Arch: "x86_64", Path: "/x"},
	}}}}
	var out bytes.Buffer
	p.RestoreJDKs(&out, false)

	got := out.String()
	if !strings.Contains(got, "99.0.1") || !strings.Contains(got, "Azul") {
		t.Errorf("the recorded JDK is not named:\n%s", got)
	}
	if !strings.Contains(got, "Intel build") {
		t.Errorf("an x86_64 build is not flagged as one:\n%s", got)
	}
}

// Nothing is printed for a bundle from a machine with no Java on it.
func TestRestoreJDKsSaysNothingWhenThereAreNone(t *testing.T) {
	p := &Plan{Manifest: &bundle.Manifest{}}
	var out bytes.Buffer
	p.RestoreJDKs(&out, false)
	if out.Len() != 0 {
		t.Errorf("printed a Java section for a bundle with no JDKs:\n%s", out.String())
	}
}

// Some majors have no cask at all. Dropping those from the report would put
// macstash back where it started: silent about a runtime the old machine had,
// because it had nothing tidy to say about it.
func TestAJDKWithNoCaskIsStillReported(t *testing.T) {
	gaps := missingJDKs(
		[]bundle.JDK{{Version: "13.0.2", Vendor: "Oracle Corporation"}},
		func(string) bool { return false })
	if len(gaps) != 1 {
		t.Fatalf("got %+v; want the JDK reported even with no command for it", gaps)
	}
	if gaps[0].Command != "" {
		t.Errorf("command = %q; Homebrew has no cask for Java 13", gaps[0].Command)
	}
	if !strings.Contains(gaps[0].Instruction(), "by hand") {
		t.Errorf("instruction = %q; it should say this one is a manual download", gaps[0].Instruction())
	}
}
