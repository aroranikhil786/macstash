package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeJDK builds the parts of a JDK bundle that identify it: the release file
// macOS and every build tool read, and the compiler that distinguishes a JDK
// from a runtime.
func fakeJDK(t *testing.T, dir, version, vendor string, withCompiler bool) {
	t.Helper()
	home := filepath.Join(dir, "Contents", "Home")
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	release := "IMPLEMENTOR=\"" + vendor + "\"\nJAVA_VERSION=\"" + version + "\"\nOS_ARCH=\"aarch64\"\n"
	if err := os.WriteFile(filepath.Join(home, "release"), []byte(release), 0o600); err != nil {
		t.Fatal(err)
	}
	if withCompiler {
		if err := os.WriteFile(filepath.Join(home, "bin", "javac"), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

// The JDKs a JetBrains IDE downloads land in the home directory rather than the
// system one, and no shell has ever heard of them. They are still the JDK a
// project builds with.
func TestJDKsAreFoundInTheHomeDirectory(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Java", "JavaVirtualMachines")
	fakeJDK(t, filepath.Join(dir, "zulu-11.jdk"), "11.0.21", "Azul Systems, Inc.", true)

	var found bool
	for _, j := range fromJVMDirs(home) {
		if j.Version == "11.0.21" && j.Vendor == "Azul Systems, Inc." {
			found = true
		}
	}
	if !found {
		t.Errorf("a JDK under ~/Library/Java/JavaVirtualMachines was not found: %+v", fromJVMDirs(home))
	}
}

// macOS lists the legacy applet plugin alongside real JDKs. It has no compiler,
// nothing builds against it, and telling someone to reinstall it sends them
// after a download that has not existed for years.
func TestARuntimeWithoutACompilerIsNotAJDK(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Java", "JavaVirtualMachines")
	fakeJDK(t, filepath.Join(dir, "plugin-8.jdk"), "1.8.0_271", "Oracle Corporation", false)

	for _, j := range fromJVMDirs(home) {
		if j.Version == "1.8.0_271" {
			t.Errorf("a runtime with no javac was recorded as a JDK: %+v", j)
		}
	}
}

// Majors have to sort as numbers. As strings, 8 comes after 11.
func TestJDKsSortByMajorNumerically(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Java", "JavaVirtualMachines")
	fakeJDK(t, filepath.Join(dir, "a-17.jdk"), "17.0.6", "Oracle Corporation", true)
	fakeJDK(t, filepath.Join(dir, "b-8.jdk"), "1.8.0_271", "Oracle Corporation", true)
	fakeJDK(t, filepath.Join(dir, "c-11.jdk"), "11.0.21", "Azul Systems, Inc.", true)

	// The system directory holds whatever this machine really has; only the
	// fixtures are being ordered here.
	var majors []string
	for _, j := range scanJDKs(home) {
		if strings.HasPrefix(j.Path, home) {
			majors = append(majors, j.Major())
		}
	}
	want := []string{"8", "11", "17"}
	if len(majors) != len(want) {
		t.Fatalf("majors = %v, want %v", majors, want)
	}
	for i := range want {
		if majors[i] != want[i] {
			t.Fatalf("majors = %v, want %v", majors, want)
		}
	}
}

// A JetBrains IDE writes its settings under a directory named for its release,
// so naming that directory literally means the entry stops working at the next
// version. The wildcard is what keeps the entry correct over time.
func TestCatalogPathsExpandWildcards(t *testing.T) {
	home := t.TempDir()
	for _, ide := range []string{"IntelliJIdea2026.2", "GoLand2025.3"} {
		dir := filepath.Join(home, "Library", "Application Support", "JetBrains", ide, "options")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "jdk.table.xml"), []byte("<application/>\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := matchPaths(home, "~/Library/Application Support/JetBrains/*/options/jdk.table.xml")
	if len(got) != 2 {
		t.Fatalf("matched %v; want both IDE directories", got)
	}
	// Sorted, so a bundle built twice from the same machine lists them the same
	// way and a diff of two manifests shows only real changes.
	if !strings.Contains(got[0], "GoLand") || !strings.Contains(got[1], "IntelliJ") {
		t.Errorf("matches are not sorted: %v", got)
	}
}

// A path with no wildcard must not go through the globber. Glob treats brackets
// as a character class, so a real filename containing one would stop matching
// itself.
func TestCatalogPathsWithoutWildcardsAreLiteral(t *testing.T) {
	home := t.TempDir()
	got := matchPaths(home, "~/.zshrc")
	if len(got) != 1 || got[0] != filepath.Join(home, ".zshrc") {
		t.Errorf("matchPaths(~/.zshrc) = %v; want the literal path whether or not it exists", got)
	}
}
