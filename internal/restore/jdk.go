package restore

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

const javaHome = "/usr/libexec/java_home"

// JDKInstalled reports whether a Java runtime matching this version is here.
//
// The -F flag is not optional. Without it java_home answers a query it cannot
// satisfy by printing the default JDK and exiting zero, so asking for a version
// that is not installed returns a path that works, for the wrong Java. That is
// the failure this whole check exists to catch, and the naive form of the check
// walks straight into it.
func JDKInstalled(version string) bool {
	if _, err := os.Stat(javaHome); err != nil {
		return false
	}
	return exec.Command(javaHome, "-F", "-v", version).Run() == nil
}

// MissingJDKs returns one install command per major version that is recorded in
// the bundle and absent here.
//
// One per major, not one per recorded JDK. A machine can easily carry three
// builds of Java 11 from three vendors, collected over years; reinstalling all
// three leaves java_home choosing between them arbitrarily. Where a major had a
// vendor Homebrew can supply, that vendor wins, so the substitution only happens
// when there is no alternative.
func MissingJDKs(jdks []bundle.JDK) []JDKGap {
	return missingJDKs(jdks, JDKInstalled)
}

// missingJDKs takes the presence test as an argument so the grouping can be
// tested without depending on which JDKs the machine running the tests has.
func missingJDKs(jdks []bundle.JDK, installed func(string) bool) []JDKGap {
	byMajor := map[string]JDKGap{}
	var majors []string

	for _, j := range jdks {
		major := j.Major()
		if major == "" || installed(major) {
			continue
		}
		// A JDK with no cask is still reported, with no command. Dropping it
		// would put macstash back where it started: silent about a runtime the
		// old machine had, because it had nothing tidy to say.
		cmd, same := j.InstallCommand()
		existing, seen := byMajor[major]
		if !seen {
			majors = append(majors, major)
		}
		better := !seen ||
			(cmd != "" && existing.Command == "") ||
			(cmd != "" && same && !existing.SameVendor)
		if better {
			byMajor[major] = JDKGap{Major: major, Vendor: j.Vendor, Command: cmd, SameVendor: same}
		}
	}

	sort.Slice(majors, func(i, k int) bool {
		return majorNumber(majors[i]) < majorNumber(majors[k])
	})
	out := make([]JDKGap, 0, len(majors))
	for _, m := range majors {
		out = append(out, byMajor[m])
	}
	return out
}

// JDKGap is a major version the bundle recorded and this machine lacks.
type JDKGap struct {
	Major  string
	Vendor string
	// Command installs an equivalent JDK. SameVendor says whether it is the
	// vendor the old machine had, so a substitution is never made silently.
	Command    string
	SameVendor bool
}

// Instruction is what to tell a person to do about this gap, which is a command
// when Homebrew has one and a sentence when it does not.
func (g JDKGap) Instruction() string {
	if g.Command != "" {
		return g.Command
	}
	vendor := g.Vendor
	if vendor == "" {
		vendor = "the vendor"
	}
	return "download a Java " + g.Major + " build by hand; Homebrew has no cask for it (" + vendor + ")"
}

// javaHomeQuery matches a java_home version request in a shell file. Both the
// short and long forms are accepted, and the version is allowed to be quoted,
// because all of those appear in shell configuration written by hand.
var javaHomeQuery = regexp.MustCompile(`java_home(?:\s+-{1,2}[A-Za-z]+)*\s+(?:-v|--version)\s+["']?([0-9][0-9._]*)`)

// shellConfigFiles are the files a person keeps aliases in.
var shellConfigFiles = []string{
	".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile",
}

// JavaVersionsWanted returns the Java versions the shell configuration asks
// java_home for.
//
// This is the check that would have caught a missing JDK on day one. The old
// machine's shell file names every version that machine needed, one per alias,
// and that file is carried into the bundle whole. Nothing read it. Reading it
// turns a silent gap into a list of exactly which JDKs to install.
func JavaVersionsWanted(home string) []string {
	files := make([]string, 0, len(shellConfigFiles))
	for _, name := range shellConfigFiles {
		files = append(files, filepath.Join(home, name))
	}
	// Oh My Zsh users keep aliases in custom/*.zsh rather than .zshrc, and that
	// directory is one macstash captures, so the versions are just as likely to
	// land there.
	if custom, err := filepath.Glob(filepath.Join(home, ".oh-my-zsh", "custom", "*.zsh")); err == nil {
		files = append(files, custom...)
	}

	seen := map[string]bool{}
	var out []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, m := range javaHomeQuery.FindAllStringSubmatch(string(data), -1) {
			v := m[1]
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// RestoreJDKs reports the Java runtimes the old machine had and puts back the
// majors this one is missing.
func (p *Plan) RestoreJDKs(out io.Writer, install bool) {
	jdks := p.Manifest.System.JDKs
	if len(jdks) == 0 {
		return
	}
	fmt.Fprintln(out, "\nJava runtimes recorded on the old machine:")

	var intel int
	for _, j := range jdks {
		vendor := j.Vendor
		if vendor == "" {
			vendor = "unknown vendor"
		}
		if j.Arch == "x86_64" {
			intel++
			vendor += ", Intel build"
		}
		state := "installed here"
		if !JDKInstalled(j.Version) {
			state = "missing"
		}
		fmt.Fprintf(out, "  %-12s %-34s %s\n", j.Version, vendor, state)
	}

	if intel > 0 && runtime.GOARCH == "arm64" {
		fmt.Fprintln(out, "\n  Some of those are Intel builds, which ran under Rosetta. That is usually")
		fmt.Fprintln(out, "  a leftover from an older machine rather than a requirement, so the")
		fmt.Fprintln(out, "  commands below install native builds instead.")
	}

	missing := MissingJDKs(jdks)
	if len(missing) == 0 {
		fmt.Fprintln(out, "\n  Every major version recorded is already installed here.")
		return
	}

	if !install {
		fmt.Fprintln(out, "\n  Install the missing majors with:")
		for _, gap := range missing {
			fmt.Fprintf(out, "    %s\n", gap.Instruction())
		}
		fmt.Fprintln(out, "  Or pass --install-apps to have this restore run them.")
		return
	}
	if !commandAvailable("brew") {
		fmt.Fprintln(out, "\n  Homebrew is not installed, so these cannot be installed from here:")
		for _, gap := range missing {
			fmt.Fprintf(out, "    %s\n", gap.Instruction())
		}
		return
	}
	for _, gap := range missing {
		if gap.Command == "" {
			fmt.Fprintf(out, "\n  %s\n", gap.Instruction())
			continue
		}
		fmt.Fprintf(out, "\n  %s\n", gap.Command)
		args := strings.Fields(gap.Command)
		c := exec.Command(args[0], args[1:]...)
		c.Stdout, c.Stderr = out, out
		if err := c.Run(); err != nil {
			fmt.Fprintf(out, "  failed: %v\n", err)
		}
	}
}

// majorNumber orders majors numerically, so 8 comes before 11.
func majorNumber(major string) int {
	n := 0
	for _, c := range major {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
