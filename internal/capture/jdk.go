package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// javaHome is macOS's own index of installed JVMs. It is the only thing that
// knows about all of them, because a JDK registers itself by being a bundle in
// one of two directories rather than by putting anything on PATH.
const javaHome = "/usr/libexec/java_home"

// jvmDirs are the two locations macOS treats as JDK bundles. The second is
// where JetBrains IDEs put the JDKs they download for you, which is a common way
// to end up with a JDK that no shell has ever heard of.
var jvmDirs = []string{
	"/Library/Java/JavaVirtualMachines",
	"~/Library/Java/JavaVirtualMachines",
}

// scanJDKs records every Java runtime installed on this machine.
//
// This exists because the version-manager scan cannot see them. SDKMAN, pyenv,
// fnm and the rest own their runtimes; a JDK on macOS is an installer package
// that lands in a system directory, and a machine with five of them looks, to a
// scanner that only knows version managers, like a machine with no Java at all.
func scanJDKs(home string) []bundle.JDK {
	byPath := map[string]bundle.JDK{}
	for _, j := range fromJavaHome() {
		byPath[j.Path] = j
	}
	// Read the directories too. java_home is the better source, carrying vendor
	// and architecture, but it is one binary that can fail, and losing the whole
	// inventory to that is worse than reading a release file.
	for _, j := range fromJVMDirs(home) {
		if _, ok := byPath[j.Path]; !ok {
			byPath[j.Path] = j
		}
	}

	var out []bundle.JDK
	for _, j := range byPath {
		out = append(out, j)
	}
	sort.Slice(out, func(i, k int) bool {
		if a, b := out[i].Major(), out[k].Major(); a != b {
			return majorNumber(a) < majorNumber(b)
		}
		if out[i].Version != out[k].Version {
			return out[i].Version < out[k].Version
		}
		return out[i].Path < out[k].Path
	})
	return out
}

// fromJavaHome asks macOS for the JVM index and reads it as JSON.
//
// The -X form emits a property list rather than the human table -V prints, so
// vendor, architecture and version arrive as fields instead of something to
// pull back out of a formatted line.
func fromJavaHome() []bundle.JDK {
	if _, err := os.Stat(javaHome); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	plist, err := exec.CommandContext(ctx, javaHome, "-X").Output()
	if err != nil || len(plist) == 0 {
		return nil
	}
	conv := exec.CommandContext(ctx, "plutil", "-convert", "json", "-o", "-", "-")
	conv.Stdin = bytes.NewReader(plist)
	data, err := conv.Output()
	if err != nil {
		return nil
	}

	var raw []struct {
		Name    string `json:"JVMName"`
		Version string `json:"JVMVersion"`
		Vendor  string `json:"JVMVendor"`
		Arch    string `json:"JVMArch"`
		Home    string `json:"JVMHomePath"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var out []bundle.JDK
	for _, r := range raw {
		if r.Home == "" || !compiles(r.Home) {
			continue
		}
		out = append(out, bundle.JDK{
			Version: r.Version,
			Vendor:  r.Vendor,
			Name:    r.Name,
			Arch:    r.Arch,
			Path:    r.Home,
		})
	}
	return out
}

// fromJVMDirs reads the JDK bundles on disk directly.
func fromJVMDirs(home string) []bundle.JDK {
	var out []bundle.JDK
	for _, dir := range jvmDirs {
		entries, err := os.ReadDir(expand(home, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := filepath.Join(expand(home, dir), e.Name(), "Contents", "Home")
			if !compiles(path) {
				continue
			}
			version, vendor := readRelease(path)
			if version == "" {
				continue
			}
			out = append(out, bundle.JDK{Version: version, Vendor: vendor, Path: path})
		}
	}
	return out
}

// readRelease pulls the version and vendor out of the release file every JDK
// ships at the root of its home directory.
func readRelease(home string) (version, vendor string) {
	data, err := os.ReadFile(filepath.Join(home, "release"))
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, `"`)
		switch key {
		case "JAVA_VERSION":
			version = value
		case "IMPLEMENTOR":
			vendor = value
		}
	}
	return version, vendor
}

// compiles reports whether a Java home can build code as well as run it.
//
// macOS indexes the legacy applet plugin alongside real JDKs, and it shows up in
// java_home's list looking like a sixth Java install. It is a runtime with no
// compiler, nothing builds against it, and listing it as something to reinstall
// sends a user chasing a download that has not existed for years.
func compiles(home string) bool {
	info, err := os.Stat(filepath.Join(home, "bin", "javac"))
	return err == nil && !info.IsDir()
}

// majorNumber orders majors numerically, so 8 sorts before 11 rather than after
// it the way a string comparison would have them.
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
