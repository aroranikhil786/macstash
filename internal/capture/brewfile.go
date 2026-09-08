package capture

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// ErrNoBrew is returned when Homebrew is not installed.
var ErrNoBrew = errors.New("homebrew is not installed")

// brewEnv is the environment every brew invocation runs with.
//
// HOMEBREW_NO_AUTO_UPDATE stops brew reaching for the network before doing local
// work. HOMEBREW_NO_INSTALL_FROM_API is conspicuously absent and must stay that
// way: setting it makes brew fall back to a local homebrew-core clone, and when
// that clone is missing — as it is on any machine that has only ever used the
// API — brew tries to git clone it, fails inside the sandbox, and still exits 0
// having printed a Brewfile that contains taps and nothing else.
func brewEnv() []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOMEBREW_NO_INSTALL_FROM_API=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out,
		"HOMEBREW_NO_AUTO_UPDATE=1",
		"HOMEBREW_NO_ANALYTICS=1",
		"HOMEBREW_NO_ENV_HINTS=1",
	)
}

// BrewResult is a validated Brewfile.
type BrewResult struct {
	Content []byte
	Counts  bundle.Brew
}

// DumpBrewfile produces a Brewfile and then proves it is complete.
//
// The proof is the important half. brew bundle dump can fail to enumerate
// formulae and still exit 0, leaving a Brewfile with only tap lines in it. For a
// migration tool that is the worst available failure: nothing looks wrong, the
// restore appears to succeed, and the user spends the following month finding
// missing tools one at a time — which is precisely the experience this project
// exists to abolish. So the counts are cross-checked against brew's own
// inventory, and a mismatch aborts the capture instead of shipping a truncated
// list.
func DumpBrewfile() (*BrewResult, error) {
	if !commandExists("brew") {
		return nil, ErrNoBrew
	}

	content, err := runBrew("bundle", "dump", "--file=-", "--formula", "--cask", "--tap")
	if err != nil {
		return nil, fmt.Errorf("brew bundle dump: %w", err)
	}

	got := bundle.Brew{
		Formulae:  countPrefix(content, "brew "),
		Casks:     countPrefix(content, "cask "),
		Taps:      countPrefix(content, "tap "),
		Packages:  namesWithPrefix(content, "brew "),
		Casknames: namesWithPrefix(content, "cask "),
	}

	// brew bundle dump lists formulae that were installed on request, not the
	// full dependency closure, so that is what it has to be compared against.
	// brew leaves is the tempting comparator and the wrong one: it drops any
	// formula that something else depends on, even when the user asked for it.
	want := bundle.Brew{}
	if want.Formulae, err = countLines("list", "--formula", "--installed-on-request"); err != nil {
		return nil, err
	}
	if want.Casks, err = countLines("list", "--cask"); err != nil {
		return nil, err
	}
	if want.Taps, err = countLines("tap"); err != nil {
		return nil, err
	}

	if err := ValidateCounts(got, want); err != nil {
		return nil, err
	}

	return &BrewResult{Content: content, Counts: got}, nil
}

// ValidateCounts compares what brew bundle dump wrote against what brew says is
// installed.
//
// This is the guard that makes the Brewfile trustworthy. brew bundle dump can
// fail to enumerate packages and still exit 0 — the observed failure is a
// Brewfile containing four tap lines and nothing else, on a machine with
// fourteen formulae installed. Restoring that bundle looks like a success and
// quietly loses almost everything, which is the single worst outcome available
// to a migration tool.
func ValidateCounts(got, want bundle.Brew) error {
	if got.Formulae == want.Formulae && got.Casks == want.Casks && got.Taps == want.Taps {
		return nil
	}
	return fmt.Errorf(
		"brew bundle dump produced an incomplete Brewfile and cannot be trusted:\n"+
			"  formulae: dumped %d, installed %d\n"+
			"  casks:    dumped %d, installed %d\n"+
			"  taps:     dumped %d, installed %d\n\n"+
			"Capture stopped rather than write a partial Brewfile, because a truncated one\n"+
			"restores without complaint and loses packages silently. Check that\n"+
			"HOMEBREW_NO_INSTALL_FROM_API is unset, then try again.",
		got.Formulae, want.Formulae, got.Casks, want.Casks, got.Taps, want.Taps)
}

func runBrew(args ...string) ([]byte, error) {
	cmd := exec.Command("brew", args...)
	cmd.Env = brewEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func countLines(args ...string) (int, error) {
	out, err := runBrew(args...)
	if err != nil {
		return 0, fmt.Errorf("brew %s: %w", strings.Join(args, " "), err)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n, nil
}

// namesWithPrefix extracts the quoted names from Brewfile lines.
func namesWithPrefix(content []byte, prefix string) []string {
	var out []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"`)
		if i := strings.Index(rest, `"`); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			out = append(out, rest)
		}
	}
	return out
}

func countPrefix(content []byte, prefix string) int {
	n := 0
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			n++
		}
	}
	return n
}

// formatCounts renders the Brewfile summary for the capture report.
func formatCounts(b bundle.Brew) string {
	return strconv.Itoa(b.Formulae) + " formulae, " +
		strconv.Itoa(b.Casks) + " casks, " +
		strconv.Itoa(b.Taps) + " taps"
}

// brewLine matches one Brewfile declaration: brew "name", cask "name", tap "x/y".
var brewLine = regexp.MustCompile(`^\s*(brew|cask|tap)\s+"([^"]+)"`)

// parseBrewfile returns the formula and cask names a Brewfile declares.
func parseBrewfile(content []byte) (formulae, casks []string) {
	for _, line := range strings.Split(string(content), "\n") {
		m := brewLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		switch m[1] {
		case "brew":
			formulae = append(formulae, m[2])
		case "cask":
			casks = append(casks, m[2])
		}
	}
	return formulae, casks
}

// filterBrewfile rewrites a Brewfile keeping only the selected entries, and
// recomputes the counts so the cross-check still describes the file.
//
// The counts matter: they are what a later restore and `inspect` compare
// against, and leaving them describing the pre-filter file would reintroduce
// exactly the silent mismatch the dump validation exists to catch.
func filterBrewfile(content []byte, formulae map[string]bool, haveFormulae bool,
	casks map[string]bool, haveCasks bool) ([]byte, bundle.Brew) {

	var out []string
	var counts bundle.Brew
	for _, line := range strings.Split(string(content), "\n") {
		m := brewLine.FindStringSubmatch(line)
		if m == nil {
			out = append(out, line)
			continue
		}
		switch m[1] {
		case "brew":
			if haveFormulae && !formulae[m[2]] {
				continue
			}
			counts.Formulae++
		case "cask":
			if haveCasks && !casks[m[2]] {
				continue
			}
			counts.Casks++
		case "tap":
			counts.Taps++
		}
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n")), counts
}
