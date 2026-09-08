package capture

import (
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// The exact shape of the real-world failure: brew emitted taps and nothing else,
// on a machine with fourteen formulae and a cask installed, and exited 0.
func TestValidateCountsCatchesSilentTruncation(t *testing.T) {
	truncated := bundle.Brew{Formulae: 0, Casks: 0, Taps: 4}
	actual := bundle.Brew{Formulae: 14, Casks: 1, Taps: 4}

	err := ValidateCounts(truncated, actual)
	if err == nil {
		t.Fatal("a Brewfile with no formulae was accepted on a machine with 14 installed")
	}
	for _, want := range []string{"dumped 0, installed 14", "incomplete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestValidateCountsAcceptsCompleteDump(t *testing.T) {
	counts := bundle.Brew{Formulae: 14, Casks: 1, Taps: 4}
	if err := ValidateCounts(counts, counts); err != nil {
		t.Fatalf("a complete Brewfile was rejected: %v", err)
	}
}

func TestValidateCountsCatchesMissingCasks(t *testing.T) {
	if err := ValidateCounts(
		bundle.Brew{Formulae: 14, Casks: 0, Taps: 4},
		bundle.Brew{Formulae: 14, Casks: 9, Taps: 4},
	); err == nil {
		t.Fatal("nine missing casks were accepted")
	}
}

// The poisoned variable must not reach brew, whatever the surrounding shell has
// set. This is the environment half of the same guarantee.
func TestBrewEnvStripsNoInstallFromAPI(t *testing.T) {
	t.Setenv("HOMEBREW_NO_INSTALL_FROM_API", "1")
	for _, kv := range brewEnv() {
		if strings.HasPrefix(kv, "HOMEBREW_NO_INSTALL_FROM_API=") {
			t.Fatalf("HOMEBREW_NO_INSTALL_FROM_API reached brew as %q; it forces a homebrew-core "+
				"clone that fails inside the capture sandbox and silently truncates the Brewfile", kv)
		}
	}
	var sawNoAutoUpdate bool
	for _, kv := range brewEnv() {
		if kv == "HOMEBREW_NO_AUTO_UPDATE=1" {
			sawNoAutoUpdate = true
		}
	}
	if !sawNoAutoUpdate {
		t.Error("HOMEBREW_NO_AUTO_UPDATE=1 was not set; brew would try to update over the network")
	}
}
