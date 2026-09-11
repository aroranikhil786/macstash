package bundle

import "testing"

// Java 8 reports itself as 1.8.0_271, and everything that consumes a major
// version — java_home, Homebrew casks, the aliases people write — calls it 8.
func TestJDKMajor(t *testing.T) {
	cases := map[string]string{
		"1.8.0_271": "8",
		"11.0.2":    "11",
		"11.0.21":   "11",
		"17.0.6":    "17",
		"21":        "21",
		"1.7.0_80":  "7",
	}
	for version, want := range cases {
		if got := (JDK{Version: version}).Major(); got != want {
			t.Errorf("JDK{%q}.Major() = %q, want %q", version, got, want)
		}
	}
}

func TestJDKInstallCommand(t *testing.T) {
	cases := []struct {
		name       string
		jdk        JDK
		wantCmd    string
		wantVendor bool
	}{
		{"azul keeps its own cask",
			JDK{Version: "11.0.21", Vendor: "Azul Systems, Inc.", Name: "Zulu 11.68.17"},
			"brew install --cask zulu@11", true},
		{"oracle 17 has a cask",
			JDK{Version: "17.0.6", Vendor: "Oracle Corporation", Name: "Java SE 17.0.6"},
			"brew install --cask oracle-jdk@17", true},
		// Oracle publishes casks from 17 up. Older majors are behind a
		// subscription, so a free build of the same major is the only offer
		// that can actually be carried out.
		{"oracle 11 falls back to temurin",
			JDK{Version: "11.0.17", Vendor: "Oracle Corporation", Name: "Java SE 11.0.17"},
			"brew install --cask temurin@11", false},
		{"oracle 8 falls back to temurin",
			JDK{Version: "1.8.0_271", Vendor: "Oracle Corporation", Name: "Java SE 8"},
			"brew install --cask temurin@8", false},
		// An OpenJDK reference build is Oracle-branded but is not the Oracle JDK.
		{"an openjdk reference build is not the oracle cask",
			JDK{Version: "11.0.2", Vendor: "Oracle Corporation", Name: "OpenJDK 11.0.2"},
			"brew install --cask temurin@11", false},
		{"amazon keeps corretto",
			JDK{Version: "17.0.9", Vendor: "Amazon.com Inc.", Name: "Amazon Corretto 17"},
			"brew install --cask corretto@17", true},
		{"an unknown vendor still gets a working command",
			JDK{Version: "21.0.1", Vendor: "Some Other Build"},
			"brew install --cask temurin@21", false},
		// A major nobody publishes a cask for must produce no command at all,
		// because a printed command that fails is worse than none.
		{"a major with no cask produces nothing",
			JDK{Version: "13.0.2", Vendor: "Oracle Corporation"},
			"", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, sameVendor := c.jdk.InstallCommand()
			if cmd != c.wantCmd {
				t.Errorf("command = %q, want %q", cmd, c.wantCmd)
			}
			if sameVendor != c.wantVendor {
				t.Errorf("sameVendor = %v, want %v", sameVendor, c.wantVendor)
			}
		})
	}
}
