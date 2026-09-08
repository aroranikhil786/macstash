package capture

import (
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

func names(apps []bundle.App) []bundle.App { return apps }

// The apps seen on a real managed Mac. The original check matched only the
// names of the MDM agents themselves, so five pieces of employer-deployed
// security software were listed under "reinstall these by hand".
func TestEnterpriseAgentsCatchesEmployerDeployedSoftware(t *testing.T) {
	apps := names([]bundle.App{
		{Name: "GlobalProtect", Source: SourceManual},
		{Name: "Microsoft Defender", Source: SourceManual},
		{Name: "Metallic Edge Monitor", Source: SourceManual},
		{Name: "Metallic Migration Assistant", Source: SourceManual},
		{Name: "Metallic Process Manager", Source: SourceManual},
		{Name: "Slack", Source: SourceManual},
		{Name: "IntelliJ IDEA", Source: SourceManual},
	})

	got := EnterpriseAgents(apps)

	if len(got) != 5 {
		t.Fatalf("want the 5 employer agents, got %d: %v", len(got), got)
	}
	for _, want := range []string{"GlobalProtect", "Microsoft Defender", "Metallic Edge Monitor"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s should be recognised as employer-deployed, got %v", want, got)
		}
	}
	// Ordinary software must not be swept up: telling someone not to reinstall
	// their editor would be worse than the bug being fixed.
	for _, g := range got {
		if g == "Slack" || g == "IntelliJ IDEA" {
			t.Errorf("%s is ordinary software and must not be flagged", g)
		}
	}
}

// The two lists answer different questions and must not collapse into one.
func TestManagedAppsAndEnterpriseAgentsAreDistinct(t *testing.T) {
	apps := []bundle.App{
		{Name: "Iru Self Service", Source: SourceManual},
		{Name: "Kandji Extension Manager", Source: SourceManual},
		{Name: "GlobalProtect", Source: SourceManual},
	}

	managed := ManagedApps(apps)
	agents := EnterpriseAgents(apps)

	if len(managed) != 2 {
		t.Errorf("MDM tooling = %v, want the two Kandji components", managed)
	}
	if len(agents) != 1 || agents[0] != "GlobalProtect" {
		t.Errorf("employer-deployed = %v, want GlobalProtect", agents)
	}
}

// An app matching two markers must be listed once.
func TestMatchMarkersDoesNotDuplicate(t *testing.T) {
	apps := []bundle.App{{Name: "Cisco Secure Endpoint AnyConnect", Source: SourceManual}}

	if got := EnterpriseAgents(apps); len(got) != 1 {
		t.Fatalf("want one entry, got %v", got)
	}
}

// App Store software is installed by the user, whatever it is called.
func TestMatchMarkersIgnoresAppStoreInstalls(t *testing.T) {
	apps := []bundle.App{{Name: "Microsoft Defender", Source: SourceAppStore}}

	if got := EnterpriseAgents(apps); len(got) != 0 {
		t.Fatalf("App Store installs are the user's own, got %v", got)
	}
}

func TestAdvisoryNamesTheSignalsRatherThanBeingVague(t *testing.T) {
	m := Management{Managed: true, Signals: []string{"enrolled in MDM", "Kandji"}}

	got := m.Advisory()

	for _, want := range []string{"enrolled in MDM", "Kandji", "your call"} {
		if !strings.Contains(got, want) {
			t.Errorf("advisory should mention %q, got:\n%s", want, got)
		}
	}
}

func TestAdvisoryIsSilentOnAnUnmanagedMac(t *testing.T) {
	if got := (Management{}).Advisory(); got != "" {
		t.Errorf("want no advisory, got %q", got)
	}
}
