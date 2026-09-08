package capture

import (
	"os"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// Management describes whether a Mac appears to be under corporate control.
type Management struct {
	Managed bool
	// Signals are the specific things that were detected, so the advisory can be
	// concrete rather than ominous.
	Signals []string
}

// DetectManagement heuristically identifies a managed device.
//
// This exists for the employment risk rather than the security risk. On a
// company laptop, creating a portable archive of your configuration may breach
// acceptable-use policy or trip a DLP agent regardless of whether it contains
// anything sensitive — and a tool that earns someone an awkward conversation
// with their security team has failed them even though it never leaked a byte.
//
// It warns and proceeds. Refusing would be paternalistic: plenty of managed Macs
// have perfectly reasonable policies, and the person running this knows their
// employer's rules better than a heuristic does.
func DetectManagement() Management {
	var m Management

	if out, ok := run("profiles", "status", "-type", "enrollment"); ok {
		lower := strings.ToLower(out)
		if strings.Contains(lower, "mdm enrollment: yes") {
			m.Managed = true
			m.Signals = append(m.Signals, "enrolled in MDM")
		}
		if strings.Contains(lower, "dep") && !strings.Contains(lower, "dep: no") {
			m.Signals = append(m.Signals, "device enrolment programme")
		}
	}

	for path, label := range map[string]string{
		"/usr/local/bin/jamf":                 "Jamf",
		"/Library/Kandji":                     "Kandji",
		"/Library/Intune":                     "Microsoft Intune",
		"/Applications/Company Portal.app":    "Intune Company Portal",
		"/Library/Application Support/Mosyle": "Mosyle",
		"/usr/local/jamf":                     "Jamf",
		"/Library/Application Support/Addigy": "Addigy",
		"/Applications/Self Service.app":      "Jamf Self Service",
	} {
		if _, err := os.Stat(path); err == nil {
			m.Managed = true
			m.Signals = appendUnique(m.Signals, label)
		}
	}
	return m
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}

// Advisory renders the management warning, or an empty string.
func (m Management) Advisory() string {
	if !m.Managed {
		return ""
	}
	return "\nThis Mac appears to be managed by your employer (" + strings.Join(m.Signals, ", ") + ").\n\n" +
		"Capturing configuration to a portable archive may be against your acceptable-use\n" +
		"policy, and endpoint monitoring may flag it, whatever the archive contains. This\n" +
		"bundle holds no credentials, but that is a separate question from whether you are\n" +
		"permitted to create it. Check before you transfer it off this machine.\n\n" +
		"Continuing — this is your call, not the tool's.\n"
}

// ManagedApps returns applications installed under management, which a restore
// should not try to reinstall itself.
//
// Reinstalling a managed app from Homebrew produces two copies with different
// update channels, and the MDM will usually reassert its own afterwards. Naming
// the conflict is more useful than either fighting it or ignoring it.
func ManagedApps(apps []bundle.App) []string {
	var out []string
	for _, a := range apps {
		if a.Source == SourceAppStore {
			continue
		}
		for _, marker := range []string{"Self Service", "Company Portal", "Kandji", "Mosyle", "Addigy"} {
			if strings.Contains(a.Name, marker) {
				out = append(out, a.Name)
			}
		}
	}
	return out
}
