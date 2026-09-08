package restore

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// RunningApps returns the names of applications currently running, matched by
// their bundle path.
//
// Matching on the .app path rather than the process name avoids the obvious
// false positives: a process called "Code" could be anything, but something
// executing out of /Applications/Visual Studio Code.app is unambiguous.
func RunningApps() []string {
	out, err := exec.Command("ps", "-A", "-o", "command=").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		i := strings.Index(line, ".app/")
		if i < 0 {
			continue
		}
		start := strings.LastIndex(line[:i], "/")
		if start < 0 {
			continue
		}
		name := line[start+1 : i]
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BlockedByRunningApp returns the requirements whose application must be quit
// before its configuration can be restored.
//
// An app that rewrites its preferences on quit will overwrite anything restored
// underneath it the moment it closes. Restoring anyway produces the worst kind
// of failure: it reports success, and the change silently disappears an hour
// later when the user quits the app.
func BlockedByRunningApp(reqs []bundle.Requirement, running []string) []bundle.Requirement {
	var blocked []bundle.Requirement
	for _, r := range reqs {
		if !r.QuitFirst {
			continue
		}
		for _, name := range running {
			if appMatches(r, name) {
				blocked = append(blocked, r)
				break
			}
		}
	}
	return blocked
}

// appMatches compares a catalog entry against a running application name
// loosely, because the entry says "iTerm2" and the bundle on disk is "iTerm".
func appMatches(r bundle.Requirement, running string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.NewReplacer(" ", "", "-", "", "_", "").Replace(s))
	}
	a, b := norm(r.Name), norm(running)
	if a == b {
		return true
	}
	// "iTerm2" vs "iTerm": accept a prefix match of at least four characters so
	// short names cannot collide by accident.
	if len(a) >= 4 && len(b) >= 4 && (strings.HasPrefix(a, b) || strings.HasPrefix(b, a)) {
		return true
	}
	return norm(r.Entry) == b
}

// PermissionChecklist renders the macOS permissions a human has to grant.
//
// None of these can be automated: TCC exists precisely so that software cannot
// grant itself access. Listing them is the whole contribution — knowing that
// Karabiner needs Input Monitoring before any remapping works saves an hour of
// wondering why a correct config does nothing.
func PermissionChecklist(reqs []bundle.Requirement) string {
	byPerm := map[string][]string{}
	for _, r := range reqs {
		for _, p := range r.Permissions {
			byPerm[p] = append(byPerm[p], r.Name)
		}
	}
	if len(byPerm) == 0 {
		return ""
	}

	var perms []string
	for p := range byPerm {
		perms = append(perms, p)
	}
	sort.Strings(perms)

	var b strings.Builder
	b.WriteString("\nPermissions to grant by hand in System Settings › Privacy & Security.\n")
	b.WriteString("macstash cannot grant these — that is the point of the permission system:\n")
	for _, p := range perms {
		apps := byPerm[p]
		sort.Strings(apps)
		fmt.Fprintf(&b, "  %-22s %s\n", permissionLabel(p), strings.Join(apps, ", "))
	}
	return b.String()
}

// permissionLabel maps a catalog key to the name macOS actually shows.
func permissionLabel(key string) string {
	switch key {
	case "full_disk_access":
		return "Full Disk Access"
	case "accessibility":
		return "Accessibility"
	case "input_monitoring":
		return "Input Monitoring"
	case "screen_recording":
		return "Screen Recording"
	case "developer_tools":
		return "Developer Tools"
	case "automation":
		return "Automation"
	default:
		return key
	}
}
