package restore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
			byPerm[p] = append(byPerm[p], r.DisplayName())
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
		fmt.Fprintf(&b, "  %-22s %s\n", bundle.PermissionLabel(p), strings.Join(apps, ", "))
	}
	return b.String()
}

// hostTerminals maps $TERM_PROGRAM to the catalog entry for that terminal.
//
// Values are what the terminals actually export, checked rather than guessed:
// iTerm2 sets "iTerm.app", Apple's Terminal sets "Apple_Terminal".
var hostTerminals = map[string]string{
	"iTerm.app":      "iterm2",
	"Apple_Terminal": "terminal",
	"WezTerm":        "wezterm",
	"ghostty":        "ghostty",
	"alacritty":      "alacritty",
	"Alacritty":      "alacritty",
	"vscode":         "vscode",
}

// HostTerminalEntry returns the catalog entry id of the terminal macstash is
// running inside, or "" if it cannot tell.
func HostTerminalEntry() string {
	return hostTerminals[os.Getenv("TERM_PROGRAM")]
}

// RunningInside reports whether a blocked requirement is the terminal this
// process is running in.
//
// This is the difference between an instruction and a dead end. "iTerm2 is
// running — quit it and re-run" is impossible advice when the shell printing it
// lives inside iTerm2: quitting takes the restore with it. The user needs to be
// told to start a different terminal, which is not something they would infer.
func RunningInside(r bundle.Requirement) bool {
	entry := HostTerminalEntry()
	return entry != "" && entry == r.Entry
}

// HostTerminalAdvice returns the instruction for a blocked app that happens to
// be the terminal in use.
func HostTerminalAdvice(r bundle.Requirement) string {
	name := r.Name
	if name == "" {
		name = r.Entry
	}
	if HostTerminalEntry() == "terminal" {
		return "you are running inside " + name + " — quitting it would end this restore.\n" +
			"        Run macstash from a different terminal instead"
	}
	return "you are running inside " + name + " — quitting it would end this restore.\n" +
		"        Open Terminal (in /Applications/Utilities) and run macstash from there"
}

// GitRewritesToSSH reports whether the restored git config rewrites remote URLs
// to SSH.
//
// An insteadOf rule is correct configuration that depends on something a bundle
// deliberately never carries. On a machine with no key yet it turns every fetch
// into an authentication failure, and Homebrew goes down with it, because brew
// clones its taps with the user's git config. Both facts were already in the
// restore output, in separate sections, and connecting them is the difference
// between a checklist and a morning spent debugging.
func GitRewritesToSSH(home string) bool {
	data, err := os.ReadFile(filepath.Join(home, ".gitconfig"))
	if err != nil {
		return false
	}
	// Only rules pointing at SSH matter. The reverse direction, rewriting SSH
	// to HTTPS, needs no key and is often exactly how someone works around not
	// having one.
	for _, section := range strings.Split(string(data), "[url ")[1:] {
		head, body, ok := strings.Cut(section, "]")
		// Case-insensitive so pushInsteadOf counts too. It rewrites only pushes,
		// which is a narrower break than insteadOf but needs the same key.
		if !ok || !strings.Contains(strings.ToLower(body), "insteadof") {
			continue
		}
		if strings.Contains(head, "git@") || strings.Contains(head, "ssh://") {
			return true
		}
	}
	return false
}

// HasSSHKey reports whether a private key exists in ~/.ssh.
//
// The public halves are ignored: one on its own authenticates nothing, which is
// why macstash stopped carrying them.
func HasSSHKey(home string) bool {
	entries, err := os.ReadDir(filepath.Join(home, ".ssh"))
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasSuffix(name, ".pub") {
			continue
		}
		if strings.HasPrefix(name, "id_") {
			return true
		}
	}
	return false
}
