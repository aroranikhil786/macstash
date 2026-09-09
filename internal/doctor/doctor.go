// Package doctor answers the question the rest of the tool exists to serve:
// what is still missing?
//
// The month after a migration is the real problem. The initial setup is a
// visible, bounded task that people plan for; what actually hurts is discovering
// over the following weeks, one thing at a time, that a tool is absent, a
// version is wrong, or a login was never restored. doctor turns that trickle
// into a list you can read on day one, and again in week three.
package doctor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/capture"
	"github.com/aroranikhil786/macstash/internal/restore"
)

// Status is the outcome of one check.
type Status string

const (
	// OK means the machine matches what was captured.
	OK Status = "ok"
	// Missing means something recorded is not here.
	Missing Status = "missing"
	// Action means a human has to do something no tool can do for them.
	Action Status = "action"
)

// Check is one finding.
type Check struct {
	Area   string
	Status Status
	Detail string
	// Fix is the command or step that resolves it, where one exists.
	Fix string
}

// Run diffs the live machine against the manifest written by the last restore.
func Run(home string, man *bundle.Manifest, deep bool) []Check {
	var checks []Check
	checks = append(checks, checkFiles(home, man)...)
	checks = append(checks, checkBrew(man)...)
	checks = append(checks, checkScrubs(man)...)
	checks = append(checks, checkSDKs(man)...)
	checks = append(checks, checkToolchains(man)...)
	checks = append(checks, checkExtensions(man)...)
	checks = append(checks, checkApps(man)...)
	checks = append(checks, checkMCP(home, man)...)
	checks = append(checks, checkPermissions(man)...)
	if deep {
		checks = append(checks, checkDeep(man)...)
	}
	return checks
}

// checkFiles verifies captured files are present and unmodified.
func checkFiles(home string, man *bundle.Manifest) []Check {
	var checks []Check
	var present int
	for _, item := range man.Items {
		path := filepath.Join(home, filepath.FromSlash(item.Rel))
		data, err := os.ReadFile(path)
		if err != nil {
			checks = append(checks, Check{
				Area: "files", Status: Missing,
				Detail: item.Rel + " is not on this machine",
				Fix:    "macstash restore <bundle> --apply --only " + item.Entry,
			})
			continue
		}
		present++
		if item.SHA256 == "" {
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != item.SHA256 {
			// Divergence is usually the user editing their own config, which is
			// the correct thing to do. It is reported, not corrected.
			checks = append(checks, Check{
				Area: "files", Status: OK,
				Detail: item.Rel + " has been edited since the restore",
			})
		}
	}
	if present > 0 {
		checks = append(checks, verified("files", "%d restored file(s) still in place", present))
	}
	return checks
}

// checkBrew reports packages that were installed on the old machine and are not
// installed here.
func checkBrew(man *bundle.Manifest) []Check {
	if man.Brewfile == nil {
		return nil
	}
	if _, err := exec.LookPath("brew"); err != nil {
		return []Check{{
			Area: "homebrew", Status: Missing,
			Detail: "Homebrew is not installed, so none of the captured packages are here",
			Fix:    "install Homebrew from https://brew.sh, then re-run the restore",
		}}
	}

	installed := brewSet("list", "--formula")
	casks := brewSet("list", "--cask")

	var checks []Check
	var missing []string
	for _, p := range man.Brewfile.Packages {
		if !installed[p] {
			missing = append(missing, p)
		}
	}
	for _, c := range man.Brewfile.Casknames {
		if !casks[c] {
			missing = append(missing, "--cask "+c)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		checks = append(checks, Check{
			Area: "homebrew", Status: Missing,
			Detail: fmt.Sprintf("%d package(s) not installed: %s", len(missing), strings.Join(truncate(missing, 8), ", ")),
			Fix:    "brew install " + strings.Join(truncate(missing, 8), " "),
		})
	} else if n := len(man.Brewfile.Packages) + len(man.Brewfile.Casknames); n > 0 {
		checks = append(checks, verified("homebrew", "all %d recorded package(s) installed", n))
	}
	return checks
}

func brewSet(args ...string) map[string]bool {
	out := map[string]bool{}
	cmd := exec.Command("brew", args...)
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1", "HOMEBREW_NO_ENV_HINTS=1")
	data, err := cmd.Output()
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out[t] = true
		}
	}
	return out
}

// checkScrubs reports credentials removed at capture.
//
// This is the check that pays for the scrub class. Without it, a registry token
// stripped at capture becomes a 401 three weeks later with no explanation; with
// it, the tool names the file, the reason and the command.
func checkScrubs(man *bundle.Manifest) []Check {
	var checks []Check
	for _, s := range man.Scrubs {
		checks = append(checks, Check{
			Area: "credentials", Status: Action,
			Detail: fmt.Sprintf("%s — %s was removed at capture (%d occurrence(s))", s.File, s.Reason, s.Count),
			Fix:    reauthCommand(s.File),
		})
	}
	return checks
}

// reauthCommand maps a scrubbed file to the command that puts its credential
// back.
func reauthCommand(file string) string {
	switch {
	case strings.HasSuffix(file, ".npmrc"):
		return "npm login  (once per registry listed in ~/.npmrc)"
	case strings.Contains(file, "docker/config.json"):
		return "docker login <registry>"
	case strings.HasSuffix(file, ".gitconfig"):
		return "re-add any credential helper or inline token you rely on"
	case strings.Contains(file, "gradle.properties"):
		return "re-add repository credentials to ~/.gradle/gradle.properties"
	case strings.Contains(file, "pypirc"):
		return "re-add your PyPI token to ~/.pypirc"
	default:
		return "re-authenticate this tool"
	}
}

// checkSDKs verifies recorded language versions are installed.
func checkSDKs(man *bundle.Manifest) []Check {
	var checks []Check
	var considered int
	for manager, versions := range man.System.SDKs {
		tool := strings.SplitN(manager, "/", 2)[0]
		if _, err := exec.LookPath(tool); err != nil {
			if tool == "go" || tool == "rust" {
				continue // reported through Homebrew instead
			}
			considered++
			checks = append(checks, Check{
				Area: "runtimes", Status: Missing,
				Detail: fmt.Sprintf("%s is not installed, so %d recorded version(s) are unavailable", tool, len(versions)),
				Fix:    "install " + tool + ", then re-run the restore",
			})
			continue
		}
		considered++
	}
	if len(checks) == 0 && considered > 0 {
		checks = append(checks, verified("runtimes", "all %d recorded runtime(s) present", considered))
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Detail < checks[j].Detail })
	return checks
}

// checkToolchains verifies globally installed packages.
func checkToolchains(man *bundle.Manifest) []Check {
	var checks []Check
	for manager, pkgs := range man.System.Toolchains {
		if _, err := exec.LookPath(manager); err != nil {
			checks = append(checks, Check{
				Area: "toolchains", Status: Missing,
				Detail: fmt.Sprintf("%s is not installed; %d global package(s) recorded", manager, len(pkgs)),
			})
		}
	}
	if len(checks) == 0 && len(man.System.Toolchains) > 0 {
		checks = append(checks, verified("toolchains", "all %d package manager(s) present", len(man.System.Toolchains)))
	}
	sort.Slice(checks, func(i, j int) bool { return checks[i].Detail < checks[j].Detail })
	return checks
}

// checkExtensions verifies editor extensions.
func checkExtensions(man *bundle.Manifest) []Check {
	var checks []Check
	for editor, want := range man.System.Extensions {
		// Found the way restore finds it: these CLIs ship inside the
		// application and are not on PATH unless someone put them there. Asking
		// PATH alone meant doctor skipped the editor in silence and reported
		// nothing about extensions that were never installed.
		bin, found := restore.EditorCommand(editor)
		if !found {
			checks = append(checks, Check{
				Area: "editor", Status: Action,
				Detail: fmt.Sprintf("%s is not installed here, so its %d extension(s) are not either", editor, len(want)),
				Fix:    "install it, or send them elsewhere: macstash restore <bundle> --apply --extensions-to <editor>",
			})
			continue
		}
		have := map[string]bool{}
		if out, err := exec.Command(bin, "--list-extensions").Output(); err == nil {
			for _, l := range strings.Split(string(out), "\n") {
				if t := strings.TrimSpace(l); t != "" {
					have[t] = true
				}
			}
		}
		var missing []string
		for _, id := range want {
			if !have[id] {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			checks = append(checks, Check{
				Area: "editor", Status: Missing,
				Detail: fmt.Sprintf("%s is missing %d extension(s)", editor, len(missing)),
				Fix:    editor + " --install-extension " + strings.Join(truncate(missing, 3), " --install-extension "),
			})
			continue
		}
		checks = append(checks, verified("editor", "%s has all %d recorded extension(s)", editor, len(want)))
	}
	return checks
}

// checkApps reports applications recorded on the old machine that are not here.
//
// The two groups are kept apart deliberately. An app with a Homebrew cask is
// Missing — a gap with a command that closes it. An app without one is an
// Action, because no tool can close it. Reporting both as "reinstall by hand"
// was the old behaviour and it was wrong on the machine it was written against:
// nine of the ten apps it told the user to go and find had a cask.
func checkApps(man *bundle.Manifest) []Check {
	var installable, manual []string
	var considered int
	tokens := map[string]string{}
	for _, a := range man.Applications {
		if a.Source == "homebrew" || a.Source == "system" {
			continue
		}
		considered++
		if appInstalled(a.Name) {
			continue
		}
		if a.CaskToken != "" {
			installable = append(installable, a.Name)
			tokens[a.Name] = a.CaskToken
			continue
		}
		manual = append(manual, a.Name)
	}

	var checks []Check
	if len(installable) > 0 {
		sort.Strings(installable)
		var cmds []string
		for _, n := range truncate(installable, 6) {
			if t, ok := tokens[n]; ok {
				cmds = append(cmds, t)
			}
		}
		checks = append(checks, Check{
			Area: "applications", Status: Missing,
			Detail: fmt.Sprintf("%d app(s) are not installed but Homebrew has a cask: %s",
				len(installable), strings.Join(truncate(installable, 8), ", ")),
			Fix: "brew install --cask " + strings.Join(cmds, " "),
		})
	}
	if len(manual) > 0 {
		sort.Strings(manual)
		checks = append(checks, Check{
			Area: "applications", Status: Action,
			Detail: fmt.Sprintf("%d app(s) have no Homebrew cask and are not here: %s",
				len(manual), strings.Join(truncate(manual, 8), ", ")),
			Fix: "download and install these yourself — macstash never fetches from URLs",
		})
	}
	// Counted rather than inferred from the manifest: apps Homebrew or macOS
	// owns are skipped above, and confirming apps that were never looked at
	// would be the same false assurance as the count this replaced.
	if len(checks) == 0 && considered > 0 {
		checks = append(checks, verified("applications", "all %d hand-installed application(s) present", considered))
	}
	return checks
}

// appInstalled reports whether an app bundle exists in any of the places macOS
// keeps them.
func appInstalled(name string) bool {
	dirs := []string{"/Applications", "/Applications/Utilities"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(d, name+".app")); err == nil {
			return true
		}
	}
	return false
}

// checkMCP reports MCP servers that were configured on the old machine and are
// not configured here.
//
// Their definitions are never captured — they hold credentials inline — so this
// is the only trace of them a restore leaves. Reporting the ones already
// present matters as much as the missing ones: re-adding a server that is
// already there is how people end up with duplicates.
func checkMCP(home string, man *bundle.Manifest) []Check {
	if len(man.System.MCPServers) == 0 {
		return nil
	}
	here := map[string]bool{}
	for _, s := range capture.ScanMCPServers(home) {
		here[strings.ToLower(s.Name)] = true
	}

	var missing []string
	needs := map[string][]string{}
	for _, s := range man.System.MCPServers {
		if here[strings.ToLower(s.Name)] {
			continue
		}
		missing = append(missing, s.Name)
		if len(s.EnvKeys) > 0 {
			needs[s.Name] = s.EnvKeys
		}
	}
	if len(missing) == 0 {
		return []Check{verified("mcp", "all %d recorded MCP server(s) configured", len(man.System.MCPServers))}
	}
	sort.Strings(missing)

	fix := "re-add them in each editor's MCP settings"
	if len(needs) > 0 {
		var parts []string
		for _, n := range missing {
			if k, ok := needs[n]; ok {
				parts = append(parts, n+" needs "+strings.Join(k, ", "))
			}
		}
		fix = strings.Join(truncate(parts, 4), "; ")
	}
	return []Check{{
		Area: "mcp", Status: Action,
		Detail: fmt.Sprintf("%d MCP server(s) are not configured here: %s",
			len(missing), strings.Join(truncate(missing, 8), ", ")),
		Fix: fix,
	}}
}

// checkPermissions always reports, because there is no way to read TCC grants
// without the very permissions being asked about.
func checkPermissions(man *bundle.Manifest) []Check {
	var checks []Check
	for _, r := range man.Requirements {
		name := r.DisplayName()
		for _, p := range r.Permissions {
			label := bundle.PermissionLabel(p)
			pane := "System Settings › Privacy & Security › " + label

			// Full Disk Access is the one permission that can be answered from
			// here, and only for the terminal this process runs in: macOS grants
			// privacy permissions to an application and a command-line tool
			// inherits its host's, so the probe below describes that app and no
			// other. Everything else is reported without a claim about whether
			// it is granted, which is honest rather than useless: the list still
			// says what to go and check.
			if p != "full_disk_access" {
				checks = append(checks, Check{
					Area: "permissions", Status: Action,
					Detail: fmt.Sprintf("%s needs %s — macstash cannot see whether it is granted", name, label),
					Fix:    pane,
				})
				continue
			}
			if restore.HostTerminalEntry() != r.Entry {
				checks = append(checks, Check{
					Area: "permissions", Status: Action,
					Detail: fmt.Sprintf("%s needs %s — run doctor inside %s to test it", name, label, name),
					Fix:    pane,
				})
				continue
			}
			if fullDiskAccessGranted() {
				checks = append(checks, Check{
					Area: "permissions", Status: OK,
					Detail: fmt.Sprintf("%s has %s", name, label),
				})
				continue
			}
			checks = append(checks, Check{
				Area: "permissions", Status: Action,
				Detail: fmt.Sprintf("%s does not have %s", name, label),
				Fix:    pane + ", then add " + name,
			})
		}
	}
	return checks
}

// fullDiskAccessGranted reports whether this process can read a TCC-protected
// path.
//
// ~/Library/Application Support/com.apple.TCC/TCC.db is the probe: it exists on
// every install, its Unix mode is world-readable, and the only thing standing
// between a process and its contents is the privacy grant. Checked on a machine
// without the permission, where the open fails despite mode 644, which is what
// makes the result mean what it says.
//
// A read that fails for any other reason counts as not granted. This decides
// whether to print a checklist item, so the cost of being wrong is one line
// somebody can ignore.
func fullDiskAccessGranted() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	f, err := os.Open(filepath.Join(home, "Library", "Application Support", "com.apple.TCC", "TCC.db"))
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// checkDeep actually runs things, rather than comparing lists.
//
// A toolchain can be present and still not work: a JDK on PATH but the wrong
// one, a git remote that resolves but rejects your key, a docker CLI with no
// daemon behind it. These are the failures that look fine until the first real
// task of the day.
func checkDeep(man *bundle.Manifest) []Check {
	var checks []Check
	probe := func(area, detail string, timeout time.Duration, name string, args ...string) {
		if _, err := exec.LookPath(name); err != nil {
			return
		}
		cmd := exec.Command(name, args...)
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			return
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				checks = append(checks, Check{Area: area, Status: Missing, Detail: detail + " failed"})
			} else {
				checks = append(checks, Check{Area: area, Status: OK, Detail: detail + " works"})
			}
		case <-time.After(timeout):
			_ = cmd.Process.Kill()
			checks = append(checks, Check{Area: area, Status: Missing, Detail: detail + " timed out"})
		}
	}

	probe("deep", "git authentication (ls-remote against origin)", 20*time.Second, "git", "ls-remote", "--exit-code", "origin", "HEAD")
	probe("deep", "docker daemon", 15*time.Second, "docker", "info")
	probe("deep", "java runtime", 10*time.Second, "java", "-version")
	probe("deep", "go toolchain", 20*time.Second, "go", "version")
	probe("deep", "kubectl cluster access", 15*time.Second, "kubectl", "version", "--client")
	return checks
}

// verified records a check that looked and found nothing wrong.
//
// Without these the summary counts only problems, so a machine in perfect shape
// reported "0 fine" and there was no way to tell a clean result from a check
// that never ran. A count of what was actually confirmed is the number worth
// printing.
func verified(area, format string, args ...any) Check {
	return Check{Area: area, Status: OK, Detail: fmt.Sprintf(format, args...)}
}

func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("... +%d more", len(s)-n))
}

// Summarise renders checks for a human, worst first.
func Summarise(checks []Check, verbose bool) string {
	var b strings.Builder
	byStatus := map[Status][]Check{}
	for _, c := range checks {
		byStatus[c.Status] = append(byStatus[c.Status], c)
	}

	fmt.Fprintf(&b, "%d checked, %d missing, %d needing you\n\n",
		len(checks), len(byStatus[Missing]), len(byStatus[Action]))

	for _, status := range []Status{Missing, Action} {
		group := byStatus[status]
		if len(group) == 0 {
			continue
		}
		label := "Missing"
		if status == Action {
			label = "Needs you — nothing can do these for you"
		}
		fmt.Fprintf(&b, "%s:\n", label)
		for _, c := range group {
			fmt.Fprintf(&b, "  [%s] %s\n", c.Area, c.Detail)
			if c.Fix != "" {
				fmt.Fprintf(&b, "         %s\n", c.Fix)
			}
		}
		b.WriteString("\n")
	}

	// The confirmations are the answer to "did it actually look?", which the
	// counts alone cannot settle. They are not worth a screen every time, so
	// they print on request.
	if verbose && len(byStatus[OK]) > 0 {
		b.WriteString("Confirmed:\n")
		for _, c := range byStatus[OK] {
			fmt.Fprintf(&b, "  [%s] %s\n", c.Area, c.Detail)
		}
		b.WriteString("\n")
	} else if n := len(byStatus[OK]); n > 0 {
		fmt.Fprintf(&b, "%d check(s) confirmed fine. Pass --verbose to list them.\n\n", n)
	}

	if len(byStatus[Missing]) == 0 && len(byStatus[Action]) == 0 {
		b.WriteString("Nothing outstanding against the recorded manifest. That is a statement\n" +
			"about what was captured, not a guarantee that the machine is complete.\n")
	}
	return b.String()
}
