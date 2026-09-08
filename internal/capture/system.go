package capture

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// commandTimeout bounds every external command.
//
// Several of these talk to daemons — docker in particular will sit there
// indefinitely if Docker Desktop is starting up — and a capture that hangs is a
// capture nobody runs monthly.
const commandTimeout = 10 * time.Second

// run executes a command with a timeout and returns trimmed stdout.
func run(name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "NO_COLOR=1")
	out, err := cmd.Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(out)), true
}

// lines splits command output into non-empty trimmed lines.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ScanSystem gathers everything that is a list rather than a file: language
// runtime versions, globally installed packages, editor extensions and the
// handful of settings that live in places `defaults` does not reach.
//
// None of it is copied. Versions and package names are recorded so the new
// machine can install the same things from the same public sources, which is
// both smaller and safer than moving binaries between machines.
func ScanSystem(home string) bundle.System {
	var s bundle.System
	s.SDKs = scanSDKs(home)
	s.Toolchains = scanToolchains()
	s.Extensions = scanEditorExtensions()
	s.LoginItems = scanLoginItems()
	s.KubeContexts = scanKubeContexts()
	s.DockerContexts, s.DockerImages = scanDocker()
	s.Keyboard = scanKeyboard()
	s.DefaultApps = scanDefaultApps()
	s.HostsEntries = scanHosts()
	s.MCPServers = ScanMCPServers(home)
	return s
}

// scanSDKs records the exact language versions installed and which is current.
//
// "Install Java 17" is not good enough — the build that works is the one built
// with 17.0.9-tem, and finding that out again means bisecting a week of CI.
func scanSDKs(home string) map[string][]string {
	sdks := map[string][]string{}

	// SDKMAN is a shell function, not a binary, so its state is read from disk.
	candidates := filepath.Join(home, ".sdkman", "candidates")
	if entries, err := os.ReadDir(candidates); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			var versions []string
			vs, err := os.ReadDir(filepath.Join(candidates, e.Name()))
			if err != nil {
				continue
			}
			for _, v := range vs {
				if v.Name() == "current" {
					if target, err := os.Readlink(filepath.Join(candidates, e.Name(), "current")); err == nil {
						versions = append(versions, "current="+filepath.Base(target))
					}
					continue
				}
				versions = append(versions, v.Name())
			}
			if len(versions) > 0 {
				sdks["sdkman/"+e.Name()] = versions
			}
		}
	}

	if out, ok := run("fnm", "list"); ok {
		sdks["fnm"] = lines(out)
	}
	if entries, err := os.ReadDir(filepath.Join(home, ".nvm", "versions", "node")); err == nil {
		var versions []string
		for _, e := range entries {
			versions = append(versions, e.Name())
		}
		if len(versions) > 0 {
			sdks["nvm"] = versions
		}
	}
	if out, ok := run("pyenv", "versions", "--bare"); ok {
		sdks["pyenv"] = lines(out)
	}
	if out, ok := run("rbenv", "versions", "--bare"); ok {
		sdks["rbenv"] = lines(out)
	}
	if out, ok := run("asdf", "list"); ok {
		sdks["asdf"] = lines(out)
	}
	if out, ok := run("mise", "ls", "--installed"); ok {
		sdks["mise"] = lines(out)
	}
	if out, ok := run("go", "version"); ok {
		sdks["go"] = []string{out}
	}
	if out, ok := run("rustc", "--version"); ok {
		sdks["rust"] = []string{out}
	}
	return sdks
}

// scanToolchains records globally installed packages per package manager.
func scanToolchains() map[string][]string {
	t := map[string][]string{}

	if out, ok := run("npm", "ls", "-g", "--depth=0", "--parseable"); ok {
		var pkgs []string
		for _, l := range lines(out) {
			if base := filepath.Base(l); base != "lib" && base != "" {
				pkgs = append(pkgs, base)
			}
		}
		if len(pkgs) > 0 {
			t["npm"] = pkgs
		}
	}
	if out, ok := run("pipx", "list", "--short"); ok {
		t["pipx"] = lines(out)
	}
	if out, ok := run("uv", "tool", "list"); ok {
		// uv lists each tool then indents its binaries with a leading dash.
		var pkgs []string
		for _, l := range lines(out) {
			if !strings.HasPrefix(l, "-") {
				pkgs = append(pkgs, l)
			}
		}
		if len(pkgs) > 0 {
			t["uv"] = pkgs
		}
	}
	if out, ok := run("cargo", "install", "--list"); ok {
		var pkgs []string
		for _, l := range lines(out) {
			// Top-level entries are unindented; binaries under them are indented.
			if !strings.HasPrefix(l, " ") && strings.HasSuffix(l, ":") {
				pkgs = append(pkgs, strings.TrimSuffix(l, ":"))
			}
		}
		if len(pkgs) > 0 {
			t["cargo"] = pkgs
		}
	}
	if out, ok := run("gem", "list", "--local", "--no-versions"); ok {
		t["gem"] = lines(out)
	}
	if out, ok := run("kubectl", "krew", "list"); ok {
		t["krew"] = lines(out)
	}
	return t
}

// scanEditorExtensions lists installed editor extensions by id.
func scanEditorExtensions() map[string][]string {
	ext := map[string][]string{}
	for _, editor := range []string{"code", "code-insiders", "cursor", "windsurf"} {
		if out, ok := run(editor, "--list-extensions"); ok {
			if l := lines(out); len(l) > 0 {
				ext[editor] = l
			}
		}
	}
	return ext
}

// scanLoginItems lists what starts at login. Reported only: adding login items
// programmatically means writing to another app's domain, and a restore that
// silently arranges for programs to run at every login is not a restore anyone
// asked for.
func scanLoginItems() []string {
	out, ok := run("osascript", "-e",
		`tell application "System Events" to get the name of every login item`)
	if !ok {
		return nil
	}
	var items []string
	for _, p := range strings.Split(out, ",") {
		if t := strings.TrimSpace(p); t != "" {
			items = append(items, t)
		}
	}
	return items
}

// scanKubeContexts records context names only.
//
// The kubeconfig itself is on the never list — it holds client certificates and
// tokens. The names are enough to tell someone which clusters they need to get
// access to again.
func scanKubeContexts() []string {
	out, ok := run("kubectl", "config", "get-contexts", "-o", "name")
	if !ok {
		return nil
	}
	return lines(out)
}

// scanDocker records context names and image names. Images are never bundled —
// they are enormous and re-pullable by name.
func scanDocker() (contexts, images []string) {
	if out, ok := run("docker", "context", "ls", "--format", "{{.Name}}"); ok {
		contexts = lines(out)
	}
	if out, ok := run("docker", "images", "--format", "{{.Repository}}:{{.Tag}}"); ok {
		for _, l := range lines(out) {
			if !strings.HasPrefix(l, "<none>") {
				images = append(images, l)
			}
		}
		sort.Strings(images)
	}
	return contexts, images
}

// scanKeyboard records key repeat rates and modifier remapping.
func scanKeyboard() map[string]string {
	k := map[string]string{}
	for _, key := range []string{"InitialKeyRepeat", "KeyRepeat", "ApplePressAndHoldEnabled"} {
		if out, ok := run("defaults", "read", "-g", key); ok {
			k[key] = out
		}
	}
	if out, ok := run("defaults", "read", "com.apple.keyboard.fnState"); ok {
		k["fnState"] = out
	}
	return k
}

// scanDefaultApps records which application opens which file type, via duti.
func scanDefaultApps() map[string]string {
	out, ok := run("duti", "-x", "html")
	if !ok {
		return nil
	}
	apps := map[string]string{}
	if l := lines(out); len(l) > 0 {
		apps["html"] = l[0]
	}
	for _, ext := range []string{"md", "json", "js", "ts", "py", "go", "txt", "pdf", "csv", "yaml"} {
		if o, ok := run("duti", "-x", ext); ok {
			if l := lines(o); len(l) > 0 {
				apps[ext] = l[0]
			}
		}
	}
	return apps
}

// scanHosts records non-default /etc/hosts entries.
//
// Only the custom lines are kept. The boilerplate localhost block is identical
// on every Mac, and restoring it wholesale would clobber whatever the new
// machine already has.
func scanHosts() []string {
	data, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return nil
	}
	defaults := map[string]bool{
		"127.0.0.1 localhost": true, "255.255.255.255 broadcasthost": true,
		"::1 localhost": true, "fe80::1%lo0 localhost": true,
	}
	var custom []string
	for _, l := range lines(string(data)) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		norm := strings.Join(strings.Fields(l), " ")
		if defaults[norm] {
			continue
		}
		custom = append(custom, norm)
	}
	return custom
}
