package restore

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// ManifestPath is where restore records what it did, for `doctor` to compare
// against later.
const ManifestPath = ".macstash/manifest.json"

// EnsureXcodeTools triggers Apple's Command Line Tools installer if the tools
// are missing. The installer is Apple's own and interactive; macstash starts it
// and steps out of the way.
func EnsureXcodeTools(out io.Writer) {
	if _, err := exec.Command("xcode-select", "-p").Output(); err == nil {
		return
	}
	fmt.Fprintln(out, "\nXcode Command Line Tools are missing. Starting Apple's installer —")
	fmt.Fprintln(out, "accept the dialog, then re-run this restore (it is safe to repeat).")
	cmd := exec.Command("xcode-select", "--install")
	cmd.Stdout, cmd.Stderr = out, out
	_ = cmd.Run()
}

// EnsureRosetta installs Rosetta 2 on Apple Silicon if it is absent.
//
// Plenty of developer tooling is still x86-only, and the failure without Rosetta
// is an unhelpful "bad CPU type in executable" long after the restore finished.
func EnsureRosetta(out io.Writer) {
	if runtime.GOARCH != "arm64" {
		return
	}
	if _, err := os.Stat("/Library/Apple/usr/share/rosetta/rosetta"); err == nil {
		return
	}
	fmt.Fprintln(out, "\nInstalling Rosetta 2 (Apple's installer, needed for x86-only tools)...")
	cmd := exec.Command("softwareupdate", "--install-rosetta", "--agree-to-license")
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(out, "  Rosetta install did not complete (%v). Run it by hand if you need it.\n", err)
	}
}

// RestorePrefs imports exported preference domains.
//
// Apps that were blocked for running are excluded upstream, because importing a
// domain under a running app is undone the moment that app quits.
func (p *Plan) RestorePrefs(out io.Writer) error {
	dir := filepath.Join(p.Staging, "prefs")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // no prefs in this bundle
	}
	// Map preference domains back to the catalog entries that own them, so a
	// blocked app's domain can be recognised. The blocked set is keyed by
	// display name ("iTerm2") while a domain is a bundle identifier
	// ("com.googlecode.iterm2"), so comparing the two directly never matches.
	blockedDomain := map[string]string{}
	for _, b := range p.BlockedApps {
		for _, d := range p.Manifest.System.PrefOwners[b.Entry] {
			blockedDomain[d] = b.Name
		}
	}

	fmt.Fprintln(out, "\nImporting preferences:")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".plist") {
			continue
		}
		domain := strings.TrimSuffix(e.Name(), ".plist")

		// Importing a domain under a running app is undone the moment that app
		// quits and rewrites its preferences from memory. Reporting "imported"
		// and then losing it hours later is worse than refusing now.
		if app, isBlocked := blockedDomain[domain]; isBlocked {
			fmt.Fprintf(out, "  %-34s REFUSED — %s is running\n", domain, app)
			continue
		}
		cmd := exec.Command("defaults", "import", domain, filepath.Join(dir, e.Name()))
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(out, "  %-34s failed: %v\n", domain, err)
			continue
		}
		fmt.Fprintf(out, "  %-34s imported\n", domain)
	}
	fmt.Fprintln(out, "  Some preference changes only take effect after logging out and back in.")
	return nil
}

// RestoreSDKs reinstalls the exact language versions recorded at capture.
//
// Exact versions matter more than they look. "Java 17" and "17.0.9-tem" are not
// the same thing when a build breaks, and rediscovering which one worked costs
// far more than recording it did.
func (p *Plan) RestoreSDKs(out io.Writer, apply bool) {
	sdks := p.Manifest.System.SDKs
	if len(sdks) == 0 {
		return
	}
	fmt.Fprintln(out, "\nLanguage runtimes recorded on the old machine:")

	var managers []string
	for m := range sdks {
		managers = append(managers, m)
	}
	sort.Strings(managers)

	for _, m := range managers {
		versions := sdks[m]
		tool := strings.SplitN(m, "/", 2)[0]
		available := commandAvailable(tool)

		fmt.Fprintf(out, "  %-16s %s\n", m, strings.Join(truncate(versions, 4), ", "))
		if !available {
			fmt.Fprintf(out, "  %-16s (%s is not installed here — install it, then re-run)\n", "", tool)
			continue
		}
		if !apply {
			continue
		}
		for _, v := range versions {
			if strings.HasPrefix(v, "current=") || strings.Contains(v, " ") {
				continue
			}
			if args := installArgs(tool, v); args != nil {
				cmd := exec.Command(args[0], args[1:]...)
				cmd.Stdout, cmd.Stderr = out, out
				_ = cmd.Run() // individual failures are reported by the tool itself
			}
		}
	}
}

// installArgs maps a version manager and version to its install command.
func installArgs(tool, version string) []string {
	switch tool {
	case "fnm":
		return []string{"fnm", "install", version}
	case "pyenv":
		return []string{"pyenv", "install", "--skip-existing", version}
	case "rbenv":
		return []string{"rbenv", "install", "--skip-existing", version}
	case "mise":
		return []string{"mise", "install", version}
	default:
		// sdkman is a shell function and go/rust come from Homebrew; neither can
		// be driven usefully from here.
		return nil
	}
}

// RestoreToolchains reinstalls globally installed packages.
//
// This is opt-in rather than automatic. A real machine had 122 gems and 8 npm
// globals recorded; reinstalling those is an unbounded, unattended, network-bound
// phase in the middle of a restore, where a single hung package stalls
// everything and the user has no signal about what is happening. Printing the
// list and the exact command is more useful than doing it silently, and someone
// who does want it automated passes --install-toolchains.
func (p *Plan) RestoreToolchains(out io.Writer, apply bool) {
	t := p.Manifest.System.Toolchains
	if len(t) == 0 {
		return
	}
	fmt.Fprintln(out, "\nGlobally installed packages:")

	var managers []string
	for m := range t {
		managers = append(managers, m)
	}
	sort.Strings(managers)

	for _, m := range managers {
		pkgs := t[m]
		fmt.Fprintf(out, "  %-8s %d package(s): %s\n", m, len(pkgs), strings.Join(truncate(pkgs, 5), ", "))
		if !apply {
			continue
		}
		if !commandAvailable(m) {
			fmt.Fprintf(out, "  %-8s (%s is not installed here)\n", "", m)
			continue
		}
		fmt.Fprintf(out, "  %-8s installing %d package(s), this reaches the network...\n", "", len(pkgs))
		for i, pkg := range pkgs {
			args := toolchainInstallArgs(m, pkg)
			if args == nil {
				continue
			}
			fmt.Fprintf(out, "  %-8s [%d/%d] %s\n", "", i+1, len(pkgs), pkg)
			cmd := exec.Command(args[0], args[1:]...)
			_ = cmd.Run() // individual failures are the package manager's to report
		}
	}
}

func toolchainInstallArgs(manager, pkg string) []string {
	// Strip any trailing version annotation the listing added.
	pkg = strings.TrimSpace(strings.SplitN(pkg, " ", 2)[0])
	if pkg == "" || strings.HasPrefix(pkg, "-") {
		return nil
	}
	switch manager {
	case "npm":
		return []string{"npm", "install", "-g", pkg}
	case "pipx":
		return []string{"pipx", "install", pkg}
	case "cargo":
		return []string{"cargo", "install", pkg}
	case "gem":
		return []string{"gem", "install", pkg}
	default:
		return nil
	}
}

// RestoreExtensions reinstalls editor extensions.
//
// Two things it will not do quietly. If the editor's command-line tool is not
// on PATH it prints the ids rather than only the count, because a bare "47
// extension(s), not installed" leaves nothing to act on and the list is the
// whole reason they were captured. And a failed install is counted and named:
// the exit status used to be discarded, so a run where every extension failed
// looked exactly like a run where every one succeeded.
func (p *Plan) RestoreExtensions(out io.Writer, apply bool, target string) {
	ext := p.Manifest.System.Extensions
	if len(ext) == 0 {
		return
	}
	fmt.Fprintln(out, "\nEditor extensions:")

	var editors []string
	for e := range ext {
		editors = append(editors, e)
	}
	sort.Strings(editors)

	if target != "" {
		ids := mergedExtensions(ext)
		fmt.Fprintf(out, "  %-14s %d extension(s), from %s in the bundle\n",
			target, len(ids), strings.Join(editors, " and "))
		installExtensions(out, target, ids, apply)
		return
	}

	var missing bool
	for _, editor := range editors {
		ids := ext[editor]
		fmt.Fprintf(out, "  %-14s %d extension(s)\n", editor, len(ids))
		if _, found := editorCommand(editor); !found {
			missing = true
			fmt.Fprintf(out, "  %-14s (%s is not installed here)\n", "", editor)
			for _, id := range ids {
				fmt.Fprintf(out, "    %s\n", id)
			}
			continue
		}
		installExtensions(out, editor, ids, apply)
	}
	if missing {
		offerAnotherEditor(out)
	}
}

// installExtensions runs the editor's own command once per extension.
func installExtensions(out io.Writer, editor string, ids []string, apply bool) {
	bin, found := editorCommand(editor)
	if !found || !apply {
		return
	}
	var failed []string
	for _, id := range ids {
		cmd := exec.Command(bin, "--install-extension", id, "--force")
		if err := cmd.Run(); err != nil {
			failed = append(failed, id)
		}
	}
	fmt.Fprintf(out, "  %-14s installed %d, failed %d\n", "", len(ids)-len(failed), len(failed))
	for _, id := range failed {
		fmt.Fprintf(out, "    failed: %s\n", id)
	}
}

// offerAnotherEditor names the editors that could take the extensions instead.
//
// These are all VS Code forks and accept the same extension ids, so a bundle
// captured from stable is useful on a machine running only Insiders. Restore
// does not redirect on its own: which editor someone wants their extensions in
// is a preference, not something to infer from what happens to be installed.
// Printing the flag beside the list is the difference between a dead end and a
// second command.
func offerAnotherEditor(out io.Writer) {
	here := InstalledEditors()
	if len(here) == 0 {
		fmt.Fprintf(out, "  %-14s Install one of these editors, then re-run to get the list above.\n", "")
		return
	}
	fmt.Fprintf(out, "\n  Those extensions can go into an editor you do have. These take the same\n"+
		"  ids, so re-run with whichever you want:\n")
	for _, e := range here {
		fmt.Fprintf(out, "    --extensions-to %s\n", e)
	}
}

// mergedExtensions flattens every editor's list into one deduplicated set. A
// machine running both stable and Insiders records shared extensions twice, and
// installing the same id twice is only slower.
func mergedExtensions(ext map[string][]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ids := range ext {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

// KnownEditors lists the editors macstash can install extensions into.
func KnownEditors() []string {
	names := make([]string, 0, len(editorApps))
	for n := range editorApps {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// InstalledEditors returns the known editors present on this machine.
func InstalledEditors() []string {
	var out []string
	for _, n := range KnownEditors() {
		if _, ok := editorCommand(n); ok {
			out = append(out, n)
		}
	}
	return out
}

// CheckEditorTarget validates an --extensions-to value before the restore
// starts. Finding a typo after the files are written means running the whole
// thing again.
func CheckEditorTarget(name string) error {
	if _, ok := editorApps[name]; !ok {
		return fmt.Errorf("no editor %q; macstash knows %s", name, strings.Join(KnownEditors(), ", "))
	}
	if _, ok := editorCommand(name); !ok {
		if here := InstalledEditors(); len(here) > 0 {
			return fmt.Errorf("%s is not installed here; these are: %s", name, strings.Join(here, ", "))
		}
		return fmt.Errorf("%s is not installed here", name)
	}
	return nil
}

// ReportOnly prints the things a restore cannot do anything about.
func (p *Plan) ReportOnly(out io.Writer) {
	s := p.Manifest.System

	if len(s.LoginItems) > 0 {
		fmt.Fprintf(out, "\nLogin items on the old machine (add by hand — macstash will not arrange\nfor programs to run at your login):\n")
		for _, i := range s.LoginItems {
			fmt.Fprintf(out, "  %s\n", i)
		}
	}
	if len(s.KubeContexts) > 0 {
		fmt.Fprintf(out, "\nKubernetes contexts (the kubeconfig itself is never captured):\n")
		for _, c := range s.KubeContexts {
			fmt.Fprintf(out, "  %s\n", c)
		}
	}
	if len(s.DockerImages) > 0 {
		fmt.Fprintf(out, "\nDocker images to pull again (%d; images are never bundled):\n", len(s.DockerImages))
		for _, i := range truncate(s.DockerImages, 10) {
			fmt.Fprintf(out, "  docker pull %s\n", i)
		}
	}
	if len(s.HostsEntries) > 0 {
		fmt.Fprintf(out, "\nCustom /etc/hosts entries (needs sudo, so add them yourself):\n")
		for _, h := range s.HostsEntries {
			fmt.Fprintf(out, "  %s\n", h)
		}
	}
	if len(s.DefaultApps) > 0 {
		fmt.Fprintf(out, "\nDefault applications by file type (needs duti):\n")
		var exts []string
		for e := range s.DefaultApps {
			exts = append(exts, e)
		}
		sort.Strings(exts)
		for _, e := range exts {
			fmt.Fprintf(out, "  duti -s %s %s all\n", s.DefaultApps[e], e)
		}
	}
	if len(s.Keyboard) > 0 {
		fmt.Fprintf(out, "\nKeyboard settings:\n")
		var keys []string
		for k := range s.Keyboard {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(out, "  defaults write -g %s %s\n", k, s.Keyboard[k])
		}
	}
}

// WriteManifest records the restored state at ~/.macstash/manifest.json.
//
// This is what `doctor` compares the live machine against later. Without it,
// doctor has nothing to diff and the "what is still missing" question — the one
// the whole project exists to answer — cannot be asked.
func (p *Plan) WriteManifest(home string) error {
	path := filepath.Join(home, ManifestPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(p.Manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// editorApps maps an editor's command to the application that ships it.
var editorApps = map[string]string{
	"code":          "Visual Studio Code",
	"code-insiders": "Visual Studio Code - Insiders",
	"cursor":        "Cursor",
	"windsurf":      "Windsurf",
}

// editorCommand finds the binary that installs an extension.
//
// PATH first, then inside the application itself. Every one of these editors
// ships its command-line tool at Contents/Resources/app/bin, and putting it on
// PATH is a manual step from inside the editor that most people never take.
// Refusing to install 39 extensions because of that, when the binary is sitting
// at a known path, is a worse answer than looking for it.
//
// The binary is found by reading that directory rather than by guessing its
// name: in Visual Studio Code - Insiders it is called "code", not
// "code-insiders", and names differ across the forks. Tunnel helpers live there
// too and are skipped.
func editorCommand(name string) (string, bool) {
	if path, err := exec.LookPath(name); err == nil {
		return path, true
	}
	app, ok := editorApps[name]
	if !ok {
		return "", false
	}
	dirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	for _, d := range dirs {
		bin := filepath.Join(d, app+".app", "Contents", "Resources", "app", "bin")
		entries, err := os.ReadDir(bin)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.Contains(e.Name(), "tunnel") {
				continue
			}
			path := filepath.Join(bin, e.Name())
			if info, err := os.Stat(path); err == nil && info.Mode()&0o111 != 0 {
				return path, true
			}
		}
	}
	return "", false
}

func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("... +%d more", len(s)-n))
}

// LoadLiveManifest reads the manifest written by a previous restore.
func LoadLiveManifest(home string) (*bundle.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(home, ManifestPath))
	if err != nil {
		return nil, err
	}
	var m bundle.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
