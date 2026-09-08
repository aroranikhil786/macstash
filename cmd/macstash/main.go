// Command macstash captures a macOS development environment and rebuilds it on
// another Mac.
//
// macstash opens no sockets of its own. That is enforced in CI at the import
// graph, and capture additionally re-executes itself inside a sandbox that denies
// network access outright, so it is a property of the process and not merely a
// claim in a README.
package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/capture"
	"github.com/aroranikhil786/macstash/internal/catalog"
	"github.com/aroranikhil786/macstash/internal/doctor"
	"github.com/aroranikhil786/macstash/internal/redact"
	"github.com/aroranikhil786/macstash/internal/restore"
	"github.com/aroranikhil786/macstash/internal/scanner"
	"github.com/aroranikhil786/macstash/internal/selection"
)

// Version is the macstash release this binary was built from.
// Version is overwritten at release time by scripts/release.sh via
// -ldflags "-X main.Version=...". It must stay a var: the Go linker silently
// ignores -X on a const, so declaring it const would ship every release
// labelled 0.1.0-dev, and record that wrong version in every bundle manifest.
var Version = "0.2.0-dev"

const usage = `macstash — capture a macOS development environment and rebuild it elsewhere

  macstash capture                 scan this Mac and write a bundle to ~/macstash/
  macstash capture --plan          show what would be captured, write nothing
  macstash inspect <bundle>        read a bundle's manifest without applying it
  macstash doctor                  what is still missing on this machine
  macstash doctor --deep           actually run things, not just compare lists
  macstash catalog [show <id>]     what macstash knows how to capture
  macstash clone [bundle]          clone the repositories a bundle recorded
  macstash backups --prune         apply retention to ~/.macstash/backups
  macstash export --to brewfile    convert a bundle to another tool's format
  macstash restore <bundle>        show what a restore would change (default)
  macstash restore <bundle> --apply   actually restore

Flags:
  --plan              show changes without making them
  --apply             make the changes (restore only)
  -o <path>           output path for capture
  --force             write a bundle into a cloud-synced folder anyway
  --from-other-user   restore a bundle captured by a different user
  --unredacted        show git remotes and tap URLs in full (they are hidden by
                      default because terminal output gets screenshotted)
  --only <ids>        restrict to these catalog entries (comma-separated)
  --skip <ids>        exclude these catalog entries
  --yes               do not pause for confirmation
  --install-toolchains  reinstall global npm/gem/pipx/cargo packages during
                      restore (off by default: it is a long unattended,
                      network-bound phase; the report lists the commands)
  --install-apps      install missing applications with brew install --cask
                      (off by default: it downloads and installs GUI software)
  --clone-repos       clone the recorded repositories during restore (off by
                      default: needs your SSH key and any VPN to be in place)
  --select            open a selection file in $EDITOR and prune what is
                      captured or restored: apps, repos, packages, configs
  --selection <path>  reuse a selection file saved earlier, without an editor
  --include-launch-agents   restore LaunchAgents (background programs; off by
                      default because they run code at every login)
  --verbose           list every file

Bundles never contain credentials. Expect to re-authenticate a few tools on the
new machine; ` + "`inspect`" + ` lists which ones.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
}

type flags struct {
	plan              bool
	apply             bool
	force             bool
	fromOtherUser     bool
	unredacted        bool
	yes               bool
	deep              bool
	installToolchains bool
	installApps       bool
	cloneRepos        bool
	selectItems       bool
	selectionFile     string
	prune             bool
	to                string
	launchAgents      bool
	only              []string
	skip              []string
	verbose           bool
	out               string
	args              []string
}

func parse(argv []string) (*flags, error) {
	f := &flags{}
	for i := 0; i < len(argv); i++ {
		switch a := argv[i]; a {
		case "--plan":
			f.plan = true
		case "--apply":
			f.apply = true
		case "--force":
			f.force = true
		case "--from-other-user":
			f.fromOtherUser = true
		case "--unredacted":
			f.unredacted = true
		case "--yes", "-y":
			f.yes = true
		case "--include-launch-agents":
			f.launchAgents = true
		case "--deep":
			f.deep = true
		case "--install-toolchains":
			f.installToolchains = true
		case "--install-apps":
			f.installApps = true
		case "--clone-repos":
			f.cloneRepos = true
		case "--select":
			f.selectItems = true
		case "--selection":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("--selection needs a path to a selection file")
			}
			i++
			f.selectionFile = argv[i]
		case "--prune":
			f.prune = true
		case "--to":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("--to needs a format (brewfile or chezmoi)")
			}
			i++
			f.to = argv[i]
		case "--only":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("%s needs a comma-separated list of catalog ids", a)
			}
			i++
			f.only = splitList(argv[i])
		case "--skip":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("%s needs a comma-separated list of catalog ids", a)
			}
			i++
			f.skip = splitList(argv[i])
		case "--verbose", "-v":
			f.verbose = true
		case "-o", "--out":
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("%s needs a path", a)
			}
			i++
			f.out = argv[i]
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown flag %q", a)
			}
			f.args = append(f.args, a)
		}
	}
	return f, nil
}

// filterEntries applies --only and --skip to the catalog.
//
// These were previously accepted by capture and silently ignored, so someone
// narrowing a bundle deliberately — the likeliest reason to reach for the flag —
// got a full-catalog bundle and no warning. An unknown id is an error rather
// than a no-op, because a typo would otherwise widen the capture without saying
// so.
func filterEntries(entries []catalog.Entry, only, skip []string) ([]catalog.Entry, error) {
	if len(only) == 0 && len(skip) == 0 {
		return entries, nil
	}
	known := map[string]bool{}
	for _, e := range entries {
		known[e.ID] = true
	}
	for _, id := range append(append([]string{}, only...), skip...) {
		if !known[id] {
			return nil, fmt.Errorf("no catalog entry %q (try `macstash catalog`)", id)
		}
	}

	inOnly := map[string]bool{}
	for _, id := range only {
		inOnly[id] = true
	}
	inSkip := map[string]bool{}
	for _, id := range skip {
		inSkip[id] = true
	}

	var out []catalog.Entry
	for _, e := range entries {
		if len(inOnly) > 0 && !inOnly[e.ID] {
			continue
		}
		if inSkip[e.ID] {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// splitList parses a comma-separated flag value.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func run(argv []string) error {
	if len(argv) == 0 || argv[0] == "help" || argv[0] == "--help" || argv[0] == "-h" {
		fmt.Print(usage)
		return nil
	}
	cmd := argv[0]
	f, err := parse(argv[1:])
	if err != nil {
		return err
	}

	switch cmd {
	case "capture":
		return cmdCapture(f)
	case "inspect":
		return cmdInspect(f)
	case "restore":
		return cmdRestore(f)
	case "doctor":
		return cmdDoctor(f)
	case "catalog":
		return cmdCatalog(f)
	case "clone":
		return cmdClone(f)
	case "backups":
		return cmdBackups(f)
	case "export":
		return cmdExport(f)
	case "version":
		fmt.Printf("macstash %s\n", Version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `macstash help`)", cmd)
	}
}

func cmdCapture(f *flags) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("capture reads macOS-specific locations and only runs on macOS")
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run as root")
	}
	// Re-exec under a profile that denies network access. Capture needs none, so
	// denying it makes "this tool does not phone home" structural.
	if err := capture.ReExecSandboxed(); err != nil {
		return fmt.Errorf("entering the no-network sandbox: %w", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	entries, err := catalog.Load()
	if err != nil {
		return err
	}
	entries, err = filterEntries(entries, f.only, f.skip)
	if err != nil {
		return err
	}
	plan, err := capture.Scan(home, entries)
	if err != nil {
		return err
	}

	if adv := plan.Management.Advisory(); adv != "" {
		fmt.Fprint(os.Stderr, adv)
	}

	if f.plan {
		// Read, scrub and scan without writing, so the plan reports the same
		// scanner findings a real capture would.
		if _, err := plan.Analyse(); err != nil {
			return err
		}
		printCapturePlan(plan, f.unredacted, f.verbose)
		fmt.Println("\nNothing was written. Re-run without --plan to create the bundle.")
		return nil
	}

	brew, brewErr := capture.DumpBrewfile()
	if brewErr != nil {
		// A machine with no Homebrew still deserves a bundle; a Homebrew that
		// produced an untrustworthy Brewfile does not.
		if brewErr != capture.ErrNoBrew {
			return brewErr
		}
		fmt.Fprintln(os.Stderr, "note: Homebrew is not installed, so no Brewfile was captured.")
	}
	plan.Brew = brew

	// Selection runs after the Brewfile dump so formulae and casks can be pruned
	// too, and before anything is written so an abort costs nothing.
	if f.selectItems || f.selectionFile != "" {
		doc := plan.SelectionDocument()
		chosen, err := resolveSelection(doc, f, filepath.Join(home, ".macstash"))
		if err != nil {
			return err
		}
		plan.ApplySelection(chosen)
		before, total := doc.Counts()
		after, _ := chosen.Counts()
		fmt.Printf("Selection: keeping %d of %d items (%d excluded).\n", after, total, before-after)
	}

	out := f.out
	if out == "" {
		host, _ := os.Hostname()
		host = strings.SplitN(host, ".", 2)[0]
		name := fmt.Sprintf("macstash-%s-%s", sanitize(host), time.Now().Format("2006-01-02"))
		out = filepath.Join(home, "macstash", name+".tar.gz")
	}
	if err := checkCloudSync(home, out, f.force); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}

	staging, err := os.MkdirTemp("", "macstash-capture-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)

	u, _ := user.Current()
	host, _ := os.Hostname()
	w, err := bundle.NewWriter(filepath.Join(staging, "bundle"), bundle.Source{
		Hostname: host,
		Username: username(u),
		OS:       osVersion(),
		Arch:     runtime.GOARCH,
		Shell:    os.Getenv("SHELL"),
		Version:  Version,
	})
	if err != nil {
		return err
	}
	if err := plan.Write(w); err != nil {
		return err
	}
	if err := w.Finish(time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := bundle.Archive(w.Root(), out); err != nil {
		return err
	}

	printCapturePlan(plan, f.unredacted, f.verbose)
	fmt.Printf("\nBundle written to %s\n", out)
	fmt.Printf("Transfer it with AirDrop or a USB drive, then on the new Mac run:\n")
	fmt.Printf("  macstash restore %s\n", filepath.Base(out))
	return nil
}

func printCapturePlan(p *capture.Plan, unredacted, verbose bool) {
	fmt.Printf("Detected %d tools: %s\n", len(p.Detected), strings.Join(p.Detected, ", "))
	fmt.Printf("Files to capture: %d\n", len(p.Files))
	if s := p.BrewSummary(); s != "" {
		fmt.Printf("Homebrew: %s\n", s)
	}

	scrubbed := 0
	for _, f := range p.Files {
		if f.Class == "scrub" {
			scrubbed++
		}
	}
	if scrubbed > 0 {
		fmt.Printf("Files captured with credentials removed: %d\n", scrubbed)
	}

	if verbose {
		fmt.Println("\nFiles:")
		for _, f := range p.Files {
			fmt.Printf("  %-7s %s\n", f.Class, f.Rel)
		}
	}

	if len(p.Files) > 0 {
		fmt.Println()
		fmt.Print(scanner.Summary(p.ScanFindings))
	}

	if managed := capture.ManagedApps(p.Applications); len(managed) > 0 {
		fmt.Printf("\nManaged by your employer's device management: %s\n", strings.Join(managed, ", "))
		fmt.Println("  Restoring will not try to reinstall these — the MDM owns them, and a second")
		fmt.Println("  Homebrew copy would fight it for updates.")
	}

	printApplications(p.Applications, p.BrewConsulted, verbose)
	printRepos(p.Repos, unredacted, verbose)
	printMCPServers(p.System.MCPServers)

	if len(p.Excluded) > 0 {
		fmt.Printf("\nFound and deliberately not captured (%d):\n", len(p.Excluded))
		shown := 0
		for _, e := range p.Excluded {
			if !verbose && shown >= 12 {
				fmt.Printf("  ... and %d more (--verbose to list)\n", len(p.Excluded)-shown)
				break
			}
			fmt.Printf("  %-42s %s\n", e.Rel, e.Reason)
			shown++
		}
		fmt.Println("\nThese are credentials and history. You will re-authenticate these tools on\nthe new machine; that is the trade this tool makes on purpose.")
	}
}

// printApplications reports the application inventory, leading with the apps a
// restore cannot bring back. On a typical Mac that is most of them: Homebrew
// only knows about software Homebrew installed, and everything that arrived as a
// disk image or from the App Store is invisible to `brew bundle`.
func printApplications(apps []bundle.App, brewConsulted, verbose bool) {
	if len(apps) == 0 {
		return
	}
	var manual, byBrew, fromStore, system []bundle.App
	for _, a := range apps {
		switch a.Source {
		case capture.SourceHomebrew:
			byBrew = append(byBrew, a)
		case capture.SourceAppStore:
			fromStore = append(fromStore, a)
		case capture.SourceSystem:
			system = append(system, a)
		default:
			manual = append(manual, a)
		}
	}

	// Not being installed by Homebrew is not the same as not being installable
	// by it. Most apps that arrived as a disk image have a cask, and saying
	// "reinstall these ten by hand" when nine of them are one command away is a
	// failure of the tool rather than a fact about the machine.
	var byCask, unmanaged []bundle.App
	for _, a := range manual {
		if a.CaskToken != "" {
			byCask = append(byCask, a)
		} else {
			unmanaged = append(unmanaged, a)
		}
	}

	fmt.Printf("\nApplications: %d found — %d already managed by Homebrew, %d more Homebrew can\n"+
		"              install, %d from the App Store, %d needing a manual download,\n"+
		"              %d shipped with macOS\n",
		len(apps), len(byBrew), len(byCask), len(fromStore), len(unmanaged), len(system))

	if !brewConsulted {
		fmt.Println("  warning: brew could not be run, so Homebrew-installed apps could not be\n" +
			"           told apart from hand-installed ones. The list below is over-long.")
	}

	if len(byCask) > 0 {
		fmt.Printf("\nThese %d were installed by hand, but Homebrew has a cask for them, so a\nrestore can put them back (`restore --apply --install-apps`):\n", len(byCask))
		printAppList(byCask, verbose, true)
	}

	// Software an employer pushes is not the user's to reinstall. Hand-installing
	// a VPN client or an endpoint agent produces an unenrolled copy that reports
	// to nothing, which is worse than not having it.
	agents := map[string]bool{}
	for _, n := range capture.EnterpriseAgents(apps) {
		agents[n] = true
	}
	var byIT, byHand []bundle.App
	for _, a := range unmanaged {
		if agents[a.Name] {
			byIT = append(byIT, a)
		} else {
			byHand = append(byHand, a)
		}
	}

	if len(byIT) > 0 {
		fmt.Printf("\nThese %d look like software your employer deploys. Do not reinstall them\nby hand — a copy you install yourself is enrolled in nothing:\n", len(byIT))
		printAppList(byIT, verbose, false)
	}

	if len(byHand) > 0 {
		fmt.Printf("\nThese %d have no Homebrew cask and must be reinstalled by hand — macstash\nnever downloads from URLs, so it lists them instead:\n", len(byHand))
		printAppList(byHand, verbose, false)
	}
}

// printAppList prints app names, capped unless --verbose. The cap has to
// announce itself: a truncated list that looks complete is how someone finishes
// a migration believing they are done.
func printAppList(apps []bundle.App, verbose, withToken bool) {
	shown := 0
	for _, a := range apps {
		if !verbose && shown >= 15 {
			fmt.Printf("  ... and %d more (--verbose to list)\n", len(apps)-shown)
			return
		}
		v := a.Version
		if v != "" {
			v = "  (" + v + ")"
		}
		if withToken {
			fmt.Printf("  %-32s %s\n", a.Name+v, "brew install --cask "+a.CaskToken)
		} else {
			fmt.Printf("  %s%s\n", a.Name, v)
		}
		shown++
	}
}

// printAppInstallHint mentions the flag when it would actually do something,
// and stays quiet when it would not.
func printAppInstallHint(apps []bundle.App) {
	n := 0
	for _, a := range apps {
		if a.CaskToken != "" && a.Source != capture.SourceHomebrew && a.Source != capture.SourceSystem {
			n++
		}
	}
	if n == 0 {
		return
	}
	fmt.Printf("\n%d recorded application(s) can be installed with Homebrew. Re-run with\n"+
		"--install-apps to do that.\n", n)
}

// printMCPServers lists configured MCP servers.
//
// The definitions are never captured, so this is a rebuild checklist. The env
// variable names are the point: "postgres needs DATABASE_URI" is the fact that
// is genuinely hard to reconstruct months later, and it carries no secret.
func printMCPServers(servers []bundle.MCPServer) {
	if len(servers) == 0 {
		return
	}
	fmt.Printf("\nMCP servers: %d configured (definitions are never captured — they hold\n"+
		"             credentials inline, in env, args, URLs and headers)\n", len(servers))

	source := ""
	for _, m := range servers {
		if m.Source != source {
			source = m.Source
			fmt.Printf("  %s\n", source)
		}
		how := m.Command
		if m.Package != "" {
			how += " " + m.Package
		}
		if m.Host != "" {
			how = m.Transport + " " + m.Host
		}
		fmt.Printf("    %-18s %s\n", m.Name, how)
		if len(m.EnvKeys) > 0 {
			fmt.Printf("    %-18s needs: %s\n", "", strings.Join(m.EnvKeys, ", "))
		}
	}
	fmt.Println("\n  Re-add these by hand on the new machine; the values they need are in\n" +
		"  your password manager or each service's dashboard, not in this bundle.")
}

// printRepos reports git working trees, leading with the ones that would lose
// work. A repository with no remote, or with commits that were never pushed,
// exists only on the machine being replaced.
func printRepos(repos []bundle.Repo, unredacted, verbose bool) {
	if len(repos) == 0 {
		return
	}
	atRisk := capture.RepoRisks(repos)
	fmt.Printf("\nGit repositories: %d found (contents are never captured — remote, branch and\n"+
		"                  path only, so they can be cloned again)\n", len(repos))

	// Remotes are redacted below, but the paths beside them are not, and a
	// checkout directory is usually named after the repository. Hiding the host
	// while printing "inception-k8s-deployment-prod" protects nothing, so say so
	// rather than implying a safety the output does not have. macstash cannot
	// know which names matter; the person reading can.
	if !unredacted {
		fmt.Println("\n  Remote URLs are hidden below, but the paths are not, and a directory name\n" +
			"  usually is the repository name. Treat this section as internal: it is a\n" +
			"  list of what you work on, whatever the URLs say.")
	}

	if len(atRisk) > 0 {
		fmt.Printf("\n  %d hold work that exists nowhere else. Deal with these BEFORE you wipe\n  the old machine:\n", len(atRisk))
		for _, r := range atRisk {
			var why []string
			if r.NoRemote {
				why = append(why, "NO REMOTE")
			}
			if r.Dirty {
				why = append(why, "uncommitted changes")
			}
			if r.Unpushed > 0 {
				why = append(why, fmt.Sprintf("%d unpushed commit(s)", r.Unpushed))
			}
			if r.NoUpstream && !r.NoRemote {
				why = append(why, "branch tracks no upstream")
			}
			fmt.Printf("    %-46s %s\n", r.Path, strings.Join(why, ", "))
		}
	}
	if verbose {
		fmt.Println("\n  All repositories:")
		for _, r := range repos {
			remote := redact.Apply(r.Remote, unredacted)
			if r.Remote == "" {
				remote = "(no remote)"
			}
			fmt.Printf("    %-46s %s\n", r.Path, remote)
		}
	}
}

func cmdInspect(f *flags) error {
	if len(f.args) != 1 {
		return fmt.Errorf("usage: macstash inspect <bundle.tar.gz>")
	}
	man, err := bundle.ReadManifest(f.args[0])
	if err != nil {
		return err
	}

	fmt.Printf("Bundle:     %s\n", f.args[0])
	fmt.Printf("Captured:   %s\n", man.CreatedAt)
	fmt.Printf("From:       %s@%s (%s, %s)\n", man.Source.Username, man.Source.Hostname, man.Source.OS, man.Source.Arch)
	fmt.Printf("Schema:     %d (macstash %s)\n", man.SchemaVersion, man.Source.Version)
	fmt.Printf("Files:      %d\n", len(man.Items))
	if man.Brewfile != nil {
		fmt.Printf("Homebrew:   %d formulae, %d casks, %d taps\n",
			man.Brewfile.Formulae, man.Brewfile.Casks, man.Brewfile.Taps)
	}

	if n := len(man.Applications); n > 0 {
		manual := 0
		for _, a := range man.Applications {
			if a.Source != capture.SourceHomebrew && a.Source != capture.SourceSystem {
				manual++
			}
		}
		fmt.Printf("Apps:       %d (%d need manual reinstall)\n", n, manual)
	}
	if n := len(man.Repos); n > 0 {
		fmt.Printf("Repos:      %d (%d with work that exists nowhere else)\n", n, len(capture.RepoRisks(man.Repos)))
	}

	if len(man.Applications) > 0 {
		printApplications(man.Applications, man.Brewfile != nil, f.verbose)
	}
	if len(man.Repos) > 0 {
		printRepos(man.Repos, f.unredacted, f.verbose)
		printMCPServers(man.System.MCPServers)
	}

	fmt.Println()
	fmt.Print(scanner.Summary(man.ScanFindings))

	if len(man.Scrubs) > 0 {
		fmt.Printf("\nCredentials removed at capture — re-authenticate these:\n")
		for _, s := range man.Scrubs {
			fmt.Printf("  %-28s %s (%d)\n", s.File, s.Reason, s.Count)
		}
	}
	if len(man.Excluded) > 0 {
		fmt.Printf("\nSeen and not captured (%d):\n", len(man.Excluded))
		for _, e := range man.Excluded {
			fmt.Printf("  %-42s %s\n", e.Rel, e.Reason)
		}
	}
	if len(man.Notes) > 0 {
		fmt.Printf("\nRestore notes:\n")
		for _, n := range man.Notes {
			fmt.Printf("  [%s] %s\n", n.Entry, strings.ReplaceAll(strings.TrimSpace(n.Text), "\n", "\n        "))
		}
	}
	if f.verbose {
		fmt.Printf("\nFile list:\n")
		for _, i := range man.Items {
			fmt.Printf("  %-7s %s\n", i.Class, i.Rel)
		}
	}
	return nil
}

func cmdRestore(f *flags) error {
	if len(f.args) != 1 {
		return fmt.Errorf("usage: macstash restore <bundle.tar.gz> [--apply]")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	p, cleanup, err := restore.Prepare(f.args[0], home)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := restore.Preflight(p.Manifest, f.fromOtherUser); err != nil {
		return err
	}
	if f.fromOtherUser {
		fmt.Print(restore.CodeExecutionWarning(p.Manifest))
	}

	p.Filter(f.only, f.skip)

	// Selection runs after --only/--skip so the file reflects what is actually
	// on the table, and before the plan is printed so the counts are honest.
	selectedApps, selectedRepos := p.Manifest.Applications, p.Manifest.Repos
	if f.selectItems || f.selectionFile != "" {
		doc := restore.SelectionDocument(p, home)
		chosen, err := resolveSelection(doc, f, filepath.Join(home, ".macstash"))
		if err != nil {
			return err
		}
		selectedApps, selectedRepos = restore.ApplySelection(p, chosen)
		if s := restore.Summary(chosen); s != "" {
			fmt.Println(s)
		}
	}

	if len(p.BlockedApps) > 0 {
		fmt.Println("These applications are running and rewrite their own configuration when")
		fmt.Println("they quit, so restoring underneath them would be silently undone:")
		for _, b := range p.BlockedApps {
			if restore.RunningInside(b) {
				fmt.Printf("  %s — %s\n", b.Name, restore.HostTerminalAdvice(b))
				continue
			}
			fmt.Printf("  %s — quit it, then re-run (restore is safe to repeat)\n", b.Name)
		}
		fmt.Println()
	}

	counts := p.Counts()
	fmt.Printf("Restore plan for %s\n", f.args[0])
	fmt.Printf("  create:    %d\n", counts[restore.Create])
	fmt.Printf("  overwrite: %d  (backed up to ~/%s/)\n", counts[restore.Overwrite], restore.BackupDir)
	fmt.Printf("  unchanged: %d\n", counts[restore.Unchanged])
	if n := counts[restore.Refused]; n > 0 {
		fmt.Printf("  refused:   %d\n", n)
	}

	for _, a := range p.Actions {
		switch a.Kind {
		case restore.Refused:
			fmt.Printf("  REFUSED  %-38s %s\n", a.Rel, a.Reason)
		case restore.Unchanged:
			if f.verbose {
				fmt.Printf("  unchanged %s\n", a.Rel)
			}
		default:
			fmt.Printf("  %-9s %s\n", string(a.Kind), a.Rel)
		}
	}

	// A fresh Mac — the tool's whole scenario — has no Homebrew yet. Aborting
	// here used to skip the entire restore: no dotfiles, no prefs, no manifest,
	// so `doctor` afterwards reported that no restore had ever happened. Nothing
	// below this point needs brew, and every step is idempotent, so the right
	// move is to say so and carry on. The user installs brew and re-runs to pick
	// up the packages.
	skipBrewfile := false
	if p.HasBrewfile {
		if err := restore.CheckHomebrew(p.Manifest); err != nil {
			fmt.Print("\n" + restore.HomebrewInstallMessage)
			fmt.Println("Continuing with everything that does not need Homebrew.")
			skipBrewfile = true
		} else {
			fmt.Printf("\nBrewfile: %d formulae, %d casks, %d taps to install\n",
				p.Manifest.Brewfile.Formulae, p.Manifest.Brewfile.Casks, p.Manifest.Brewfile.Taps)
		}
	}

	if !f.apply {
		p.RestoreSDKs(os.Stdout, false)
		p.RestoreToolchains(os.Stdout, false)
		p.RestoreExtensions(os.Stdout, false)
		if f.installApps {
			if err := restore.InstallApps(selectedApps, false, os.Stdout); err != nil {
				return err
			}
		} else {
			printAppInstallHint(selectedApps)
		}
		if f.cloneRepos {
			if err := restore.CloneRepos(home, selectedRepos, false, os.Stdout); err != nil {
				return err
			}
		}
		p.ReportOnly(os.Stdout)
		// No offerBundleDeletion here. --plan must not change anything, and
		// offering a destructive action from a dry run is exactly the kind of
		// surprise the flag exists to rule out.
		if err := restore.RestoreLaunchAgents(home, p.Manifest.LaunchAgents, p.Staging, f.launchAgents, false, os.Stdout); err != nil {
			return err
		}
		if c := restore.PermissionChecklist(p.Manifest.Requirements); c != "" {
			fmt.Print(c)
		}
		fmt.Println("\nNothing was changed. Re-run with --apply to restore.")
		return nil
	}

	fmt.Println("\nApplying...")

	// The sequence follows plan §7. Every step is idempotent, so a failure at
	// step nine does not mean starting again from step one.
	restore.EnsureXcodeTools(os.Stdout)
	restore.EnsureRosetta(os.Stdout)

	if p.HasBrewfile && !skipBrewfile {
		if err := p.InstallBrewfile(os.Stdout); err != nil {
			return err
		}
	}
	if f.installApps {
		if err := restore.InstallApps(selectedApps, true, os.Stdout); err != nil {
			return err
		}
	}
	p.RestoreSDKs(os.Stdout, true)

	stamp := time.Now().Format("2006-01-02T15-04-05")
	if err := p.Apply(home, stamp, os.Stdout); err != nil {
		return err
	}
	if err := p.RestorePrefs(os.Stdout); err != nil {
		return err
	}
	p.RestoreExtensions(os.Stdout, true)
	p.RestoreToolchains(os.Stdout, f.installToolchains)

	if err := p.WriteManifest(home); err != nil {
		return fmt.Errorf("writing %s: %w", restore.ManifestPath, err)
	}
	fmt.Printf("\nRecorded this restore at ~/%s — `macstash doctor` diffs against it.\n", restore.ManifestPath)

	if err := restore.RestoreLaunchAgents(home, p.Manifest.LaunchAgents, p.Staging, f.launchAgents, true, os.Stdout); err != nil {
		return err
	}
	p.ReportOnly(os.Stdout)

	// Cloning is last on purpose: it is the only step that needs credentials
	// macstash deliberately never captured, so it is the most likely to fail and
	// the least damaging to fail late.
	if f.cloneRepos {
		if err := restore.CloneRepos(home, selectedRepos, true, os.Stdout); err != nil {
			return err
		}
	} else if n := len(selectedRepos); n > 0 {
		fmt.Printf("\n%d repository(ies) recorded. `macstash clone %s` clones them, or\n"+
			"re-run restore with --clone-repos.\n", n, f.args[0])
	}

	if !f.installApps {
		printAppInstallHint(selectedApps)
	}
	offerBundleDeletion(f.args[0], f.yes)

	if len(p.Manifest.Scrubs) > 0 {
		fmt.Printf("\nRe-authenticate these — the credentials were removed at capture:\n")
		for _, s := range p.Manifest.Scrubs {
			fmt.Printf("  %-28s %s\n", s.File, s.Reason)
		}
	}
	if c := restore.PermissionChecklist(p.Manifest.Requirements); c != "" {
		fmt.Print(c)
	}

	if len(p.Manifest.Notes) > 0 {
		fmt.Printf("\nNotes:\n")
		for _, n := range p.Manifest.Notes {
			fmt.Printf("  [%s] %s\n", n.Entry, strings.ReplaceAll(strings.TrimSpace(n.Text), "\n", "\n        "))
		}
	}
	return nil
}

// checkCloudSync refuses to drop a bundle into a folder that syncs to somebody
// else's servers. A bundle is a concentrated picture of one machine; uploading it
// is not a decision to make by accident.
// resolveSelection turns --select or --selection into a chosen document.
//
// The file is written under ~/.macstash rather than a temporary directory so it
// survives the run: a selection is worth keeping, and after a parse error the
// user needs somewhere to go and fix it.
func resolveSelection(doc selection.Document, f *flags, dir string) (selection.Document, error) {
	if doc.Empty() {
		return doc, nil
	}
	var chosen selection.Document
	var err error
	if f.selectionFile != "" {
		chosen, err = selection.Load(f.selectionFile, doc)
	} else {
		chosen, err = selection.Edit(doc, dir)
	}
	if err == selection.ErrCancelled {
		return selection.Document{}, errNothingSelected
	}
	if err != nil {
		return selection.Document{}, err
	}
	// A saved file that selects nothing means the same as an emptied one. Both
	// reach here; without this the --selection path would quietly perform a
	// restore that writes nothing and report it as success.
	if selected, _ := chosen.Counts(); selected == 0 {
		return selection.Document{}, errNothingSelected
	}
	return chosen, nil
}

var errNothingSelected = fmt.Errorf(
	"nothing was left selected, so nothing was done.\n" +
		"Emptying the selection file is the documented way to cancel; re-run to try again")

func checkCloudSync(home, out string, force bool) error {
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	synced := []struct{ path, service string }{
		{filepath.Join(home, "Library/Mobile Documents"), "iCloud Drive"},
		{filepath.Join(home, "Library/CloudStorage"), "a cloud storage provider"},
		{filepath.Join(home, "Dropbox"), "Dropbox"},
		{filepath.Join(home, "OneDrive"), "OneDrive"},
		{filepath.Join(home, "Google Drive"), "Google Drive"},
	}
	for _, s := range synced {
		if abs == s.path || strings.HasPrefix(abs, s.path+string(filepath.Separator)) {
			if force {
				fmt.Fprintf(os.Stderr, "warning: writing a bundle into %s, which syncs off this machine.\n", s.service)
				return nil
			}
			return fmt.Errorf(
				"%s is synced by %s.\n\n"+
					"A bundle is a concentrated picture of your machine, and writing it here uploads\n"+
					"it. Choose a local path with -o, or pass --force if you meant to.", abs, s.service)
		}
	}
	return nil
}

func sanitize(s string) string {
	if s == "" {
		return "mac"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		default:
			return '-'
		}
	}, s)
}

func username(u *user.User) string {
	if u == nil {
		return ""
	}
	return u.Username
}

func osVersion() string {
	data, err := os.ReadFile("/System/Library/CoreServices/SystemVersion.plist")
	if err != nil {
		return runtime.GOOS
	}
	s := string(data)
	const key = "<key>ProductVersion</key>"
	i := strings.Index(s, key)
	if i < 0 {
		return runtime.GOOS
	}
	rest := s[i+len(key):]
	start := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if start < 0 || end < start {
		return runtime.GOOS
	}
	return "macOS " + rest[start+len("<string>"):end]
}

// cmdDoctor diffs the live machine against the manifest the last restore wrote.
func cmdDoctor(f *flags) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var man *bundle.Manifest
	if len(f.args) == 1 {
		// Allow doctor against a bundle directly, for checking before restoring.
		man, err = bundle.ReadManifest(f.args[0])
	} else {
		man, err = restore.LoadLiveManifest(home)
		if err != nil && os.IsNotExist(err) {
			return fmt.Errorf(
				"no restore has been recorded on this machine.\n\n"+
					"doctor compares against ~/%s, which `macstash restore --apply` writes.\n"+
					"To check a bundle without restoring it: macstash doctor <bundle.tar.gz>",
				restore.ManifestPath)
		}
	}
	if err != nil {
		return err
	}

	fmt.Printf("Checking this machine against the capture from %s\n\n", man.CreatedAt)
	checks := doctor.Run(home, man, f.deep)
	fmt.Print(doctor.Summarise(checks))

	if !f.deep {
		fmt.Println("Run `macstash doctor --deep` to actually exercise the toolchain rather")
		fmt.Println("than only compare it against the manifest.")
	}
	return nil
}

// cmdCatalog lists what macstash knows about.
func cmdCatalog(f *flags) error {
	entries, err := catalog.Load()
	if err != nil {
		return err
	}

	if len(f.args) == 2 && f.args[0] == "show" {
		for _, e := range entries {
			if e.ID != f.args[1] {
				continue
			}
			fmt.Printf("%s (%s)\n  category: %s\n", e.Name, e.ID, e.Category)
			fmt.Println("  captures:")
			for _, p := range e.Capture.Paths {
				fmt.Printf("    %-7s %s\n", p.Class, p.Path)
				for _, r := range p.Scrub {
					fmt.Printf("            removes: %s\n", r.Reason)
				}
			}
			for _, d := range e.Capture.Defaults {
				fmt.Printf("    prefs   %s\n", d.Domain)
			}
			if e.Restore.QuitFirst {
				fmt.Println("  must be quit before restore: yes")
			}
			if len(e.Restore.Permissions) > 0 {
				fmt.Printf("  needs permissions: %s\n", strings.Join(e.Restore.Permissions, ", "))
			}
			if e.Restore.Note != "" {
				fmt.Printf("  note: %s\n", strings.ReplaceAll(strings.TrimSpace(e.Restore.Note), "\n", "\n        "))
			}
			return nil
		}
		return fmt.Errorf("no catalog entry %q (try `macstash catalog`)", f.args[1])
	}

	byCategory := map[string][]catalog.Entry{}
	for _, e := range entries {
		byCategory[e.Category] = append(byCategory[e.Category], e)
	}
	var cats []string
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	fmt.Printf("%d catalog entries. Each is a small YAML file; contributing one is a\nfifteen-line pull request.\n\n", len(entries))
	for _, c := range cats {
		fmt.Printf("%s\n", c)
		for _, e := range byCategory[c] {
			fmt.Printf("  %-12s %s\n", e.ID, e.Name)
		}
	}
	fmt.Println("\n`macstash catalog show <id>` prints one entry in full.")
	return nil
}

// cmdClone re-clones recorded repositories.
func cmdClone(f *flags) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	var man *bundle.Manifest
	if len(f.args) == 1 {
		man, err = bundle.ReadManifest(f.args[0])
	} else {
		man, err = restore.LoadLiveManifest(home)
		if err != nil && os.IsNotExist(err) {
			return fmt.Errorf("no recorded restore; pass a bundle: macstash clone <bundle.tar.gz>")
		}
	}
	if err != nil {
		return err
	}
	return restore.CloneRepos(home, man.Repos, f.apply, os.Stdout)
}

// cmdBackups applies retention to displaced files.
func cmdBackups(f *flags) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if !f.prune {
		backups, err := restore.ListBackups(home)
		if err != nil {
			return err
		}
		if len(backups) == 0 {
			fmt.Println("No backups. Restore moves anything it would overwrite into ~/.macstash/backups/.")
			return nil
		}
		fmt.Printf("%d backup(s) in ~/%s:\n", len(backups), restore.BackupDir)
		for _, b := range backups {
			fmt.Printf("  %s  %d files\n", b.Name, b.Files)
		}
		fmt.Println("\n`macstash backups --prune` removes those older than 30 days.")
		return nil
	}
	return restore.PruneBackups(home, restore.DefaultRetentionDays, f.apply, os.Stdout)
}

// cmdExport converts a bundle into another tool's format.
//
// macstash is a starting point, not a place to live. Someone who has used it to
// move machines should be able to graduate to a properly managed dotfiles setup
// without doing the work twice, so exporting hands off rather than locking in.
func cmdExport(f *flags) error {
	if len(f.args) != 1 {
		return fmt.Errorf("usage: macstash export <bundle.tar.gz> --to brewfile|chezmoi")
	}
	if f.out == "" {
		return fmt.Errorf("export needs an output path: -o <dir-or-file>")
	}

	staging, err := os.MkdirTemp("", "macstash-export-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err := bundle.Extract(f.args[0], staging); err != nil {
		return err
	}

	switch f.to {
	case "brewfile":
		data, err := os.ReadFile(filepath.Join(staging, "Brewfile"))
		if err != nil {
			return fmt.Errorf("this bundle has no Brewfile")
		}
		if err := os.WriteFile(f.out, data, 0o600); err != nil {
			return err
		}
		fmt.Printf("Brewfile written to %s\n  brew bundle install --file=%s\n", f.out, f.out)
		return nil

	case "chezmoi":
		// chezmoi's source layout renames a leading dot to "dot_".
		src := filepath.Join(staging, "home")
		count := 0
		err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(src, p)
			if err != nil {
				return err
			}
			parts := strings.Split(filepath.ToSlash(rel), "/")
			for i, seg := range parts {
				if strings.HasPrefix(seg, ".") {
					parts[i] = "dot_" + seg[1:]
				}
			}
			dest := filepath.Join(f.out, filepath.FromSlash(strings.Join(parts, "/")))
			if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			count++
			return os.WriteFile(dest, data, 0o600)
		})
		if err != nil {
			return err
		}
		fmt.Printf("chezmoi source directory written to %s (%d files)\n", f.out, count)
		fmt.Printf("  chezmoi init --source %s\n  chezmoi diff\n", f.out)
		return nil

	default:
		return fmt.Errorf("unknown export format %q (brewfile or chezmoi)", f.to)
	}
}

// offerBundleDeletion offers to remove the bundle once a restore has succeeded.
//
// There is deliberately no "secure delete" here and no claim of one. On an APFS
// SSD, overwriting a file does not reliably destroy the old blocks — the drive's
// controller may have already written elsewhere — and Time Machine local
// snapshots can retain a copy regardless. Pretending otherwise would be the
// worst kind of security theatre: a promise that makes someone comfortable
// carrying a bundle around on a USB stick. FileVault is the control that
// actually protects this data at rest.
func offerBundleDeletion(path string, assumeYes bool) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	fmt.Printf("\nThe bundle is still at %s (%d KB).\n", path, info.Size()/1024)
	fmt.Println("It contains no credentials, but it is a detailed picture of your setup.")

	if assumeYes {
		fmt.Println("Left in place (--yes does not delete anything).")
		return
	}

	fmt.Print("Delete it now? [y/N] ")
	var answer string
	if _, err := fmt.Scanln(&answer); err != nil {
		fmt.Println("\nLeft in place.")
		return
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		fmt.Println("Left in place.")
		return
	}
	if err := os.Remove(path); err != nil {
		fmt.Printf("Could not delete it: %v\n", err)
		return
	}
	fmt.Println("Deleted.")
	fmt.Println("Note: this is an ordinary delete. On an APFS SSD the underlying blocks may")
	fmt.Println("survive, and a Time Machine local snapshot may still hold a copy. FileVault")
	fmt.Println("is what actually protects this data at rest.")
}
