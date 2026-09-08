// Package capture scans a Mac and produces a bundle.
//
// Capture is allowlist-only. It looks at the paths named by catalog entries and
// nowhere else. There is no wholesale sweep of ~/.config or ~/Library/Application
// Support, because a sweep plus an exclude list is always one release behind the
// next CLI that decides to keep a token in a config directory.
package capture

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/catalog"
	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/scanner"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

// Planned is one file capture intends to collect.
type Planned struct {
	Entry string
	Rel   string
	Abs   string
	Class classify.Class
	Mode  os.FileMode
	Size  int64
	Rules []scrub.Rule
}

// Plan is the full result of scanning a machine: what would be captured, what
// was found and deliberately left out, and why.
type Plan struct {
	Home         string
	Detected     []string
	Files        []Planned
	Excluded     []bundle.Excluded
	Notes        []bundle.Note
	Requirements []bundle.Requirement
	// Applications is every app on the machine, tagged with whether a restore
	// can reinstall it. Most of them, on a real Mac, it cannot.
	Applications []bundle.App
	// Repos is what it would take to clone each working tree back.
	Repos []bundle.Repo
	// System is the list-shaped inventory: runtime versions, global packages,
	// editor extensions, login items.
	System bundle.System
	// Prefs maps a preference domain to its exported plist. Domains are exported
	// only when a catalog entry names them.
	Prefs map[string][]byte
	// ScanFindings is secret-scanner output over everything captured.
	ScanFindings []scanner.Finding
	// LaunchAgents are background jobs found on the machine.
	LaunchAgents []bundle.LaunchAgent
	// Management is the corporate-device advisory, if any.
	Management Management
	// BrewConsulted is false when brew could not be run, in which case the
	// application inventory cannot tell Homebrew casks from hand-installed apps.
	BrewConsulted bool
	Brew          *BrewResult
	// BrewErr is recorded rather than returned so that a machine without Homebrew
	// still produces a useful bundle.
	BrewErr error
}

// Scan walks the catalog against a home directory and decides what to capture.
// It reads no file contents; that happens later, and only for paths that survive
// classification.
func Scan(home string, entries []catalog.Entry) (*Plan, error) {
	p := &Plan{Home: home}
	seen := make(map[string]bool)

	for _, e := range entries {
		found := false
		for _, cp := range e.Capture.Paths {
			abs := expand(home, cp.Path)
			info, err := os.Lstat(abs)
			if err != nil {
				continue // not on this machine
			}
			found = true

			if info.IsDir() {
				if err := p.walkDir(home, e, cp, abs, seen); err != nil {
					return nil, err
				}
				continue
			}
			p.consider(home, e, cp, abs, seen)
		}
		if found {
			p.Detected = append(p.Detected, e.ID)
			p.Notes = append(p.Notes, bundle.Note{Entry: e.ID, Text: strings.TrimSpace(e.Restore.Note)})
			p.Requirements = append(p.Requirements, bundle.Requirement{
				Entry:       e.ID,
				Name:        e.Name,
				QuitFirst:   e.Restore.QuitFirst,
				Permissions: e.Restore.Permissions,
				Category:    e.Category,
			})
		}
	}

	p.probeCredentials(home)
	p.dedupeExcluded()

	// Applications and repositories are inventory rather than captured files:
	// nothing is copied, but a migration is not usable without knowing what was
	// installed by hand and which trees hold unpushed work.
	casks, brewKnown := CaskTokens()
	p.Applications = ScanApplications(casks)
	p.BrewConsulted = brewKnown
	p.Repos = ScanRepos(home, 4)
	p.System = ScanSystem(home)
	p.Management = DetectManagement()
	p.LaunchAgents = ScanLaunchAgents(home)
	p.exportPrefs(entries)

	sort.Slice(p.Files, func(i, j int) bool { return p.Files[i].Rel < p.Files[j].Rel })
	sort.Slice(p.Excluded, func(i, j int) bool { return p.Excluded[i].Rel < p.Excluded[j].Rel })
	return p, nil
}

// walkDir descends a catalog-named directory. Naming a directory in the catalog
// is what authorises capture of the files inside it; nothing else is reachable.
func (p *Plan) walkDir(home string, e catalog.Entry, cp catalog.Path, dir string, seen map[string]bool) error {
	return filepath.WalkDir(dir, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable path is usually TCC refusing us, not a bug. Record it
			// and keep going: a partial capture the user is told about beats an
			// aborted one.
			p.Excluded = append(p.Excluded, bundle.Excluded{
				Rel: relOrAbs(home, abs), Reason: "unreadable: " + err.Error(),
			})
			return nil
		}
		if d.IsDir() {
			if matchesAny(relTo(dir, abs), cp.Skip) {
				return filepath.SkipDir
			}
			return nil
		}
		if matchesAny(relTo(dir, abs), cp.Skip) {
			return nil
		}
		p.consider(home, e, cp, abs, seen)
		return nil
	})
}

// consider classifies one candidate file and either plans it or records why not.
func (p *Plan) consider(home string, e catalog.Entry, cp catalog.Path, abs string, seen map[string]bool) {
	rel, ok := homeRel(home, abs)
	if !ok {
		p.Excluded = append(p.Excluded, bundle.Excluded{Rel: abs, Reason: "outside $HOME"})
		return
	}
	if seen[rel] {
		return
	}

	v := classify.Resolve(home, abs, cp.Class)
	if v.Class == classify.Never {
		seen[rel] = true
		p.Excluded = append(p.Excluded, bundle.Excluded{Rel: rel, Reason: v.Reason})
		return
	}

	// Stat rather than Lstat: a symlink is dereferenced, so what lands in the
	// bundle is always a plain file. Extraction depends on that being true.
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return
	}

	limit := cp.MaxSize
	if limit <= 0 {
		limit = bundle.MaxFileBytes
	}
	if info.Size() > limit {
		seen[rel] = true
		p.Excluded = append(p.Excluded, bundle.Excluded{
			Rel:    rel,
			Reason: fmt.Sprintf("larger than %d MB — too big for a config bundle", limit>>20),
		})
		return
	}
	if cp.TextOnly && isBinary(abs) {
		seen[rel] = true
		p.Excluded = append(p.Excluded, bundle.Excluded{
			Rel: rel, Reason: "binary, not a script — reinstall it with the tool that put it there",
		})
		return
	}

	seen[rel] = true
	p.Files = append(p.Files, Planned{
		Entry: e.ID, Rel: rel, Abs: abs,
		Class: v.Class, Mode: info.Mode(), Size: info.Size(),
		Rules: cp.Scrub,
	})
}

// Write reads the planned files, scrubs what needs scrubbing, and fills a bundle.
func (p *Plan) Write(w *bundle.Writer) error {
	for _, f := range p.Files {
		content, err := os.ReadFile(f.Abs)
		if err != nil {
			return fmt.Errorf("reading %s: %w", f.Rel, err)
		}

		if f.Class == classify.Scrub {
			cleaned, records, err := scrub.Apply(content, f.Rules, f.Rel)
			if err != nil {
				// Failing to scrub is never survivable: passing the file through
				// unscrubbed is exactly the outcome the class exists to prevent.
				return fmt.Errorf("scrubbing %s: %w", f.Rel, err)
			}
			content = cleaned
			w.RecordScrubs(records)
		}

		// Scan what is actually going into the bundle, after scrubbing. Scanning
		// the original would report credentials that the scrub already removed,
		// and a report full of already-handled findings is a report nobody reads.
		p.ScanFindings = append(p.ScanFindings, scanner.Scan(content, f.Rel)...)

		if err := w.AddHomeFile(f.Entry, f.Rel, content, f.Mode, f.Class); err != nil {
			return err
		}
	}
	w.RecordScanFindings(p.ScanFindings)

	for _, ex := range p.Excluded {
		w.RecordExcluded(ex.Rel, ex.Reason)
	}
	for _, n := range p.Notes {
		w.RecordNote(n.Entry, n.Text)
	}
	for _, r := range p.Requirements {
		w.RecordRequirement(r)
	}
	if p.Brew != nil {
		if err := w.AddRootFile("Brewfile", p.Brew.Content); err != nil {
			return err
		}
		w.SetBrew(p.Brew.Counts)
	}
	w.SetInventory(p.Applications, p.Repos)

	for domain, data := range p.Prefs {
		if err := w.AddPrefDomain(domain, data); err != nil {
			return err
		}
	}
	if err := w.SetSystem(p.System); err != nil {
		return err
	}
	if err := w.SetLaunchAgents(p.LaunchAgents); err != nil {
		return err
	}
	// LaunchAgent plists routinely carry tokens in EnvironmentVariables, so they
	// are scanned too. These findings are recorded separately because the agents
	// are stored outside the home/ tree.
	var agentFindings []scanner.Finding
	for _, a := range p.LaunchAgents {
		agentFindings = append(agentFindings, scanner.Scan(a.Content, "LaunchAgents/"+a.File)...)
	}
	p.ScanFindings = append(p.ScanFindings, agentFindings...)
	w.RecordScanFindings(agentFindings)
	return nil
}

// exportPrefs exports the preference domains named by detected catalog entries,
// plus the curated NSGlobalDomain key allowlist.
func (p *Plan) exportPrefs(entries []catalog.Entry) {
	p.Prefs = map[string][]byte{}
	detected := map[string]bool{}
	for _, id := range p.Detected {
		detected[id] = true
	}

	for _, e := range entries {
		if !detected[e.ID] {
			continue
		}
		for _, d := range e.Capture.Defaults {
			if data, ok := ExportDomain(d.Domain); ok {
				p.Prefs[d.Domain] = data
				p.System.Prefs = append(p.System.Prefs, d.Domain)
			}
		}
	}

	if data, n := ExportNSGlobal(); n > 0 {
		p.Prefs["NSGlobalDomain"] = data
		p.System.Prefs = append(p.System.Prefs, fmt.Sprintf("NSGlobalDomain (%d allowlisted keys)", n))
	}
	sort.Strings(p.System.Prefs)
}

// ManualAppCount is how many applications a restore cannot reinstall by itself.
func (p *Plan) ManualAppCount() int { return len(ManualApps(p.Applications)) }

// BrewSummary renders the Brewfile counts for the report.
func (p *Plan) BrewSummary() string {
	if p.Brew == nil {
		return ""
	}
	return formatCounts(p.Brew.Counts)
}

// isBinary reports whether a file looks like a compiled executable rather than a
// script, by checking for a NUL byte in its first block.
func isBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 8000)
	n, _ := f.Read(buf)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}

func expand(home, p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func homeRel(home, abs string) (string, bool) {
	rel, err := filepath.Rel(home, abs)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func relOrAbs(home, abs string) string {
	if rel, ok := homeRel(home, abs); ok {
		return rel
	}
	return abs
}

func relTo(dir, abs string) string {
	rel, err := filepath.Rel(dir, abs)
	if err != nil {
		return filepath.Base(abs)
	}
	return filepath.ToSlash(rel)
}

// matchesAny reports whether a path relative to a captured directory matches any
// skip pattern.
//
// A pattern containing no slash matches a basename at any depth, the way
// .gitignore behaves. Without that, "*.log" only ever matches logs sitting at the
// top of the tree, which is never what the person writing the catalog entry
// meant.
func matchesAny(rel string, globs []string) bool {
	base := path.Base(rel)
	for _, g := range globs {
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		if !strings.Contains(g, "/") {
			if ok, _ := path.Match(g, base); ok {
				return true
			}
		}
		if rel == g || strings.HasPrefix(rel, g+"/") {
			return true
		}
		// A directory pattern also excludes everything beneath it.
		if i := strings.Index(rel, "/"); i >= 0 {
			for _, prefix := range dirPrefixes(rel) {
				if ok, _ := path.Match(g, prefix); ok {
					return true
				}
			}
		}
	}
	return false
}

// dirPrefixes returns each directory prefix of rel.
func dirPrefixes(rel string) []string {
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// probeCredentials records which known credential locations exist on this
// machine, without reading any of them. The result is a re-authentication
// checklist: these are the things that will not work on the new Mac until the
// user signs in again, and naming them at capture time is the difference between
// a planned half hour and an unplanned afternoon.
func (p *Plan) probeCredentials(home string) {
	for _, c := range classify.KnownCredentialPaths() {
		abs := filepath.Join(home, filepath.FromSlash(c.Rel))
		if _, err := os.Lstat(abs); err != nil {
			continue
		}
		p.Excluded = append(p.Excluded, bundle.Excluded{
			Rel:    c.Rel,
			Reason: c.Reason + " (found, deliberately not captured)",
		})
	}

	// SSH private keys are matched by rule rather than by a fixed path, so they
	// need their own probe. They are also the single most consequential thing to
	// name: a developer who is not told their keys did not come across will find
	// out from a git push that fails on the new machine.
	dir := filepath.Join(home, ".ssh")
	names, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, n := range names {
		if n.IsDir() {
			continue
		}
		if never, reason := classify.IsNever(".ssh/" + n.Name()); never {
			p.Excluded = append(p.Excluded, bundle.Excluded{
				Rel:    ".ssh/" + n.Name(),
				Reason: reason + " (found, deliberately not captured)",
			})
		}
	}
}

// dedupeExcluded collapses paths reported by both the directory walk and the
// credential probe, keeping the first reason recorded.
func (p *Plan) dedupeExcluded() {
	seen := make(map[string]bool, len(p.Excluded))
	out := p.Excluded[:0]
	for _, e := range p.Excluded {
		if seen[e.Rel] {
			continue
		}
		seen[e.Rel] = true
		out = append(out, e)
	}
	p.Excluded = out
}
