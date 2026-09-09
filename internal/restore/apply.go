package restore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/redact"
)

// ActionKind is what restore intends to do with one file.
type ActionKind string

const (
	// Create writes a file that is not currently present.
	Create ActionKind = "create"
	// Overwrite replaces existing content, after backing it up.
	Overwrite ActionKind = "overwrite"
	// Unchanged means the live file already matches the bundle. Re-running a
	// restore should be quiet, not noisy, so these are counted and not listed.
	Unchanged ActionKind = "unchanged"
	// Refused means the bundle asked for something restore will not do.
	Refused ActionKind = "refused"
)

// Action is one planned change.
type Action struct {
	Rel   string
	Kind  ActionKind
	Class classify.Class
	// Mode is the owner permission recorded at capture. Without it a restored
	// script arrives without its execute bit and fails the first time it runs.
	Mode   uint32
	Reason string
}

// Plan is a fully-resolved restore, computed before anything is written.
type Plan struct {
	Manifest *bundle.Manifest
	Actions  []Action
	Staging  string
	// HasBrewfile is true when the bundle carries packages to install.
	HasBrewfile bool
	// BlockedApps are applications that must be quit before their configuration
	// can be restored.
	BlockedApps []bundle.Requirement
}

// Prepare extracts a bundle to a staging directory and works out what applying it
// would change. It writes nothing into the home directory. The returned cleanup
// function removes the staging tree.
func Prepare(archive, home string) (*Plan, func(), error) {
	staging, err := os.MkdirTemp("", "macstash-restore-")
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { os.RemoveAll(staging) }

	if err := bundle.Extract(archive, staging); err != nil {
		cleanup()
		return nil, nil, err
	}
	man, err := bundle.ReadManifest(archive)
	if err != nil {
		cleanup()
		return nil, nil, err
	}

	p := &Plan{
		Manifest:    man,
		Staging:     staging,
		HasBrewfile: man.Brewfile != nil,
	}

	// Work out which entries cannot be restored yet because their application is
	// running and would overwrite the result on quit.
	p.BlockedApps = BlockedByRunningApp(man.Requirements, RunningApps())
	blockedEntry := map[string]string{}
	blockedReq := map[string]bundle.Requirement{}
	for _, b := range p.BlockedApps {
		blockedEntry[b.Entry] = b.Name
		blockedReq[b.Entry] = b
	}

	for _, item := range man.Items {
		src := filepath.Join(staging, "home", filepath.FromSlash(item.Rel))

		if name, blocked := blockedEntry[item.Entry]; blocked {
			p.Actions = append(p.Actions, Action{
				Rel: item.Rel, Kind: Refused,
				Reason: blockedReason(name, blockedReq[item.Entry]),
			})
			continue
		}

		// The never list runs on the way out of a bundle as well as on the way in.
		// Extract already refused these, so reaching here means the manifest and
		// the archive disagree, which is itself worth reporting rather than
		// quietly ignoring.
		if never, reason := classify.IsNever(item.Rel); never {
			p.Actions = append(p.Actions, Action{Rel: item.Rel, Kind: Refused, Reason: reason})
			continue
		}

		content, err := os.ReadFile(src)
		if err != nil {
			p.Actions = append(p.Actions, Action{
				Rel: item.Rel, Kind: Refused, Reason: "listed in the manifest but missing from the archive",
			})
			continue
		}
		// A checksum mismatch means the bundle was altered after capture. Restore
		// says so instead of applying it.
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); item.SHA256 != "" && got != item.SHA256 {
			p.Actions = append(p.Actions, Action{
				Rel: item.Rel, Kind: Refused, Reason: "checksum does not match the manifest; the bundle was modified after capture",
			})
			continue
		}

		kind := Create
		if live, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(item.Rel))); err == nil {
			switch {
			case bytes.Equal(live, content):
				kind = Unchanged
			case len(content) == 0 && len(live) > 0:
				// An empty file has nothing to restore, so writing it over a file
				// that has content can only destroy. This is not hypothetical: a
				// migration replaced a .zprofile holding the Homebrew shellenv
				// line with the empty one from the old machine, and brew left the
				// PATH of every new login shell. The backup held it, but the plan
				// said "overwrite" and gave no hint that the incoming side was
				// blank.
				//
				// Creating an empty file is still allowed. A zero-byte file whose
				// existence is the whole point — .hushlogin is the usual one — has
				// no live content to lose.
				p.Actions = append(p.Actions, Action{
					Rel: item.Rel, Kind: Refused, Class: item.Class, Mode: item.Mode,
					Reason: "empty in the bundle but not here; keeping what this machine has",
				})
				continue
			default:
				kind = Overwrite
			}
		}
		p.Actions = append(p.Actions, Action{Rel: item.Rel, Kind: kind, Class: item.Class, Mode: item.Mode})
	}
	return p, cleanup, nil
}

// Filter narrows a plan to the given catalog entry ids. only and skip are the
// --only and --skip flag values; an empty only means "everything".
func (p *Plan) Filter(only, skip []string) {
	if len(only) == 0 && len(skip) == 0 {
		return
	}
	inOnly := map[string]bool{}
	for _, id := range only {
		inOnly[id] = true
	}
	inSkip := map[string]bool{}
	for _, id := range skip {
		inSkip[id] = true
	}

	byRel := map[string]string{}
	for _, item := range p.Manifest.Items {
		byRel[item.Rel] = item.Entry
	}

	kept := p.Actions[:0]
	for _, a := range p.Actions {
		entry := byRel[a.Rel]
		if len(inOnly) > 0 && !inOnly[entry] {
			continue
		}
		if inSkip[entry] {
			continue
		}
		kept = append(kept, a)
	}
	p.Actions = kept
}

// Counts summarises the plan.
func (p *Plan) Counts() map[ActionKind]int {
	c := map[ActionKind]int{}
	for _, a := range p.Actions {
		c[a.Kind]++
	}
	return c
}

// Apply writes the planned files. stamp names the backup directory for this run.
func (p *Plan) Apply(home, stamp string, out io.Writer) error {
	var written, backed int

	for _, a := range p.Actions {
		switch a.Kind {
		case Unchanged, Refused:
			continue
		}

		target := filepath.Join(home, filepath.FromSlash(a.Rel))
		if a.Kind == Overwrite {
			dst, err := backupFile(home, stamp, a.Rel)
			if err != nil {
				return fmt.Errorf("backing up %s: %w", a.Rel, err)
			}
			backed++
			fmt.Fprintf(out, "  backed up %s -> %s\n", a.Rel, shortenHome(home, dst))
		}

		src := filepath.Join(p.Staging, "home", filepath.FromSlash(a.Rel))
		content, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		// Honour the captured mode. ~/bin and ~/.local/bin exist in the catalog
		// precisely to carry personal scripts across, and a script restored
		// without its execute bit is a permission-denied error the first time
		// the user reaches for it — weeks after the restore reported success.
		mode := os.FileMode(a.Mode).Perm() & 0o700
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(target, content, mode); err != nil {
			return err
		}
		// WriteFile only applies mode when it creates the file, so an overwrite
		// keeps whatever permissions were already there.
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
		written++
		fmt.Fprintf(out, "  %-9s %s\n", string(a.Kind), a.Rel)
	}

	fmt.Fprintf(out, "\n%d files written, %d backed up to ~/%s/%s\n",
		written, backed, BackupDir, stamp)
	return nil
}

// InstallBrewfile runs brew bundle install against the staged Brewfile.
//
// It continues past individual package failures: on a real machine a couple of
// casks will always fail for reasons that have nothing to do with this tool, and
// abandoning the other two hundred packages because of them would be absurd.
func (p *Plan) InstallBrewfile(out io.Writer) error {
	brewfile := filepath.Join(p.Staging, "Brewfile")
	if _, err := os.Stat(brewfile); err != nil {
		return nil
	}
	// List third-party taps before installing anything from them. A tap is a
	// source of arbitrary install code, and Homebrew will happily run a cask's
	// postflight script; whose code is about to run is worth showing first.
	if data, err := os.ReadFile(brewfile); err == nil {
		var taps []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "tap ") {
				continue
			}
			if strings.Contains(line, "homebrew/") {
				continue // official
			}
			taps = append(taps, redact.TapURL(line))
		}
		if len(taps) > 0 {
			fmt.Fprintf(out, "\nThird-party Homebrew taps in this bundle. Their formulae run install code\non your machine, so check you recognise them:\n")
			for _, t := range taps {
				fmt.Fprintf(out, "  %s\n", t)
			}
		}
	}

	fmt.Fprintf(out, "\nInstalling packages with brew bundle (this reaches the network)...\n")

	cmd := exec.Command("brew", "bundle", "install", "--file="+brewfile, "--no-upgrade")
	cmd.Env = append(os.Environ(), "HOMEBREW_NO_ANALYTICS=1", "HOMEBREW_NO_ENV_HINTS=1")
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(out,
			"\nbrew bundle reported failures (%v). This is common and usually affects only a\n"+
				"few packages. Re-running the restore is safe and will retry them.\n", err)
	}
	return nil
}

func shortenHome(home, p string) string {
	if rel, err := filepath.Rel(home, p); err == nil {
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}

// blockedReason explains a refusal, distinguishing the case where the app to be
// quit is the terminal the user is standing in.
func blockedReason(name string, req bundle.Requirement) string {
	if RunningInside(req) {
		return name + " is running and rewrites its config on quit — run macstash from a different terminal"
	}
	return name + " is running and rewrites its config on quit — quit it and re-run"
}
