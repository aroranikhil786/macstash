package bundle

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aroranikhil786/macstash/internal/classify"
	"github.com/aroranikhil786/macstash/internal/scanner"
	"github.com/aroranikhil786/macstash/internal/scrub"
)

// Writer builds a bundle directory. Everything it creates is owner-only: the
// bundle is a concentrated picture of one person's machine and has no business
// being readable by anyone else on the box.
type Writer struct {
	root string
	man  Manifest
}

// NewWriter creates the bundle skeleton at root.
func NewWriter(root string, src Source) (*Writer, error) {
	for _, d := range []string{root, filepath.Join(root, "home"), filepath.Join(root, "manifests")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Writer{
		root: root,
		man: Manifest{
			SchemaVersion: SchemaVersion,
			Source:        src,
		},
	}, nil
}

// Root returns the bundle directory.
func (w *Writer) Root() string { return w.root }

// AddHomeFile stores content at home/<rel> and indexes it.
func (w *Writer) AddHomeFile(entry, rel string, content []byte, mode os.FileMode, class classify.Class) error {
	if never, reason := classify.IsNever(rel); never {
		// Should be unreachable: capture filters first. Belt and braces, because
		// the cost of being wrong here is the entire point of the project.
		return fmt.Errorf("refusing to write never-listed path %s (%s) into a bundle", rel, reason)
	}
	target := filepath.Join(w.root, "home", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(target, content, mode.Perm()&0o700); err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	w.man.Items = append(w.man.Items, Item{
		Entry:  entry,
		Rel:    rel,
		Class:  class,
		Mode:   uint32(mode.Perm() & 0o700),
		Size:   int64(len(content)),
		SHA256: hex.EncodeToString(sum[:]),
	})
	return nil
}

// AddRootFile stores a top-level bundle file such as the Brewfile.
func (w *Writer) AddRootFile(name string, content []byte) error {
	return os.WriteFile(filepath.Join(w.root, name), content, 0o600)
}

// RecordScrubs appends scrub audit records to the manifest.
func (w *Writer) RecordScrubs(records []scrub.Record) {
	w.man.Scrubs = append(w.man.Scrubs, records...)
}

// RecordExcluded notes a path that the never list kept out.
func (w *Writer) RecordExcluded(rel, reason string) {
	w.man.Excluded = append(w.man.Excluded, Excluded{Rel: rel, Reason: reason})
}

// RecordNote attaches a restore caveat from a catalog entry.
func (w *Writer) RecordNote(entry, text string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	w.man.Notes = append(w.man.Notes, Note{Entry: entry, Text: text})
}

// SetBrew records the Brewfile summary counts.
func (w *Writer) SetBrew(b Brew) { w.man.Brewfile = &b }

// RecordScanFindings stores secret-scanner output in the manifest.
func (w *Writer) RecordScanFindings(f []scanner.Finding) {
	w.man.ScanFindings = append(w.man.ScanFindings, f...)
}

// RecordRequirement stores a catalog entry's restore preconditions.
func (w *Writer) RecordRequirement(r Requirement) {
	if !r.QuitFirst && len(r.Permissions) == 0 && r.Category == "" {
		return
	}
	w.man.Requirements = append(w.man.Requirements, r)
}

// AddPrefDomain stores an exported preference domain under prefs/.
func (w *Writer) AddPrefDomain(domain string, data []byte) error {
	dir := filepath.Join(w.root, "prefs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, domain+".plist"), data, 0o600)
}

// SetSystem records the list-shaped inventory, both in the manifest and as a
// standalone file under manifests/ that can be read without tooling.
func (w *Writer) SetSystem(s System) error {
	w.man.System = s
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.root, "manifests", "system.json"), append(data, '\n'), 0o600)
}

// SetInventory records the application and repository inventories, both in the
// manifest and as standalone files under manifests/, so they can be read
// without a JSON parser when someone is halfway through setting up a new laptop.
func (w *Writer) SetInventory(apps []App, repos []Repo) {
	w.man.Applications = apps
	w.man.Repos = repos
}

// Manifest exposes the manifest under construction.
func (w *Writer) Manifest() *Manifest { return &w.man }

// Finish writes the manifest. createdAt is passed in rather than read from the
// clock so that callers control timestamp formatting and tests stay reproducible.
func (w *Writer) Finish(createdAt string) error {
	w.man.CreatedAt = createdAt
	data, err := json.MarshalIndent(w.man, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.root, ManifestName), append(data, '\n'), 0o600)
}

// Archive packs a bundle directory into a gzipped tar at out.
//
// Only regular files and directories are written. Capture dereferences symlinks
// precisely so that this is true, which is what lets Extract refuse every other
// entry type outright.
func Archive(dir, out string) error {
	f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			// A bundle directory should never contain anything else; if it somehow
			// does, leave it out rather than encode it.
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Uid, hdr.Gid = 0, 0
		hdr.Uname, hdr.Gname = "", ""
		hdr.Mode = int64(info.Mode().Perm() & 0o700)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(tw, src)
		return err
	})
}

// ReadManifest reads macstash.json out of a bundle tarball without extracting
// anything, which is what makes `inspect` safe to run on a bundle you do not
// trust yet.
func ReadManifest(archive string) (*Manifest, error) {
	f, err := os.Open(archive)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("no %s in archive", ManifestName)
		}
		if err != nil {
			return nil, err
		}
		if filepath.ToSlash(filepath.Clean(hdr.Name)) != ManifestName {
			continue
		}
		var m Manifest
		if err := json.NewDecoder(io.LimitReader(tr, maxFileBytes)).Decode(&m); err != nil {
			return nil, fmt.Errorf("manifest is not valid JSON: %w", err)
		}
		return &m, nil
	}
}
