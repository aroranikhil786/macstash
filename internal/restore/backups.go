package restore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DefaultRetentionDays is how long displaced files are kept before `backups
// --prune` will remove them.
const DefaultRetentionDays = 30

// Backup is one timestamped backup directory.
type Backup struct {
	Name  string
	Path  string
	When  time.Time
	Files int
	Bytes int64
}

// ListBackups enumerates ~/.macstash/backups.
func ListBackups(home string) ([]Backup, error) {
	root := filepath.Join(home, BackupDir)
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var out []Backup
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b := Backup{Name: e.Name(), Path: filepath.Join(root, e.Name())}
		// The directory name is the timestamp; fall back to mtime if it was
		// renamed by hand.
		if t, err := time.Parse("2006-01-02T15-04-05", e.Name()); err == nil {
			b.When = t
		} else if info, err := e.Info(); err == nil {
			b.When = info.ModTime()
		}
		_ = filepath.WalkDir(b.Path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr
			}
			b.Files++
			if info, err := d.Info(); err == nil {
				b.Bytes += info.Size()
			}
			return nil
		})
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.After(out[j].When) })
	return out, nil
}

// PruneBackups removes backups older than the retention window.
//
// It always keeps the most recent one regardless of age: a machine that was set
// up months ago and never touched since still deserves one undo step.
func PruneBackups(home string, days int, apply bool, out io.Writer) error {
	backups, err := ListBackups(home)
	if err != nil {
		return err
	}
	if len(backups) == 0 {
		fmt.Fprintln(out, "No backups to prune.")
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	var removed, kept int
	for i, b := range backups {
		if i == 0 || b.When.After(cutoff) {
			kept++
			fmt.Fprintf(out, "  keep   %s  (%d files, %s)\n", b.Name, b.Files, humanBytes(b.Bytes))
			continue
		}
		removed++
		fmt.Fprintf(out, "  remove %s  (%d files, %s, %d days old)\n",
			b.Name, b.Files, humanBytes(b.Bytes), int(time.Since(b.When).Hours()/24))
		if apply {
			if err := os.RemoveAll(b.Path); err != nil {
				return err
			}
		}
	}

	if !apply && removed > 0 {
		fmt.Fprintf(out, "\n%d backup(s) would be removed. Re-run with --apply.\n", removed)
	} else if apply {
		fmt.Fprintf(out, "\nRemoved %d, kept %d.\n", removed, kept)
	} else {
		fmt.Fprintf(out, "\nNothing older than %d days. Kept %d.\n", days, kept)
	}
	return nil
}

func humanBytes(n int64) string {
	switch {
	case n > 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n > 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
