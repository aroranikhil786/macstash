package restore

import (
	"io"
	"os"
	"path/filepath"
)

// BackupDir is where displaced files go, under the user's home.
const BackupDir = ".macstash/backups"

// backupFile copies an existing file into the backup tree before it is replaced,
// preserving its path structure so the backup is navigable rather than a heap of
// renamed files.
//
// It copies rather than moves: if the restore fails midway, the original is still
// in place and the machine is not left half-configured.
func backupFile(home, stamp, rel string) (string, error) {
	src := filepath.Join(home, filepath.FromSlash(rel))
	dst := filepath.Join(home, BackupDir, stamp, filepath.FromSlash(rel))

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return "", err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm()&0o700)
	if err != nil {
		return "", err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return "", err
	}
	return dst, out.Sync()
}
