package bundle

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aroranikhil786/macstash/internal/classify"
)

// Extraction limits. A bundle is configuration, not data; anything past these is
// either a mistake or an attack, and in both cases stopping is correct.
const (
	maxEntries = 20000
	// MaxFileBytes is exported because capture must honour the same ceiling.
	// Capture writing a file that Extract then refuses would produce a bundle
	// that cannot be restored, which is exactly the bug this shared constant
	// prevents — and did, when ~/.local/bin turned out to hold a 64MB binary.
	MaxFileBytes  = 64 << 20 // 64 MiB
	maxFileBytes  = MaxFileBytes
	maxTotalBytes = 512 << 20 // 512 MiB
)

// Extract unpacks a macstash tarball into dest.
//
// The safety argument here rests on capture dereferencing symlinks, so a
// well-formed bundle contains only regular files and directories. That lets
// extraction allowlist exactly those two entry types, which disposes of symlink
// escape, hardlink escape, device nodes, FIFOs and setuid transfer in a single
// condition rather than by enumerating each attack and hoping the list is
// complete. Path traversal and permission bits are handled explicitly below.
//
// Extended attributes are dropped by construction: PAX records are read but never
// applied, so no quarantine or provenance attribute rides along.
func Extract(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("not a gzip archive: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(dest)
	if err != nil {
		return err
	}

	tr := tar.NewReader(gz)
	var entries int
	var total int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		entries++
		if entries > maxEntries {
			return fmt.Errorf("archive has more than %d entries; refusing", maxEntries)
		}

		// Entry type allowlist. Everything that is not a plain file or a directory
		// is refused by name so the error tells the user what was in there.
		switch hdr.Typeflag {
		case tar.TypeReg, tar.TypeDir:
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("archive contains a link (%s); macstash bundles never contain links", hdr.Name)
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("archive contains a device or FIFO node (%s); refusing", hdr.Name)
		default:
			return fmt.Errorf("archive contains unsupported entry type %q (%s); refusing", hdr.Typeflag, hdr.Name)
		}

		target, err := safeJoin(root, hdr.Name)
		if err != nil {
			return err
		}

		// Defence in depth: a bundle is a file and can be hand-edited, and
		// restoring another user's bundle is supported. The never list is applied
		// on the way out of an archive as well as on the way in.
		if rel, ok := underHome(hdr.Name); ok {
			if never, reason := classify.IsNever(rel); never {
				return fmt.Errorf("archive contains %s, which is on the never list (%s); refusing", hdr.Name, reason)
			}
		}

		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}

		if hdr.Size > maxFileBytes {
			return fmt.Errorf("%s is larger than %d bytes; refusing", hdr.Name, maxFileBytes)
		}
		total += hdr.Size
		if total > maxTotalBytes {
			return fmt.Errorf("archive expands past %d bytes; refusing", maxTotalBytes)
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		// Owner bits only. This strips setuid, setgid and the sticky bit, so they
		// cannot survive a round trip through a bundle, while keeping the execute
		// bit so a captured script is still runnable. Group and other are dropped
		// because nothing in a personal bundle should be world-readable.
		mode := os.FileMode(hdr.Mode).Perm() & 0o700
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		// LimitReader guards against a header that understates the payload.
		if _, err := io.Copy(out, io.LimitReader(tr, maxFileBytes+1)); err != nil {
			out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}

// safeJoin resolves name under root and refuses anything that would land outside
// it, whether by absolute path, by .. traversal, or by a root that is itself
// reached through a link.
func safeJoin(root, name string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(clean) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("archive contains an absolute path (%s); refusing", name)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive contains a path traversal (%s); refusing", name)
	}
	if strings.Contains(name, "\x00") {
		return "", fmt.Errorf("archive contains a NUL byte in a path; refusing")
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry %s escapes the extraction root; refusing", name)
	}
	return target, nil
}

// underHome maps an in-archive path to a $HOME-relative path, for the entries
// that live under the bundle's home/ tree.
func underHome(name string) (string, bool) {
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(name)), "./")
	const prefix = "home/"
	if !strings.HasPrefix(clean, prefix) {
		return "", false
	}
	return strings.TrimPrefix(clean, prefix), true
}
