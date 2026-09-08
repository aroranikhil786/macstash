package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tarball builds a gzipped tar from the given headers and bodies. It writes
// whatever it is told to, including things a correct capture would never
// produce — that is the point.
func tarball(t *testing.T, entries ...func(*tar.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		e(tw)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func file(name, body string, mode int64) func(*tar.Writer) {
	return func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(body)),
		})
		_, _ = tw.Write([]byte(body))
	}
}

func special(typ byte, name, link string) func(*tar.Writer) {
	return func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Typeflag: typ, Name: name, Linkname: link, Mode: 0o600})
	}
}

func TestExtractRejectsMaliciousArchives(t *testing.T) {
	cases := []struct {
		name    string
		archive func(*testing.T) string
		wantErr string
	}{
		{
			name:    "absolute path",
			archive: func(t *testing.T) string { return tarball(t, file("/etc/passwd", "pwned", 0o600)) },
			wantErr: "absolute path",
		},
		{
			name:    "parent traversal",
			archive: func(t *testing.T) string { return tarball(t, file("../../escaped", "pwned", 0o600)) },
			wantErr: "traversal",
		},
		{
			name:    "traversal in the middle",
			archive: func(t *testing.T) string { return tarball(t, file("home/../../escaped", "pwned", 0o600)) },
			wantErr: "traversal",
		},
		{
			name:    "symlink",
			archive: func(t *testing.T) string { return tarball(t, special(tar.TypeSymlink, "home/.zshrc", "/etc/passwd")) },
			wantErr: "link",
		},
		{
			name:    "hardlink",
			archive: func(t *testing.T) string { return tarball(t, special(tar.TypeLink, "home/x", "/etc/passwd")) },
			wantErr: "link",
		},
		{
			name:    "device node",
			archive: func(t *testing.T) string { return tarball(t, special(tar.TypeChar, "home/dev", "")) },
			wantErr: "device",
		},
		{
			name:    "fifo",
			archive: func(t *testing.T) string { return tarball(t, special(tar.TypeFifo, "home/pipe", "")) },
			wantErr: "device",
		},
		{
			// A hand-edited bundle carrying a credential path must be refused on the
			// way out, not merely absent on the way in.
			name:    "never-listed path smuggled into a bundle",
			archive: func(t *testing.T) string { return tarball(t, file("home/.aws/credentials", "AKIAFAKE", 0o600)) },
			wantErr: "never list",
		},
		{
			name:    "smuggled private key",
			archive: func(t *testing.T) string { return tarball(t, file("home/.ssh/id_rsa", "KEY", 0o600)) },
			wantErr: "never list",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dest := t.TempDir()
			err := Extract(c.archive(t), dest)
			if err == nil {
				t.Fatalf("extraction succeeded; expected refusal containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, c.wantErr)
			}
		})
	}
}

// setuid must not survive a round trip.
func TestExtractStripsSetuidAndGroupBits(t *testing.T) {
	archive := tarball(t, file("home/bin/tool", "#!/bin/sh\n", 0o4777))
	dest := t.TempDir()
	if err := Extract(archive, dest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dest, "home/bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode()
	if mode&os.ModeSetuid != 0 {
		t.Errorf("setuid bit survived: %v", mode)
	}
	if mode.Perm()&0o077 != 0 {
		t.Errorf("group/other bits survived: %v", mode.Perm())
	}
	if mode.Perm()&0o100 == 0 {
		t.Errorf("owner execute bit was lost, a restored script would not run: %v", mode.Perm())
	}
}

func TestExtractAcceptsAWellFormedBundle(t *testing.T) {
	archive := tarball(t,
		file("macstash.json", `{"schema_version":1}`, 0o600),
		file("home/.zshrc", "export EDITOR=vim\n", 0o600),
		file("home/.gitconfig", "[user]\n\tname = Test\n", 0o600),
	)
	dest := t.TempDir()
	if err := Extract(archive, dest); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "home/.zshrc"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "export EDITOR=vim\n" {
		t.Errorf("content round-trip failed: %q", got)
	}
}
