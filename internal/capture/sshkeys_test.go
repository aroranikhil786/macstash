package capture

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// A real key, so the fingerprint below is one OpenSSH would agree with. The
// private half was never generated; only the public line matters here.
const ed25519Pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJx8VJ7vDBrDLLZ4kQCbHzUuGx0m5rE0qBnhqoV1lQZa teddy@example"

func writeSSH(t *testing.T, home, name, content string) string {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The fingerprint has to be the one ssh-keygen prints, or it identifies nothing
// on GitHub's key list. Computed here from the wire format rather than by
// shelling out, so this test checks the arithmetic against the real tool.
func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	home := t.TempDir()
	path := writeSSH(t, home, "id_ed25519.pub", ed25519Pub+"\n")

	got, ok := parsePublicKey(ed25519Pub)
	if !ok {
		t.Fatal("the key did not parse")
	}

	out, err := exec.Command("ssh-keygen", "-lf", path).Output()
	if err != nil {
		t.Skipf("ssh-keygen unavailable: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		t.Fatalf("unexpected ssh-keygen output %q", out)
	}
	if got.Fingerprint != fields[1] {
		t.Errorf("fingerprint = %q, ssh-keygen says %q", got.Fingerprint, fields[1])
	}
	if got.Type != "ED25519" {
		t.Errorf("type = %q, want ED25519", got.Type)
	}
	if got.Comment != "teddy@example" {
		t.Errorf("comment = %q, want teddy@example", got.Comment)
	}
}

func TestParsePublicKeyRejectsRubbish(t *testing.T) {
	for _, in := range []string{"", "ssh-ed25519", "ssh-ed25519 not-base64!!"} {
		if _, ok := parsePublicKey(in); ok {
			t.Errorf("parsePublicKey(%q) should have failed", in)
		}
	}
}

// A key with no private file beside it is agent-backed, and telling its owner
// to regenerate it would be wrong advice.
func TestKeyWithNoPrivateFileIsMarkedAsSuch(t *testing.T) {
	home := t.TempDir()
	writeSSH(t, home, "id_ed25519.pub", ed25519Pub+"\n")

	keys := scanPublicKeys(filepath.Join(home, ".ssh"))

	if len(keys) != 1 {
		t.Fatalf("keys = %+v, want one", keys)
	}
	if keys[0].HasPrivate {
		t.Error("no private key file exists, so HasPrivate must be false")
	}

	writeSSH(t, home, "id_ed25519", "not really a key")
	keys = scanPublicKeys(filepath.Join(home, ".ssh"))
	if !keys[0].HasPrivate {
		t.Error("a private key file sits beside it, so HasPrivate must be true")
	}
}

// https remotes authenticate with a token. Counting them would send someone to
// add an SSH key to a server that does not use one.
func TestOnlySSHRemotesCount(t *testing.T) {
	cases := map[string]string{
		"git@github.com:owner/repo.git":            "github.com",
		"ssh://git@ssh.github.com:443/owner/repo":  "ssh.github.com",
		"ssh://gerrit.internal/project":            "gerrit.internal",
		"https://github.com/owner/repo.git":        "",
		"git://github.com/owner/repo.git":          "",
		"https://user:token@github.com/owner/repo": "",
		"": "",
	}
	for remote, want := range cases {
		if got := sshRemoteHost(remote); got != want {
			t.Errorf("sshRemoteHost(%q) = %q, want %q", remote, got, want)
		}
	}
}

func TestParseSSHConfigTakesHostnameUserAndIdentity(t *testing.T) {
	home := t.TempDir()
	writeSSH(t, home, "config", `
# a comment
Host *
  ServerAliveInterval 60
  IdentityFile ~/.ssh/id_default

Host bastion jump
  HostName bastion.internal.example
  User nikhil
  IdentityFile ~/.ssh/id_rsa

Host=shorthand
  HostName=short.example
`)

	got := parseSSHConfig(filepath.Join(home, ".ssh", "config"))

	byHost := map[string]sshConfigHost{}
	for _, h := range got {
		byHost[h.host] = h
	}
	// "Host *" is a rule, not a machine: there is nowhere to paste a key.
	if _, ok := byHost["*"]; ok {
		t.Error("a wildcard pattern must not be offered as a host")
	}
	b, ok := byHost["bastion.internal.example"]
	if !ok {
		t.Fatalf("hosts = %+v, want the bastion by its HostName", got)
	}
	if b.user != "nikhil" || b.identity != "id_rsa" {
		t.Errorf("got %+v, want user nikhil and identity id_rsa", b)
	}
	// Both aliases in one Host line resolve to the same HostName.
	if n := len(got); n != 3 {
		t.Errorf("got %d hosts, want 3 (two aliases plus the shorthand)", n)
	}
	if _, ok := byHost["short.example"]; !ok {
		t.Errorf("the Key=value form must parse too, got %+v", got)
	}
}

// Hashed hostnames cannot be reversed. Counting them is the only honest option;
// omitting them would present a partial list as a complete one.
func TestKnownHostsCountsWhatItCannotRead(t *testing.T) {
	home := t.TempDir()
	writeSSH(t, home, "known_hosts", strings.Join([]string{
		"github.com,140.82.121.4 ssh-ed25519 AAAAC3Nza",
		"|1|nzMBnGJhNMHc5F0hMSTVXQ0Ilw8=|9YyZ2xF6nA5CvhWq ssh-ed25519 AAAAC3Nza",
		"|1|otherhash=|second ssh-rsa AAAAB3Nza",
		"[bastion.example]:2222 ssh-rsa AAAAB3Nza",
		"@cert-authority *.example ssh-rsa AAAAB3Nza",
		"# a comment",
	}, "\n"))

	hosts, hashed := parseKnownHosts(filepath.Join(home, ".ssh", "known_hosts"))

	if hashed != 2 {
		t.Errorf("hashed = %d, want 2", hashed)
	}
	want := map[string]bool{"github.com": true, "140.82.121.4": true, "bastion.example": true}
	for _, h := range hosts {
		delete(want, h)
	}
	if len(want) > 0 {
		t.Errorf("missing hosts %v from %v", want, hosts)
	}
	// The port form must not produce a second entry for the same server.
	for _, h := range hosts {
		if strings.HasPrefix(h, "[") {
			t.Errorf("%q should have had its port form stripped", h)
		}
	}
}

// The whole point is one line per server, however many places named it.
func TestScanSSHUsageMergesSourcesPerHost(t *testing.T) {
	home := t.TempDir()
	writeSSH(t, home, "id_rsa.pub", ed25519Pub+"\n")
	writeSSH(t, home, "id_rsa", "private")
	writeSSH(t, home, "config", "Host github.com\n  HostName github.com\n  User git\n  IdentityFile ~/.ssh/id_rsa\n")
	writeSSH(t, home, "known_hosts", "github.com ssh-ed25519 AAAAC3Nza\n")
	repos := []bundle.Repo{
		{Path: "~/a", Remote: "git@github.com:o/a.git"},
		{Path: "~/b", Remote: "git@github.com:o/b.git"},
		{Path: "~/c", Remote: "https://github.com/o/c.git"},
	}

	keys, hosts, hidden := ScanSSHUsage(home, repos)

	if len(keys) != 1 || !keys[0].HasPrivate {
		t.Fatalf("keys = %+v, want one with a private half", keys)
	}
	if hidden != 0 {
		t.Errorf("hidden = %d, want 0", hidden)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %+v, want github.com merged into one entry", hosts)
	}
	h := hosts[0]
	if h.Repos != 2 {
		t.Errorf("repos = %d, want 2 — the https remote does not use a key", h.Repos)
	}
	if h.User != "git" || h.Identity != "id_rsa" {
		t.Errorf("got %+v, want the config details carried through", h)
	}
	if len(h.Sources) != 3 {
		t.Errorf("sources = %v, want all three", h.Sources)
	}
}

func TestScanSSHUsageOnAMachineWithNoSSHDirectory(t *testing.T) {
	keys, hosts, hidden := ScanSSHUsage(t.TempDir(), nil)

	if len(keys) != 0 || len(hosts) != 0 || hidden != 0 {
		t.Errorf("want nothing found, got %+v %+v %d", keys, hosts, hidden)
	}
}
