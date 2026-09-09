package capture

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aroranikhil786/macstash/internal/bundle"
)

// ScanSSHUsage records which SSH keys existed and where they were used.
//
// Neither half of a keypair is carried. The private key never leaves the old
// machine, and the public key is no longer copied either: it cannot
// authenticate without its private half, and restoring it onto a new machine
// makes it look as though a working key is there. What survives is a
// fingerprint, which is a hash rather than a credential, and a list of the
// places that trusted the key — which is the part that is genuinely hard to
// reconstruct. Everything here is read from local files; nothing is looked up.
func ScanSSHUsage(home string, repos []bundle.Repo) (keys []bundle.SSHKey, hosts []bundle.SSHHost, hidden int) {
	dir := filepath.Join(home, ".ssh")
	keys = scanPublicKeys(dir)

	// Merged by host, because the same server usually appears in more than one
	// place and three lines saying the same thing is not three facts.
	byHost := map[string]*bundle.SSHHost{}
	add := func(host, source string) *bundle.SSHHost {
		host = strings.TrimSpace(host)
		if host == "" {
			return nil
		}
		h, ok := byHost[host]
		if !ok {
			h = &bundle.SSHHost{Host: host}
			byHost[host] = h
		}
		if source != "" && !contains(h.Sources, source) {
			h.Sources = append(h.Sources, source)
		}
		return h
	}

	for _, c := range parseSSHConfig(filepath.Join(dir, "config")) {
		h := add(c.host, "ssh config")
		if h == nil {
			continue
		}
		if c.user != "" {
			h.User = c.user
		}
		if c.identity != "" {
			h.Identity = c.identity
		}
	}

	known, hashed := parseKnownHosts(filepath.Join(dir, "known_hosts"))
	hidden = hashed
	for _, h := range known {
		add(h, "known_hosts")
	}

	// Only SSH remotes. An https remote authenticates with a token and does not
	// care about the key at all, so counting it would pad the list with servers
	// that need nothing done to them.
	repoCount := map[string]int{}
	for _, r := range repos {
		if host := sshRemoteHost(r.Remote); host != "" {
			repoCount[host]++
		}
	}
	for host, n := range repoCount {
		if h := add(host, fmt.Sprintf("%d repository(s) clone over SSH", n)); h != nil {
			h.Repos = n
		}
	}

	for _, h := range byHost {
		sort.Strings(h.Sources)
		hosts = append(hosts, *h)
	}
	// Hosts that hold repositories first: they are the ones with an obvious
	// place to paste the new key.
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Repos != hosts[j].Repos {
			return hosts[i].Repos > hosts[j].Repos
		}
		return hosts[i].Host < hosts[j].Host
	})
	return keys, hosts, hidden
}

// scanPublicKeys reads ~/.ssh/*.pub and reduces each to an identity.
func scanPublicKeys(dir string) []bundle.SSHKey {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var keys []bundle.SSHKey
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".pub") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		k, ok := parsePublicKey(string(data))
		if !ok {
			continue
		}
		k.Name = name
		// A public key with no private key file beside it was probably never a
		// file at all: 1Password, Secretive and hardware tokens hold the private
		// half themselves. That changes the advice from "generate a new key" to
		// "enrol this one again", so it is worth recording which case it is.
		if _, err := os.Stat(filepath.Join(dir, strings.TrimSuffix(name, ".pub"))); err == nil {
			k.HasPrivate = true
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys
}

// keyTypes maps the wire name at the start of a public key to something worth
// printing.
var keyTypes = map[string]string{
	"ssh-rsa":                              "RSA",
	"ssh-dss":                              "DSA",
	"ssh-ed25519":                          "ED25519",
	"ecdsa-sha2-nistp256":                  "ECDSA",
	"ecdsa-sha2-nistp384":                  "ECDSA",
	"ecdsa-sha2-nistp521":                  "ECDSA",
	"sk-ssh-ed25519@openssh.com":           "ED25519 (hardware token)",
	"sk-ecdsa-sha2-nistp256@openssh.com":   "ECDSA (hardware token)",
	"ssh-rsa-cert-v01@openssh.com":         "RSA certificate",
	"ssh-ed25519-cert-v01@openssh.com":     "ED25519 certificate",
	"ecdsa-sha2-nistp256-cert-v01@openssh": "ECDSA certificate",
}

// parsePublicKey computes the SHA-256 fingerprint OpenSSH reports, without
// shelling out to ssh-keygen and without a dependency: the fingerprint is the
// base64 of the SHA-256 of the decoded key blob, which is what `ssh-keygen -lf`
// prints.
func parsePublicKey(line string) (bundle.SSHKey, bool) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return bundle.SSHKey{}, false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return bundle.SSHKey{}, false
	}
	sum := sha256.Sum256(blob)

	k := bundle.SSHKey{
		Type:        keyTypes[fields[0]],
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
	}
	if k.Type == "" {
		k.Type = fields[0]
	}
	if len(fields) > 2 {
		k.Comment = strings.Join(fields[2:], " ")
	}
	return k, true
}

type sshConfigHost struct {
	host, user, identity string
}

// parseSSHConfig reads the Host blocks worth listing.
//
// Include directives are not followed. A host reached through one is very
// likely to be in known_hosts as well, and quietly reading files the catalog
// never declared is not a trade worth making for the remainder.
func parseSSHConfig(path string) []sshConfigHost {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []sshConfigHost
	var current []int // indices in out sharing the current Host block

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitConfigLine(line)
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "host":
			current = nil
			for _, pattern := range strings.Fields(value) {
				// A pattern is a rule, not a machine. "Host *" sets defaults for
				// everything and names nowhere to paste a key.
				if strings.ContainsAny(pattern, "*?!") {
					continue
				}
				out = append(out, sshConfigHost{host: pattern})
				current = append(current, len(out)-1)
			}
		case "hostname":
			for _, i := range current {
				out[i].host = value
			}
		case "user":
			for _, i := range current {
				out[i].user = value
			}
		case "identityfile":
			for _, i := range current {
				out[i].identity = filepath.Base(value)
			}
		}
	}
	return out
}

// splitConfigLine handles both "Key value" and "Key=value", which ssh accepts
// interchangeably.
func splitConfigLine(line string) (key, value string, ok bool) {
	if i := strings.IndexAny(line, " \t="); i > 0 {
		key = line[:i]
		value = strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
		return key, value, value != ""
	}
	return "", "", false
}

// parseKnownHosts returns the hostnames it can read and counts the ones it
// cannot.
//
// OpenSSH can store hostnames as salted hashes, and those are not reversible.
// Counting them is the honest alternative to presenting a partial list as if it
// were complete.
func parseKnownHosts(path string) (hosts []string, hashed int) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0
	}
	defer f.Close()

	seen := map[string]bool{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		// @cert-authority and @revoked shift the host field along by one.
		if strings.HasPrefix(fields[0], "@") {
			fields = fields[1:]
			if len(fields) == 0 {
				continue
			}
		}
		if strings.HasPrefix(fields[0], "|") {
			hashed++
			continue
		}
		for _, h := range strings.Split(fields[0], ",") {
			if h = normaliseHost(h); h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	sort.Strings(hosts)
	return hosts, hashed
}

// normaliseHost strips the [host]:port form known_hosts uses for non-default
// ports, so one server on two ports is one entry.
func normaliseHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	return h
}

// sshRemoteHost returns the host a git remote authenticates to over SSH, or ""
// for anything that does not use a key.
func sshRemoteHost(remote string) string {
	remote = strings.TrimSpace(remote)
	switch {
	case remote == "":
		return ""
	case strings.HasPrefix(remote, "ssh://"):
		rest := strings.TrimPrefix(remote, "ssh://")
		if i := strings.Index(rest, "@"); i >= 0 {
			rest = rest[i+1:]
		}
		rest, _, _ = strings.Cut(rest, "/")
		host, _, _ := strings.Cut(rest, ":")
		return host
	case strings.Contains(remote, "://"):
		// https, git, file — none of them use an SSH key.
		return ""
	case strings.Contains(remote, ":"):
		// scp-style: [user@]host:path
		hostPart, _, _ := strings.Cut(remote, ":")
		if i := strings.Index(hostPart, "@"); i >= 0 {
			hostPart = hostPart[i+1:]
		}
		return hostPart
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
