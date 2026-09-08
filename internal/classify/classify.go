// Package classify assigns every candidate path exactly one data class.
//
// It is deliberately the only place that decision is made, and it is called from
// three sides: capture (what goes into a bundle), restore (what may be written
// out of one) and extract (what may come off a tar). Applying it at restore as
// well as capture matters — a bundle is a file, it can be hand-edited, and
// restoring another user's bundle is a supported operation.
package classify

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Class is the data classification of a path.
type Class string

const (
	// Public paths are captured verbatim.
	Public Class = "public"
	// Scrub paths are captured with credential lines removed and the removal recorded.
	Scrub Class = "scrub"
	// Never paths are excluded under every flag and refused on restore.
	Never Class = "never"
)

// Verdict is the outcome of classifying a single path.
type Verdict struct {
	Class Class
	// Reason is populated for Never, and explains which rule matched so the tool
	// can tell the user why something was left out rather than silently dropping it.
	Reason string
	// Escaped is true when the path resolved, via symlink, outside $HOME. Capture
	// refuses these: following them would pull in arbitrary parts of the filesystem.
	Escaped bool
}

// IsNever reports whether a $HOME-relative slash-separated path is on the never
// list, and why. It is pure: no filesystem access, so it is cheap to call on
// entries read out of a tar header.
func IsNever(rel string) (bool, string) {
	rel = strings.TrimPrefix(path.Clean(filepath.ToSlash(rel)), "./")
	if rel == "." || rel == "" {
		return false, ""
	}

	if reason, ok := neverExact[rel]; ok {
		return true, reason
	}
	for dir, reason := range neverDirs {
		if rel == dir || strings.HasPrefix(rel, dir+"/") {
			return true, reason
		}
	}
	for glob, reason := range neverDirGlobs {
		for _, prefix := range prefixes(rel) {
			if ok, _ := path.Match(glob, prefix); ok {
				return true, reason
			}
		}
	}
	// Basename globs apply to every component, so a *directory* named .env or
	// secrets.key is caught as well as a file.
	for _, component := range strings.Split(rel, "/") {
		for glob, reason := range neverBasenames {
			if ok, _ := path.Match(glob, component); ok {
				return true, reason
			}
		}
	}
	// ~/.ssh is handled by inverting the rule: everything is excluded except a
	// short allowlist.
	//
	// The obvious rule is to exclude id_*, and it is not enough. The first real
	// machine this was run against had a private key called my_new_key, which no
	// id_* pattern catches. Inside a directory that exists to hold key material,
	// default-deny is the only rule that stays correct as people name their keys
	// whatever they like.
	if strings.HasPrefix(rel, ".ssh/") {
		if !sshAllowed(strings.TrimPrefix(rel, ".ssh/")) {
			return true, "unrecognised file in ~/.ssh, treated as key material"
		}
	}
	return false, ""
}

// sshAllowed reports whether a path within ~/.ssh is one of the few things worth
// carrying to a new machine. Public keys, the config and the host database are
// useful and harmless; anything else is assumed to be a secret.
func sshAllowed(name string) bool {
	switch name {
	case "config", "known_hosts", "known_hosts.old", "authorized_keys":
		return true
	}
	if strings.HasSuffix(name, ".pub") {
		return true
	}
	// ~/.ssh/config.d/* is a common Include target and is configuration.
	if strings.HasPrefix(name, "config.d/") {
		return true
	}
	return false
}

// prefixes returns each directory prefix of rel, longest last.
func prefixes(rel string) []string {
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for i := range parts {
		out = append(out, strings.Join(parts[:i+1], "/"))
	}
	return out
}

// Resolve returns the effective class of an absolute path whose catalog-declared
// class is declared. The never list always wins over the declaration.
//
// Both the lexical path and the symlink-resolved path are checked. A catalog
// entry naming a symlink that points into ~/.aws must still classify as never,
// and checking only one of the two would miss it in one direction or the other.
func Resolve(home, abs string, declared Class) Verdict {
	if rel, ok := relTo(home, abs); ok {
		if never, reason := IsNever(rel); never {
			return Verdict{Class: Never, Reason: reason}
		}
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		// Broken or missing; the lexical verdict above is all we have. Capture will
		// skip it for not existing.
		if os.IsNotExist(err) {
			return Verdict{Class: declared}
		}
		return Verdict{Class: declared}
	}
	if resolved != abs {
		// Compare against the resolved home too. On macOS /tmp and /var are
		// themselves symlinks, and a user's $HOME can legitimately be reached
		// through one; without this every path would look like an escape.
		resolvedHome := home
		if rh, err := filepath.EvalSymlinks(home); err == nil {
			resolvedHome = rh
		}
		rel, ok := relTo(resolvedHome, resolved)
		if !ok {
			return Verdict{Class: Never, Reason: "symlink resolves outside $HOME", Escaped: true}
		}
		if never, reason := IsNever(rel); never {
			return Verdict{Class: Never, Reason: reason + " (via symlink)"}
		}
	}
	return Verdict{Class: declared}
}

// relTo returns abs as a $HOME-relative slash path, and whether it is under home
// at all.
func relTo(home, abs string) (string, bool) {
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

// KnownCredentialPath is a location the never list recognises, for reporting.
type KnownCredentialPath struct {
	Rel    string
	Reason string
}

// KnownCredentialPaths returns the never-listed locations worth probing for
// existence when reporting on a machine.
//
// This is deliberately existence-only — an Lstat, never a read. Allowlist capture
// means these paths are otherwise not looked at at all, which is right, but it
// leaves the user with no way to distinguish "macstash checked and left your AWS
// credentials behind" from "macstash never knew they were there". The first is
// a re-authentication checklist; the second is a month of mystery 401s.
//
// Glob rules are excluded: matching those would mean walking directories the
// allowlist does not authorise.
func KnownCredentialPaths() []KnownCredentialPath {
	out := make([]KnownCredentialPath, 0, len(neverExact)+len(neverDirs))
	for rel, reason := range neverExact {
		out = append(out, KnownCredentialPath{Rel: rel, Reason: reason})
	}
	for rel, reason := range neverDirs {
		out = append(out, KnownCredentialPath{Rel: rel, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}
