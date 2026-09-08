// Package redact hides internal infrastructure in anything macstash prints.
//
// The bundle keeps full remote URLs — `clone` needs them. What gets redacted is
// the display. Reports and terminal output are screenshotted, pasted into
// tickets and dropped into chat far more often than bundles are shared, and a
// git remote is a map of an employer's internal infrastructure: hostnames, org
// names, and by implication what the team is building.
//
// The distinction drawn here is between public forges and everything else.
// "This repository is on github.com" leaks almost nothing. "This repository is
// on git.internal.acme-corp.net" leaks the existence, name and topology of a
// private system, so the host itself is hidden rather than merely its path.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder is what replaces a redacted segment.
const Placeholder = "<redacted>"

// publicForges are hosts where naming the host reveals nothing an attacker
// could not guess.
var publicForges = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true,
	"codeberg.org": true, "sr.ht": true, "git.sr.ht": true,
}

// scpLike matches git's scp-style remotes, e.g. git@github.com:org/repo.git.
var scpLike = regexp.MustCompile(`^([^@/]+)@([^:/]+):(.+)$`)

// Remote redacts a git remote URL for display.
func Remote(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}

	if m := scpLike.FindStringSubmatch(url); m != nil {
		host := m[2]
		if publicForges[strings.ToLower(host)] {
			return m[1] + "@" + host + ":" + Placeholder
		}
		return Placeholder + " (private host)"
	}

	if i := strings.Index(url, "://"); i >= 0 {
		scheme, rest := url[:i], url[i+3:]
		// Strip any embedded credentials before anything else.
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		host := rest
		if slash := strings.Index(rest, "/"); slash >= 0 {
			host = rest[:slash]
		}
		if publicForges[strings.ToLower(host)] {
			return scheme + "://" + host + "/" + Placeholder
		}
		return Placeholder + " (private host)"
	}

	// A local path or something unrecognised; reveal nothing.
	return Placeholder
}

// TapURL redacts a Homebrew tap's custom URL. A tap pointing at a private host
// discloses internal infrastructure in exactly the way a git remote does.
func TapURL(line string) string {
	// tap "org/name", "https://git.internal/org/homebrew-tap"
	i := strings.Index(line, `", "`)
	if i < 0 {
		return line
	}
	return line[:i+1] + ", " + Placeholder
}

// Remotes redacts a slice of remotes unless unredacted is set.
func Remotes(urls []string, unredacted bool) []string {
	out := make([]string, len(urls))
	for i, u := range urls {
		if unredacted {
			out[i] = u
			continue
		}
		out[i] = Remote(u)
	}
	return out
}

// Apply is the single decision point used by display code.
func Apply(url string, unredacted bool) string {
	if unredacted {
		return url
	}
	return Remote(url)
}
