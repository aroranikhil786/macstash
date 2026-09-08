// Package scrub removes credentials from files that are otherwise worth keeping.
//
// The point of a scrub class, as opposed to just excluding these files, is that
// ~/.npmrc without its auth token is still a useful ~/.npmrc — it carries your
// registry, your scopes, your settings. Dropping the file entirely throws that
// away; keeping it whole leaks a token. So it is captured minus the credential,
// and every removal is recorded, so a later `doctor` can name the token that went
// missing and the command that puts it back. An unexplained 401 three weeks after
// a migration is the exact failure this project exists to prevent.
package scrub

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Kind selects how a rule edits the file.
type Kind string

const (
	// DropLine removes every line matching the pattern.
	DropLine Kind = "drop_line"
	// RedactMatch keeps the line but replaces capture group 1 with a placeholder,
	// used where deleting the line would break the file's meaning.
	RedactMatch Kind = "redact_match"
	// DropJSONKey removes a top-level key from a JSON document.
	DropJSONKey Kind = "drop_json_key"
)

// Placeholder is what RedactMatch leaves behind. It is deliberately visible: the
// user should be able to grep a restored config for it.
const Placeholder = "MACSTASH_REMOVED"

// Rule is one credential-removal rule from a catalog entry.
type Rule struct {
	Kind    Kind   `yaml:"kind"`
	Pattern string `yaml:"pattern"`
	Key     string `yaml:"key"`
	Reason  string `yaml:"reason"`
}

// Record is the audit trail of one rule firing against one file. It is written
// into the bundle manifest.
type Record struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

// Apply runs rules over content, returning the scrubbed bytes and a record for
// every rule that removed something. relFile is used only for labelling records.
func Apply(content []byte, rules []Rule, relFile string) ([]byte, []Record, error) {
	var records []Record
	out := content

	for _, r := range rules {
		var (
			next  []byte
			count int
			err   error
		)
		switch r.Kind {
		case DropJSONKey:
			next, count, err = dropJSONKey(out, r.Key)
		case RedactMatch:
			next, count, err = redactMatch(out, r.Pattern)
		case DropLine, "":
			next, count, err = dropLine(out, r.Pattern)
		default:
			return nil, nil, fmt.Errorf("unknown scrub kind %q", r.Kind)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", r.Reason, err)
		}
		out = next
		if count > 0 {
			records = append(records, Record{File: relFile, Reason: r.Reason, Count: count})
		}
	}
	return out, records, nil
}

func dropLine(content []byte, pattern string) ([]byte, int, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, 0, err
	}
	lines := strings.Split(string(content), "\n")
	kept := make([]string, 0, len(lines))
	count := 0
	for _, line := range lines {
		if re.MatchString(line) {
			count++
			continue
		}
		kept = append(kept, line)
	}
	if count == 0 {
		return content, 0, nil
	}
	return []byte(strings.Join(kept, "\n")), count, nil
}

func redactMatch(content []byte, pattern string) ([]byte, int, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, 0, err
	}
	count := 0
	out := re.ReplaceAllFunc(content, func(m []byte) []byte {
		count++
		// Splice at the capture group's byte offsets rather than searching for
		// its value. A substring search replaces the FIRST occurrence of those
		// bytes, which is not necessarily the captured one: given
		// https://ghp_TOKEN:ghp_TOKEN@host the username copy is replaced and the
		// real credential survives in the password position. Any value that also
		// appears earlier in the match hits the same trap.
		idx := re.FindSubmatchIndex(m)
		if len(idx) < 4 || idx[2] < 0 {
			return []byte(Placeholder)
		}
		// Every capture group is redacted, not just the first. In a URL of the
		// form user:password@host either half can be the secret — GitHub's own
		// scheme is https://<TOKEN>:x-oauth-basic@ — and the pattern cannot know
		// which. Redacting one half and trusting the other is how a token ends up
		// in a bundle that reports a successful scrub.
		out := append([]byte(nil), m...)
		for g := len(idx)/2 - 1; g >= 1; g-- {
			start, end := idx[2*g], idx[2*g+1]
			if start < 0 || end < start {
				continue
			}
			spliced := make([]byte, 0, len(out)+len(Placeholder))
			spliced = append(spliced, out[:start]...)
			spliced = append(spliced, Placeholder...)
			spliced = append(spliced, out[end:]...)
			out = spliced
		}
		return out
	})
	return out, count, nil
}

func dropJSONKey(content []byte, key string) ([]byte, int, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, ok := doc[key]; !ok {
		return content, 0, nil
	}
	delete(doc, key)
	out, err := json.MarshalIndent(doc, "", "\t")
	if err != nil {
		return nil, 0, err
	}
	return append(out, '\n'), 1, nil
}
