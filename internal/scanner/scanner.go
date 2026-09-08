// Package scanner looks for credentials in files that are about to be captured.
//
// It may only ever report. It never blocks a capture, never edits a file, and —
// most importantly — never says a bundle is clean. Its output is always "N
// findings to review before you transfer this bundle", because the alternative
// phrasing invites someone to trust a heuristic with the one decision it is not
// qualified to make. A scanner that says "clean" is worse than no scanner: it
// converts an unknown risk into a false assurance.
package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Finding is one thing worth a human look.
type Finding struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Rule string `json:"rule"`
	// Excerpt is a heavily truncated fragment, enough to find the line without
	// reproducing the secret in a report that may itself be shared.
	Excerpt string `json:"excerpt"`
}

type rule struct {
	name string
	re   *regexp.Regexp
}

// rules are high-confidence credential shapes. Vendor prefixes are used where
// they exist because they produce almost no false positives, which is what keeps
// the report short enough that people actually read it.
var rules = []rule{
	{"AWS access key ID", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`)},
	{"GitHub fine-grained token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{50,}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)},
	{"Stripe live key", regexp.MustCompile(`\b(sk|rk)_live_[A-Za-z0-9]{20,}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"OpenAI key", regexp.MustCompile(`\bsk-[A-Za-z0-9]{20,}\b`)},
	{"Anthropic key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{20,}\b`)},
	{"npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`)},
	{"PostgreSQL URL with password", regexp.MustCompile(`\bpostgres(ql)?://[^:\s]+:[^@\s]+@`)},
	{"URL with inline credentials", regexp.MustCompile(`\bhttps?://[^:/\s]+:[^@/\s]{6,}@`)},
}

// assignment matches a variable assignment whose name suggests a secret. The
// value is then entropy-checked, because SECRET=changeme is noise and
// SECRET=8f3a9c... is not.
var assignment = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*)\s*[:=]\s*["']?([^\s"']{12,})["']?`)

// placeholders are values that look like secrets to a regex but are obviously
// not. Reporting these trains people to ignore the report.
var placeholders = map[string]bool{
	"changeme": true, "password": true, "secret": true, "xxxxxxxxxxxx": true,
	"your_token_here": true, "todo": true, "none": true, "null": true,
	"redacted": true, "example": true, "placeholder": true,
	"macstash_removed": true,
}

// Scan examines one file's contents.
func Scan(content []byte, rel string) []Finding {
	var findings []Finding

	// Binary files produce noise, not findings.
	if bytes.IndexByte(content, 0) >= 0 {
		return nil
	}

	s := bufio.NewScanner(bytes.NewReader(content))
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for line := 1; s.Scan(); line++ {
		text := s.Text()
		if len(text) > 4000 {
			continue // minified or generated
		}

		matched := false
		for _, r := range rules {
			if loc := r.re.FindStringIndex(text); loc != nil {
				findings = append(findings, Finding{
					File: rel, Line: line, Rule: r.name, Excerpt: excerpt(text, loc[0]),
				})
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		if m := assignment.FindStringSubmatch(text); m != nil {
			value := strings.Trim(m[2], `"'`)
			if placeholders[strings.ToLower(value)] {
				continue
			}
			if shannon(value) >= 3.5 {
				findings = append(findings, Finding{
					File: rel, Line: line,
					Rule:    "high-entropy value assigned to " + m[1],
					Excerpt: excerpt(text, 0),
				})
			}
		}
	}
	return findings
}

// excerpt returns a short, masked fragment around a match.
func excerpt(line string, at int) string {
	start := at - 12
	if start < 0 {
		start = 0
	}
	end := start + 40
	if end > len(line) {
		end = len(line)
	}
	frag := strings.TrimSpace(line[start:end])
	// Mask long runs of secret-shaped characters so the report itself is safe to
	// paste into a ticket.
	return maskRuns(frag)
}

var runOfSecret = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{12,}`)

func maskRuns(s string) string {
	return runOfSecret.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) <= 6 {
			return m
		}
		return m[:4] + strings.Repeat("*", 6) + m[len(m)-2:]
	})
}

// shannon returns the Shannon entropy of s in bits per character.
func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]float64
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

// Summary renders findings for a human.
//
// Note what this never says. There is no "clean" branch and no tick mark: zero
// findings is reported as zero findings, which is a statement about what the
// scanner looked for, not a guarantee about what is in the bundle.
func Summary(findings []Finding) string {
	var b strings.Builder
	if len(findings) == 0 {
		b.WriteString("Secret scan: 0 findings. This is not a clean bill of health — the scanner\n" +
			"             matches known credential shapes and high-entropy assignments, and\n" +
			"             cannot recognise a secret that looks like ordinary text.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Secret scan: %d finding(s) to review before you transfer this bundle:\n", len(findings))
	for i, f := range findings {
		if i >= 25 {
			fmt.Fprintf(&b, "  ... and %d more\n", len(findings)-i)
			break
		}
		fmt.Fprintf(&b, "  %s:%d  %s\n      %s\n", f.File, f.Line, f.Rule, f.Excerpt)
	}
	b.WriteString("\nThese were captured, not removed. Review them and re-run capture if any is real.\n")
	return b.String()
}
