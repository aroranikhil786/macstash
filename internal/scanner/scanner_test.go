package scanner

import (
	"strings"
	"testing"
)

// shape assembles a credential-shaped fixture from fragments.
//
// This test has to contain real vendor token formats — recognising them is the
// thing being tested — which makes the file indistinguishable from a leak to
// any scanner reading it. The Stripe fixture below opened a secret-scanning
// alert on this repository the moment it went public, and a standing false
// positive is worse than none: it is the alert people learn to skim past, and
// the next one will be real.
//
// Joining the fragments at run time means the file contains no matchable
// literal while Scan still receives a genuine shape. Do not "tidy" these back
// into single strings.
func shape(parts ...string) string { return strings.Join(parts, "") }

func TestScanFindsRealCredentialShapes(t *testing.T) {
	cases := []struct{ name, content, wantRule string }{
		// AWS's own documented example key, allowlisted by scanners everywhere.
		{"aws", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "AWS access key ID"},
		{"github", "export GH=" + shape("ghp", "_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789") + "\n", "GitHub token"},
		{"slack", "SLACK=" + shape("xoxb", "-", "1234567890-abcdefghijkl") + "\n", "Slack token"},
		{"stripe", "key = " + shape("sk", "_live_", "abcdefghijklmnopqrstuvwx") + "\n", "Stripe live key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\n", "private key block"},
		{"pg url", "DB=" + shape("postgres", "://", "admin:hunter2hunter2@db.internal/app") + "\n", "PostgreSQL URL with password"},
		{"jwt", "t=" + shape("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "dozjgNryP4J3jVmNHl0w5N") + "\n", "JSON Web Token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := Scan([]byte(c.content), "script.sh")
			if len(f) == 0 {
				t.Fatalf("no finding for %s", c.name)
			}
			if f[0].Rule != c.wantRule {
				t.Errorf("rule = %q, want %q", f[0].Rule, c.wantRule)
			}
		})
	}
}

// A report nobody reads protects nobody, so obvious non-secrets must not appear.
func TestScanIgnoresPlaceholdersAndOrdinaryConfig(t *testing.T) {
	clean := []string{
		"PASSWORD=changeme\n",
		"API_KEY=your_token_here\n",
		"# TOKEN= (set this in your shell)\n",
		"alias gs='git status'\n",
		"export EDITOR=vim\n",
		"registry=https://registry.npmjs.org/\n",
		"SECRET=null\n",
	}
	for _, c := range clean {
		if f := Scan([]byte(c), "x"); len(f) != 0 {
			t.Errorf("false positive on %q: %+v", strings.TrimSpace(c), f)
		}
	}
}

func TestScanFindsHighEntropyAssignment(t *testing.T) {
	f := Scan([]byte("DATABASE_PASSWORD=xJ9mQ2vL8pR4tW6yZ1aB3cD5\n"), "x")
	if len(f) == 0 {
		t.Fatal("high-entropy password assignment was not reported")
	}
	if !strings.Contains(f[0].Rule, "high-entropy") {
		t.Errorf("rule = %q", f[0].Rule)
	}
}

// The report itself gets pasted into tickets, so it must not reproduce secrets.
func TestExcerptMasksTheSecret(t *testing.T) {
	f := Scan([]byte("export GH="+shape("ghp", "_", "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")+"\n"), "x")
	if len(f) == 0 {
		t.Fatal("no finding")
	}
	if strings.Contains(f[0].Excerpt, "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789") {
		t.Errorf("excerpt reproduced the full secret: %q", f[0].Excerpt)
	}
	if !strings.Contains(f[0].Excerpt, "*") {
		t.Errorf("excerpt was not masked: %q", f[0].Excerpt)
	}
}

func TestBinaryFilesAreSkipped(t *testing.T) {
	if f := Scan([]byte{0x00, 0x01, 0x02, 'A', 'K', 'I', 'A'}, "x.bin"); len(f) != 0 {
		t.Errorf("binary file produced findings: %+v", f)
	}
}

// The scanner must never claim a bundle is clean.
func TestSummaryNeverClaimsClean(t *testing.T) {
	s := Summary(nil)
	lower := strings.ToLower(s)
	for _, forbidden := range []string{"clean bill", "no secrets", "safe to share", "all clear"} {
		if strings.Contains(lower, forbidden) && !strings.Contains(lower, "not a clean bill") {
			t.Errorf("summary claims safety with %q: %s", forbidden, s)
		}
	}
	if !strings.Contains(lower, "not a clean bill of health") {
		t.Errorf("zero-finding summary must disclaim, got: %s", s)
	}
}

// A value that reads a secret from elsewhere is not a secret. Shell scripts are
// full of these, and reporting them is how a scan report becomes noise that
// nobody reads — which was the real-world failure: ~/.local/bin/sp was flagged
// for `export OPENAI_API_KEY="${OPENAI_API_KEY:-}"`, which contains no key.
func TestIndirectionIsNotASecret(t *testing.T) {
	clean := []string{
		`export OPENAI_API_KEY="${OPENAI_API_KEY:-}"` + "\n",
		`export GITHUB_TOKEN=$GITHUB_TOKEN` + "\n",
		`api_key = os.environ["OPENAI_API_KEY"]` + "\n",
		`token: ${{ secrets.GITHUB_TOKEN }}` + "\n",
		`password = process.env.DB_PASSWORD` + "\n",
		`SECRET_KEY=$(cat /run/secrets/key)` + "\n",
		`api_key = System.getenv("API_KEY")` + "\n",
	}
	for _, c := range clean {
		if f := Scan([]byte(c), "script.sh"); len(f) != 0 {
			t.Errorf("false positive on %q: %+v", strings.TrimSpace(c), f)
		}
	}
}

// The fix must not blind the scanner to values that really are literals.
func TestLiteralSecretsStillCaught(t *testing.T) {
	dirty := []string{
		`export OPENAI_API_KEY="sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ01"` + "\n",
		`DATABASE_PASSWORD=xJ9mQ2vL8pR4tW6yZ1aB3cD5` + "\n",
	}
	for _, c := range dirty {
		if f := Scan([]byte(c), "script.sh"); len(f) == 0 {
			t.Errorf("missed a real literal secret in %q", strings.TrimSpace(c))
		}
	}
}

// The lines that produced four of six findings on a real machine, all of them
// from powerlevel10k's own parser rather than from anyone's configuration.
//
// zsh writes `: ${token::=${(Q)${~token}}}`. The assignment regex takes the
// value as `:=${(Q)${~token}}}` — a leading colon — so an indirection test
// anchored to the start of the value missed it. A report that is five-sixths
// noise is a report people stop reading.
func TestScanIgnoresShellParameterExpansion(t *testing.T) {
	noisy := []string{
		": ${token::=${(Q)${~token}}}\n",
		`typeset -g "_p9k__google_application_credentials_${_p9k_x}"` + "\n",
		"local token=${(Q)${(z)line}}\n",
		"SECRET_TOKEN=$(cat /run/secrets/token)\n",
		"api_key=${API_KEY:-${FALLBACK_KEY}}\n",
	}
	for _, line := range noisy {
		if f := Scan([]byte(line), "p10k.zsh"); len(f) != 0 {
			t.Errorf("%q should not be reported, got %+v", line, f)
		}
	}
}

// The fix must not silence a real literal secret assigned to the same names.
func TestScanStillFindsLiteralSecretsAfterTheExpansionFix(t *testing.T) {
	real := []string{
		"SECRET_TOKEN=8f3a9c2e1b7d4056af21c3d4\n",
		"api_key = 'kJ8sLp2mQx9vRt4nZw7bYc3d'\n",
	}
	for _, line := range real {
		if f := Scan([]byte(line), "config.sh"); len(f) == 0 {
			t.Errorf("%q is a literal secret and must still be reported", line)
		}
	}
}
