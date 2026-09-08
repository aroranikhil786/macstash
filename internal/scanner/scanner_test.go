package scanner

import (
	"strings"
	"testing"
)

func TestScanFindsRealCredentialShapes(t *testing.T) {
	cases := []struct{ name, content, wantRule string }{
		{"aws", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "AWS access key ID"},
		{"github", "export GH=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n", "GitHub token"},
		{"slack", "SLACK=xoxb-1234567890-abcdefghijkl\n", "Slack token"},
		{"stripe", "key = sk_live_abcdefghijklmnopqrstuvwx\n", "Stripe live key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\n", "private key block"},
		{"pg url", "DB=postgres://admin:hunter2hunter2@db.internal/app\n", "PostgreSQL URL with password"},
		{"jwt", "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N\n", "JSON Web Token"},
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
	f := Scan([]byte("export GH=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n"), "x")
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
