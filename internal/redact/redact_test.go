package redact

import (
	"strings"
	"testing"
)

func TestRemote(t *testing.T) {
	cases := []struct {
		in       string
		wantGone []string // must not appear
		wantKept []string // must appear
	}{
		{
			in:       "https://github.com/reboot-ai-labs/plutus.git",
			wantGone: []string{"reboot-ai-labs", "plutus"},
			wantKept: []string{"github.com"},
		},
		{
			in:       "git@github.com:Masterplate/menuly.git",
			wantGone: []string{"Masterplate", "menuly"},
			wantKept: []string{"github.com"},
		},
		{
			// A private host is itself the disclosure, so it goes too.
			in:       "https://git.internal.acme-corp.net/platform/billing.git",
			wantGone: []string{"acme-corp", "internal", "platform", "billing"},
			wantKept: []string{"private host"},
		},
		{
			in:       "git@git.internal.acme.net:infra/terraform.git",
			wantGone: []string{"acme", "infra", "terraform"},
			wantKept: []string{"private host"},
		},
		{
			// Credentials embedded in a remote must never survive display.
			in:       "https://user:ghp_SECRETTOKEN0123456789@github.com/org/repo.git",
			wantGone: []string{"ghp_SECRETTOKEN", "user", "org"},
			wantKept: []string{"github.com"},
		},
	}

	for _, c := range cases {
		got := Remote(c.in)
		for _, gone := range c.wantGone {
			if strings.Contains(got, gone) {
				t.Errorf("Remote(%q) = %q; must not leak %q", c.in, got, gone)
			}
		}
		for _, kept := range c.wantKept {
			if !strings.Contains(got, kept) {
				t.Errorf("Remote(%q) = %q; expected it to mention %q", c.in, got, kept)
			}
		}
	}
}

func TestUnredactedPassesThrough(t *testing.T) {
	url := "https://github.com/org/repo.git"
	if got := Apply(url, true); got != url {
		t.Errorf("--unredacted altered the URL: %q", got)
	}
	if got := Apply(url, false); got == url {
		t.Error("default output was not redacted")
	}
}

func TestTapURL(t *testing.T) {
	in := `tap "acme/internal", "https://git.internal.acme.net/acme/homebrew-tap"`
	got := TapURL(in)
	if strings.Contains(got, "git.internal.acme.net") {
		t.Errorf("tap URL leaked the private host: %q", got)
	}
	if !strings.Contains(got, "acme/internal") {
		t.Errorf("tap name should survive so the user knows which tap: %q", got)
	}
}

func TestEmptyRemote(t *testing.T) {
	if Remote("") != "" {
		t.Error("an empty remote should stay empty, not become a placeholder")
	}
}
