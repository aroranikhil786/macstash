package scrub

import (
	"strings"
	"testing"
)

// The scrub class only earns its place if the non-credential content survives.
// Each case asserts both halves: the token is gone AND the useful config remains.
func TestNpmrc(t *testing.T) {
	in := `registry=https://registry.npmjs.org/
@acme:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=ghp_FAKEfakeFAKEfakeFAKEfake0123456789
//registry.npmjs.org/:_auth=aGVsbG86d29ybGQ=
save-exact=true
`
	rules := []Rule{
		{Kind: DropLine, Pattern: `^\s*//.*:_authToken\s*=`, Reason: "npm registry auth token"},
		{Kind: DropLine, Pattern: `^\s*//.*:_auth\s*=`, Reason: "npm registry basic auth"},
	}
	out, records, err := Apply([]byte(in), rules, ".npmrc")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, leak := range []string{"ghp_FAKE", "aGVsbG86d29ybGQ="} {
		if strings.Contains(got, leak) {
			t.Errorf("token %q survived scrub:\n%s", leak, got)
		}
	}
	for _, keep := range []string{"registry=https://registry.npmjs.org/", "@acme:registry=", "save-exact=true"} {
		if !strings.Contains(got, keep) {
			t.Errorf("useful config %q was lost:\n%s", keep, got)
		}
	}
	if len(records) != 2 {
		t.Errorf("got %d scrub records, want 2: %+v", len(records), records)
	}
}

func TestDockerConfigDropsAuthsKeepsRest(t *testing.T) {
	in := `{
  "auths": { "ghcr.io": { "auth": "c2VjcmV0OnRva2Vu" } },
  "credsStore": "desktop",
  "currentContext": "orbstack",
  "plugins": { "scan": { "org": "acme" } }
}`
	rules := []Rule{{Kind: DropJSONKey, Key: "auths", Reason: "docker registry credentials"}}
	out, records, err := Apply([]byte(in), rules, ".docker/config.json")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "c2VjcmV0OnRva2Vu") || strings.Contains(got, "auths") {
		t.Errorf("auths survived:\n%s", got)
	}
	for _, keep := range []string{"credsStore", "currentContext", "orbstack", "plugins"} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was lost:\n%s", keep, got)
		}
	}
	if len(records) != 1 || records[0].Count != 1 {
		t.Errorf("records = %+v, want one with count 1", records)
	}
}

// A gitconfig inline token must be redacted in place: dropping the whole line
// would silently remove an insteadOf rewrite the user depends on.
func TestGitconfigRedactsInlineTokenInPlace(t *testing.T) {
	in := `[user]
	name = Test User
[url "https://x-access-token:ghp_FAKEfakeFAKE0123456789abcd@github.com/"]
	insteadOf = https://github.com/
`
	rules := []Rule{{
		Kind:    RedactMatch,
		Pattern: `https://([^@/:]+):([^@/]+)@`,
		Reason:  "inline credential in git URL",
	}}
	out, records, err := Apply([]byte(in), rules, ".gitconfig")
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "ghp_FAKEfakeFAKE") {
		t.Errorf("token survived:\n%s", got)
	}
	if !strings.Contains(got, Placeholder) {
		t.Errorf("no visible placeholder left behind:\n%s", got)
	}
	if !strings.Contains(got, "insteadOf = https://github.com/") {
		t.Errorf("the insteadOf rule was lost:\n%s", got)
	}
	// Both halves are redacted, because either can hold the secret. What must
	// survive is the surrounding structure.
	if !strings.Contains(got, "@github.com/") {
		t.Errorf("structure of the url line was destroyed:\n%s", got)
	}
	if len(records) != 1 {
		t.Errorf("records = %+v, want 1", records)
	}
}

// A file with nothing to remove must come back byte-identical and produce no
// record, or the manifest fills with noise and `doctor` cries wolf.
func TestCleanFileIsUnchangedAndUnrecorded(t *testing.T) {
	in := "registry=https://registry.npmjs.org/\nsave-exact=true\n"
	rules := []Rule{{Kind: DropLine, Pattern: `_authToken`, Reason: "npm token"}}
	out, records, err := Apply([]byte(in), rules, ".npmrc")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Errorf("clean file was modified:\n%q", string(out))
	}
	if len(records) != 0 {
		t.Errorf("clean file produced records: %+v", records)
	}
}

func TestMalformedJSONIsAnErrorNotSilentPassthrough(t *testing.T) {
	rules := []Rule{{Kind: DropJSONKey, Key: "auths", Reason: "docker credentials"}}
	if _, _, err := Apply([]byte("{not json"), rules, ".docker/config.json"); err == nil {
		t.Fatal("malformed JSON scrubbed without error; a token could pass through unscrubbed")
	}
}

// The captured value can also appear earlier in the match. Replacing by
// substring search then redacts the wrong copy and leaves the real credential
// in place — a silent leak that the scrub record still counts as a success.
func TestRedactReplacesTheCapturedBytesNotTheFirstMatch(t *testing.T) {
	rule := []Rule{{
		Kind:    RedactMatch,
		Pattern: `https://([^@/:]+):([^@/]+)@`,
		Reason:  "inline credential in a git URL rewrite",
	}}

	cases := []struct{ name, in, secret string }{
		{
			// Generic PATs are routinely pasted into both halves.
			name:   "same token as username and password",
			in:     `[url "https://ghp_TOKEN123456:ghp_TOKEN123456@github.com/"]`,
			secret: "ghp_TOKEN123456",
		},
		{
			// The password's bytes occur earlier inside "https".
			name:   "password is a substring appearing earlier in the match",
			in:     `[url "https://user:http@github.com/"]`,
			secret: "",
		},
		{
			// GitHub's own scheme puts the token in the username position.
			name:   "token in the username half",
			in:     `[url "https://ghp_REALTOKEN99:x-oauth-basic@github.com/"]`,
			secret: "ghp_REALTOKEN99",
		},
		{
			name:   "password shares a prefix with the username",
			in:     `[url "https://tok:tok123456@github.com/"]`,
			secret: "tok123456",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, records, err := Apply([]byte(c.in), rule, ".gitconfig")
			if err != nil {
				t.Fatal(err)
			}
			got := string(out)
			if c.secret != "" && strings.Contains(got, c.secret) {
				t.Errorf("credential %q survived the scrub: %s", c.secret, got)
			}
			if !strings.Contains(got, Placeholder) {
				t.Errorf("nothing was redacted: %s", got)
			}
			// The placeholder must land in the password position, immediately
			// before the @.
			if !strings.Contains(got, Placeholder+"@") {
				t.Errorf("redaction landed in the wrong position: %s", got)
			}
			if len(records) != 1 {
				t.Errorf("records = %+v, want exactly 1", records)
			}
		})
	}
}
