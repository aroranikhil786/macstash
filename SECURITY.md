# Security

macstash reads a developer's home directory and writes the result to a file that
gets carried between machines. The bundle is a concentrated picture of one
person's working life, so the security properties below are the product, not a
feature of it.

## Reporting a vulnerability

Report privately through GitHub's
[security advisories](https://github.com/aroranikhil786/macstash/security/advisories/new).
Please do not open a public issue for anything that would put a bundle's
contents at risk.

If you have found a credential that macstash captures and should not, that is a
vulnerability regardless of how obscure the tool storing it is. Include the file
path relative to `$HOME` and which tool writes it. A path is enough — never send
the file, and rotate the credential rather than sharing it.

## What macstash claims

1. **A bundle contains no credentials.** Not scrubbed credentials, not encrypted
   ones — none.
2. **Capture runs with no network access.** It is re-executed under
   `sandbox-exec` with `(deny network*)`, and the binary contains no
   socket-capable code to begin with.
3. **Nothing is downloaded from a URL macstash chose.** Installing software means
   handing a list to Homebrew, which owns the download and its verification.
4. **Restore is never destructive.** Anything overwritten is copied to
   `~/.macstash/backups/<timestamp>/` first, and every step is safe to repeat.

## What macstash does not claim

- **That your bundle is safe to share.** It holds your shell config, your
  hostnames, your repository paths and your machine's shape. Treat it like a
  password manager export you happen to be able to read.
- **That the secret scanner finds every secret.** It matches known credential
  shapes and high-entropy assignments. It reports; it never claims a file is
  clean, and the wording is deliberate.
- **That a bundle from someone else is safe.** `--from-other-user` exists, prints
  a warning, and means you are accepting shell config and scripts that will
  execute on your machine. Read them.

## Invariants a change must not break

These are enforced in CI. If a pull request needs one of them relaxed, the answer
is almost certainly no.

### The never list lives in Go, not YAML

`internal/classify/never.go` is compiled in. A catalog entry is data and can
never widen it — `classify.IsNever` is consulted at capture, at restore *and* at
extraction, and a `never` verdict beats any class an entry declares.

This matters because the catalog is where contributions arrive. A new entry
should be a fifteen-line YAML file that cannot, by construction, reach a
credential.

### The allowlist is the primary control, not the never list

macstash captures only paths a catalog entry names. The never list is the
backstop, and it is always one tool behind: on the first machine this ran
against it had never heard of `~/.config/neonctl`, and a later audit of the same
machine turned up six more. If a design choice depends on the never list being
complete, the design is wrong.

### No socket-capable packages in the import graph

`scripts/check-imports.sh` fails the build on `net`, `net/http`, `crypto/tls`
and `golang.org/x/net/...`, matched exactly. `net/url` is deliberately allowed:
it parses strings and opens nothing.

The sandbox is the enforcement; this is the proof. A reviewer should not have to
trust that a network call is unreachable when the type of code that could make
one is absent.

### A scrub rule must clear every place a secret can be

Scrubbing is only used where a credential's location in a file is predictable.
Where it is not, the file goes on the never list instead and the tool is
reported as needing re-authentication.

MCP configs are the worked example. One machine had a postgres password in
`env` and a live Tavily API key passed as a positional argument, in adjacent
entries of the same file. A rule clearing `env` would have looked correct and
shipped the second key. So MCP configs are never captured, and the servers are
recorded as inventory — names, and the *names* of the variables they need.

### Failures must be loud

The failure this tool exists to prevent is the silent one. `brew bundle dump`
can exit 0 having written a Brewfile containing only `tap` lines; capture
cross-checks the counts and refuses rather than writing a partial one. Any code
path that can produce a plausible-looking, incomplete result needs a check that
fails instead.

## Verifying a release

`scripts/release.sh` publishes `SHA256SUMS` alongside the binaries:

```
shasum -a 256 -c SHA256SUMS
```

Binaries are not notarised. Installing through Homebrew avoids the quarantine
attribute; a direct download will need Gatekeeper approval.
