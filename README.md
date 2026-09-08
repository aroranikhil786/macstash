# macstash

Capture a macOS development environment and rebuild it on another Mac.
For people who never kept a dotfiles repo.

```
old Mac:   macstash capture
new Mac:   macstash restore ~/macstash/macstash-2026-09-08.tar.gz
new Mac:   macstash doctor          # what's still missing — any time later
```

The problem is not the initial setup. It's the month afterwards of discovering,
one at a time, that something is missing. `doctor` is the answer to that month.

**Why this exists alongside chezmoi, Mackup, yadm, dotbot and Nix:** every one of
those requires prior discipline — you already decided to manage your
configuration and put it in a repo. macstash works on the machine nobody ever
managed, and hands off to those tools rather than replacing them
(`macstash export --to chezmoi`).

## The one decision that shapes everything

**Bundles contain no credentials, under any flag.** There is no
`--include-secrets`. Files that normally hold credentials are either excluded or
*scrubbed* — captured with the credential lines removed and the rest intact, with
every removal recorded so `doctor` can tell you what to re-authenticate.

The cost is roughly thirty minutes of signing back in on the new machine. The
benefit is that the worst risk class cannot occur.

## What it will not do, and why

This list is the honest part of the README, and it is deliberately long.

**Cannot be automated by anything:**

- **Permissions.** Accessibility, Full Disk Access, Input Monitoring and the rest
  are granted by a human in System Settings. That is the entire point of the
  permission system. macstash lists which apps need which permission — knowing
  that Karabiner needs Input Monitoring before any remapping works saves an hour
  of wondering why a correct config does nothing.
- **Keychain, app licences, logins.** Not captured, not transportable.
- **Mac App Store apps** without your Apple ID signed in.
- **Corporate CA certificates and proxy configuration.** Detected and listed.
- **Git commit signing keys.** Detected from `.gitconfig` and listed; the key
  itself is never captured, so commits will fail until you regenerate it.

**Deliberately not done:**

- **No cloud sync.** Transfer is AirDrop or USB. Writing a bundle into a
  synced folder is refused without `--force`.
- **No fetching from URLs.** macstash never installs Homebrew — if `brew` is
  missing it prints the official command and exits. Apps installed from a disk
  image are reported as a checklist, never downloaded.
- **No user files.** Documents, Desktop, Downloads, Photos, git working trees.
- **No repository contents.** Remote URL, branch and path only.
- **No telemetry, analytics, crash reporting or update check.** An update check
  would need network code, which would break the guarantee below.

## Structural guarantees

These are properties of the build, not promises in a README:

1. **macstash's own code never opens a socket.** Enforced in CI at the import
   graph (`scripts/check-imports.sh`), which fails the build on `net`,
   `net/http`, `crypto/tls` and `golang.org/x/net/*`.
2. **`capture` runs with the network denied.** It re-executes itself under
   `sandbox-exec` with `(deny network*)`. Capture needs no network, so denying it
   makes "this tool does not phone home" a property of the process.
3. **Data flows in, never out.** Restore invokes `brew`, `fnm`, `pyenv` and other
   tools you already installed and trust, to fetch public packages.
4. **Never destructive.** Anything overwritten moves to
   `~/.macstash/backups/<timestamp>/` with its structure preserved.
5. **Refuses to run as root.**
6. **`--plan` shows every change before `--apply`,** and is the default for
   restore.
7. **Bundles are personal.** Restore refuses a bundle captured by a different
   user unless `--from-other-user` is passed — restoring someone else's `.zshrc`
   runs their code.

## The secret scanner reports; it never certifies

An entropy and pattern scanner runs over everything captured. Its output is
always "N findings to review", never "clean". Zero findings is a statement about
what the scanner looked for, not a guarantee about what is in the bundle. The
false-assurance risk lives entirely in the second phrasing, so the tool does not
have it.

## Commands

| Command | What it does |
|---|---|
| `capture` | Scan this Mac under a no-network sandbox; write a bundle to `~/macstash/` |
| `restore <bundle>` | Show what would change; `--apply` to do it |
| `doctor` | Diff this machine against the last restore |
| `doctor --deep` | Actually run things — git auth, docker, java, go |
| `inspect <bundle>` | Read a bundle's manifest without applying anything |
| `catalog` | What macstash knows how to capture; `catalog show <id>` for one entry |
| `clone` | Clone the repositories a bundle recorded (needs your SSH key and VPN) |
| `backups --prune` | Apply 30-day retention to `~/.macstash/backups/` |
| `export --to brewfile\|chezmoi` | Hand off to a tool you'll actually maintain |

Flags: `--plan`, `--apply`, `--only <ids>`, `--skip <ids>`, `--yes`, `--verbose`,
`-o <path>`, `--force`, `--from-other-user`, `--unredacted`, `--deep`.

Restore does the safe things by default. The three phases that install software
or reach the network are opt-in, because each one is long, unattended, and worth
choosing deliberately:

| Flag | What it adds to `restore --apply` |
|---|---|
| `--install-apps` | Installs missing applications with `brew install --cask` |
| `--clone-repos` | Clones the recorded repositories |
| `--install-toolchains` | Reinstalls global npm/gem/pipx/cargo packages |

`--install-apps` is worth knowing about. Homebrew only reports software Homebrew
installed, so an app that arrived as a disk image looks unrecoverable — but most
of them have a cask anyway. On the machine this was developed against, all ten
"hand-installed" apps had one, so the manual reinstall list was empty. macstash
resolves the cask at capture and hands the list to Homebrew; it never downloads
from a URL it chose itself.

Git remotes and tap URLs are hidden by default, because terminal output gets
screenshotted. `--unredacted` shows them.

## Contributing a catalog entry

Everything macstash knows lives in `internal/catalog/entries/*.yaml`, embedded in
the binary. A contribution is a fifteen-line pull request:

```yaml
id: iterm2
name: iTerm2
category: terminal
detect:
  app: /Applications/iTerm.app
capture:
  defaults:
    - domain: com.googlecode.iterm2
  paths:
    - path: ~/Library/Application Support/iTerm2/DynamicProfiles
      class: public
restore:
  quit_first: true            # iTerm2 rewrites its plist on quit
  permissions: [full_disk_access]
```

The accumulated `quit_first` flags, permission lists and scrub patterns *are* the
product. They are what nobody else has written down.

CI rejects any entry naming a path on the never list. That list lives in Go
(`internal/classify/never.go`), not YAML, so a catalog change cannot reach around
it.

## Building

```
go build -o macstash ./cmd/macstash
go test ./...
./scripts/check-imports.sh
```

Apache-2.0. Local-only, single-machine, no commercial tier. The security posture
is the differentiator and is never traded for convenience.
