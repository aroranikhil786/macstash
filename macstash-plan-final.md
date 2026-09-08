# macstash — Project Plan (v1, post-review)

**Status:** Accepted for implementation, pending residual items in §9
**Date:** 8 September 2026
**Supersedes:** `macstash-plan.md` (v0 draft). Changes from v0 are listed in §10.

---

## 1. What it is

> **macstash** — capture a macOS development environment and rebuild it on another Mac. For people who never kept a dotfiles repo.

```
old Mac:   macstash capture
new Mac:   macstash restore ~/macstash/macstash-2026-09-08.tar.gz
new Mac:   macstash doctor          # what's still missing — any time later
```

The problem is not the initial setup. It's the month afterwards of discovering, one at a time, that something is missing. `doctor` is the answer to that month.

**Why it exists alongside chezmoi, Mackup, yadm, dotbot and Nix:** every one of those requires prior discipline — you already decided to manage your configuration and put it in a repo. macstash works on the machine nobody ever managed, and hands off to those tools rather than replacing them.

**Two use cases, not one.** Planned migration (laptop refresh) and disaster recovery (theft, dead SSD, IT-mandated wipe). If `capture` is cheap enough to run monthly, the tool becomes a dev-environment snapshot and migration is just one moment you use it.

---

## 2. Security posture

### 2.1 Two risk categories

- **Security risk** — a bundle is a concentrated, portable collection of a developer's configuration. If credentials were in it, leaking it would be a serious breach.
- **Employment risk** — on a company-managed laptop, creating that artifact may violate acceptable-use policy or trip a DLP agent regardless of outcome. A tool that gets someone a conversation with their security team has failed even if it never leaked a byte.

**The single most important decision in this plan: v1.0 bundles contain no credentials, under any flag.** There is no `--include-secrets`. Files that normally hold credentials are either excluded or *scrubbed* — captured with the credential lines removed and the rest intact. The cost is roughly thirty minutes of re-authentication on the new machine. The benefit is that the worst risk class cannot occur.

### 2.2 Architectural invariants

Properties that are structurally true rather than promised:

1. **macstash's own code never opens a socket.** Enforced at the import-graph level: `go list -deps ./...` must contain no package under `net` or `golang.org/x/net`, and CI fails if it does. A `grep` for `net/http` is not sufficient and is not the check.
2. **`capture` runs with network denied.** Capture needs no network at all, so it re-executes itself under a macOS sandbox profile (`sandbox-exec`, profile: `(deny network*)`). If `sandbox-exec` is unavailable, capture proceeds with a visible warning. *Note: `sandbox-exec` is deprecated but functional; see §9.*
3. **Data flows in, never out.** Restore invokes `brew`, `code`, `sdk`, `fnm`, `pyenv` — binaries the user installed and trusts — to download public packages. Nothing about the machine is transmitted anywhere.
4. **macstash never installs Homebrew.** If `brew` is absent, restore prints the official install command and exits. The user runs it, then re-runs restore. This keeps "no scripts fetched from URLs" literally true.
5. **No telemetry, analytics, crash reporting, or update check.** An update check requires network code, which would break invariant 1.
6. **Never destructive.** Anything overwritten moves to `~/.macstash/backups/<timestamp>/` with structure preserved.
7. **Refuses to run as root.**
8. **`--plan` shows every change before `--apply`.** Documented as the default in every example.
9. **Bundles are personal.** Restore refuses a bundle whose captured username differs from the current user unless `--from-other-user` is passed, and prints the code-execution warning (R4) at that point.

### 2.3 Data classification

Every captured path has exactly one class. This is the primary control.

| Class | Behaviour | Examples |
|---|---|---|
| **public** | Captured as-is | `.zshrc`, `.gitconfig`, `.vimrc`, `.tmux.conf`, `.ssh/config`, `.ssh/known_hosts`, `.ssh/*.pub`, `.aws/config`, `.editorconfig` |
| **scrub** | Captured with credential lines removed; the removal is recorded so `doctor` can report it | `.npmrc`, `.m2/settings.xml`, `.gradle/gradle.properties`, `.pypirc`, `.yarnrc.yml`, `.docker/config.json`, `.terraformrc` |
| **never** | Excluded under every flag; list lives in Go code, not YAML, and cannot be overridden by a catalog entry | see §2.4 |

**Directories are allowlist-only.** `~/.config/<tool>` is captured only when the catalog has an entry for `<tool>` that names the paths inside it. There is no wholesale capture of `~/.config`, `~/Library/Application Support`, or any other container directory. The prototype's exclude-list approach is abandoned: an exclude list is always behind the next CLI that stores a token.

**Preference plists are allowlist-only.** Third-party `defaults` domains are exported only when a catalog entry names the domain. `NSGlobalDomain` is exported as a curated key allowlist, not the whole domain, because it carries machine-specific and locale keys that break things on import.

### 2.4 The `never` list (in code)

| Category | Paths |
|---|---|
| Keychain & cookies | `~/Library/Keychains/`, `~/Library/Cookies/`, browser profile directories (Safari, Chrome, Firefox, Arc login and cookie DBs) |
| Private keys | `~/.ssh/id_*` (non-`.pub`), `~/.ssh/*.pem`, `~/.gnupg/private-keys-v1.d/`, `secring.gpg` |
| Cloud credentials | `~/.aws/credentials`, `~/.aws/sso/cache/`, `~/.aws/cli/cache/`, `~/.azure/` (`accessTokens.json`, `msal_*`), `~/.config/gcloud/` (`credentials.db`, `access_tokens.db`, `legacy_credentials/`) |
| Cluster access | `~/.kube/config`, `~/.kube/cache/` |
| Token-only files | `~/.netrc`, `~/.git-credentials`, `~/.config/gh/hosts.yml`, `~/.cargo/credentials.toml`, `~/.terraform.d/credentials.tfrc.json` |
| CLI token stores | `~/.config/op/`, `~/.config/doctl/`, `~/.config/fly*/`, `~/.wrangler/`, `~/.vercel/`, `~/.netlify/`, `~/.config/configstore/` |
| Editor secret stores | `~/Library/Application Support/Code/User/globalStorage/state.vscdb*`, the Cursor equivalent |
| Shell history | `~/.zsh_history`, `~/.bash_history`, `~/.zsh_sessions/`, `~/.local/share/fish/fish_history` |
| By pattern, anywhere in a captured tree | `.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.keystore` |

CI rejects any catalog entry whose paths match this list.

### 2.5 Scrub rules

| File | What is removed |
|---|---|
| `.npmrc` | `_authToken`, `_auth`, `_password` lines |
| `.m2/settings.xml` | `<password>`, `<passphrase>` element contents; `settings-security.xml` is never captured |
| `.gradle/gradle.properties` | keys matching `*password*`, `*token*`, `*secret*`, `*apikey*` (case-insensitive) |
| `.pypirc` | `password =` lines |
| `.yarnrc.yml` | `npmAuthToken`, `npmAuthIdent` |
| `.docker/config.json` | the `auths` object; `credsStore`, `currentContext`, `plugins` are kept |
| `.terraformrc` | `credentials` blocks |
| `.gitconfig` | any value matching `https://[^@/]+:[^@/]+@` (inline tokens in `url.*.insteadOf`) |

Each scrub is recorded in the bundle manifest as `{file, rule, count}` so that `doctor` can say: *"`~/.npmrc` is present but one registry token was removed at capture — re-authenticate with `npm login --registry …`."* That message is the difference between a fifteen-minute fix and a two-day mystery 401.

### 2.6 Secret scanner

An entropy and pattern scanner runs over everything classified `public` and over `~/bin`. **It may only ever report.** Its output is "N findings to review before you transfer this bundle," never "clean." The false-assurance risk comes from the second phrasing, so the tool does not have it.

### 2.7 Risk register

| # | Risk | Control |
|---|---|---|
| R1 | Bundle contains credentials | Structurally prevented in v1.0: no `--include-secrets`; `never` list in code; scrub for semi-config files; scanner reports the remainder |
| R2 | Bundle written into a cloud-synced folder | Refuse (without `--force`) to write under `~/Library/Mobile Documents`, `~/Library/CloudStorage/` (Dropbox, OneDrive, Google Drive, Box on macOS ≥12.1), and — when iCloud Desktop & Documents sync is enabled — `~/Desktop` and `~/Documents`. Default output: `~/macstash/`, which is never synced |
| R3 | Employee trips corporate policy or DLP | v1.0 bundles carry no credentials, which removes most of the exposure. Detect management heuristically (`profiles status -type enrollment`, plus `/usr/local/bin/jamf`, `/Library/Kandji`, Intune Company Portal) and print an advisory; **warn and proceed**, do not refuse |
| R4 | Restoring a bundle executes its author's code (`.zshrc`, `.ssh/config` `ProxyCommand`, `.gitconfig` hooks) | Inherent. Documented plainly. Username-mismatch guard (invariant 9) makes sharing between people an explicit act. `--plan` lists every file |
| R5 | LaunchAgents = persistent background execution | Not restored by default. `--include-launch-agents` required; each agent's `ProgramArguments` printed before writing |
| R6 | Archive extraction escape (zip-slip) | Reject absolute paths, `..` components, symlinks resolving outside the bundle root, hardlinks, device nodes; strip setuid/setgid bits and extended attributes. Unit-tested with malicious fixtures |
| R7 | Bundle lingers on disk after restore | Restore offers to delete the bundle on success. **No "shred" claim:** on APFS with SSDs, overwrite is not reliable and Time Machine local snapshots may retain copies. The docs say so, and say FileVault is the real protection |
| R8 | Shell history contains pasted tokens | Excluded entirely in v1 (`never` list). Revisit as opt-in with scrubbing after the scanner has a track record |
| R9 | Old configs accumulate in `~/.macstash/backups/` | 30-day retention by default; `macstash backups --prune` |
| R10 | Malicious catalog PR captures a credential path | `never` list is in code, not YAML; CI rejects catalog paths matching it; any change to `never`, `scrub`, or a class downgrade requires maintainer review |
| R11 | Restored config conflicts with MDM-managed config | Warn when a Brewfile cask duplicates a managed app; never touch `/Library` or system domains; `NSGlobalDomain` key allowlist |
| R12 | Trojaned binary in the supply chain | Published SHA-256 checksums for every release; Homebrew formula in an owned tap (formula binaries do not receive the quarantine attribute, so Gatekeeper is not a blocker on the primary install path); notarization for direct downloads once a Developer account is justified ($99/yr) |
| R13 | `brew bundle` runs cask `postflight` and third-party tap code | Inherent to Homebrew and pre-existing on the user's machine. Restore lists third-party taps explicitly before installing and continues past individual failures |
| R14 | Internal-infrastructure disclosure (SSO URLs, role ARNs, internal git remotes, tap URLs) | Bundles are personal (invariant 9). `report.md` redacts git remotes and tap URLs by default (`--unredacted` to include), because reports get screenshotted |

---

## 3. What we will not do

- No iCloud, Dropbox or any cloud-sync integration. Transfer is AirDrop, USB, or (later) a one-shot LAN transfer with no account. `macstash capture -o <any path>` already lets a user choose a synced folder if they insist — with the R2 warning.
- No LLM, no agent, no runtime inference. All knowledge is static YAML embedded in the binary.
- No fetching from arbitrary URLs. Apps installed from a DMG are reported as a manual checklist, never downloaded. Homebrew itself is never installed by macstash.
- No user files: Documents, Desktop, Downloads, Photos, git working trees.
- No fleet, MDM, or multi-user features.
- No secrets management, and in v1.0 no secrets transport at all.
- No copying of git repository contents — remote URL and branch only.

---

## 4. Command surface

| Command | Behaviour |
|---|---|
| `capture` | Scan this Mac under a no-network sandbox; produce a bundle in `~/macstash/` |
| `restore <bundle>` | Rebuild a machine. Refuses root, refuses username mismatch, refuses missing Homebrew (prints the command) |
| `doctor` | Diff the live machine against `~/.macstash/manifest.json`: missing packages, missing paths, scrubbed credentials not yet re-entered, permissions checklist, apps outside Homebrew |
| `doctor --deep` | Actually run things: `java -version` matches captured, `go build` succeeds, `git push --dry-run` authenticates, `docker info` responds |
| `inspect <bundle>` | Read a bundle's manifest and file list without applying anything |
| `catalog` | List known apps; `catalog show <id>` prints an entry |
| `clone` | Clone recorded git repos. Separate from restore because it needs SSH keys and VPN, neither of which exists at restore time |
| `backups --prune` | Apply retention to `~/.macstash/backups/` |
| `export --to <fmt>` | Convert a bundle to a Brewfile, a chezmoi source directory, or a Nix expression *(post-1.0)* |

Global flags: `--plan`, `--only <ids>`, `--skip <ids>`, `--yes`, `--verbose`, `-o <path>`, `--force`, `--from-other-user`, `--include-launch-agents`.

---

## 5. What capture collects

| # | Domain | Class | Restore action |
|---|---|---|---|
| 1 | Homebrew — `brew bundle dump` (formulae, casks, taps, mas, VS Code extensions) | public | `brew bundle install`, taps listed first |
| 2 | Dotfiles, catalog-driven | per entry | Copy, with backup of collisions |
| 3 | Preference plists, catalog-named domains only; `NSGlobalDomain` key allowlist | public | `defaults import`; `quit_first` apps checked |
| 4 | Application Support subsets, catalog-named paths only | per entry | Copy |
| 5 | Fonts (`~/Library/Fonts`) | public | Copy |
| 6 | **SDK and language versions** — SDKMAN candidates, nvm/fnm, pyenv, rbenv, Go toolchain; *exact* versions and which is default | public | `sdk install java 17.0.9-tem`, `fnm install 18.20.4`, etc. |
| 7 | **`~/bin`, `~/.local/bin`** — personal scripts | public, scanner-reported | Copy |
| 8 | Toolchain manifests — npm globals, pipx, cargo, gems, krew | public | Reinstall by name |
| 9 | **Git repo list** — remote URL, branch, relative path. Warns loudly about uncommitted changes, unpushed commits, and repos with no remote | public, redacted in report | `clone` (separate step) |
| 10 | Editor extensions — VS Code, Cursor | public | `code --install-extension` |
| 11 | Login items | public | Report only |
| 12 | Keyboard modifier remapping, key repeat, default apps per file type (`duti`), `/etc/hosts` | public | Restore where possible (`/etc/hosts` needs sudo — prompt) |
| 13 | Container runtime — Docker/OrbStack/Colima settings, `docker context` list, image names | scrub / public | Settings copied; images listed for `docker pull`, never bundled |
| 14 | Kubernetes context names (not the kubeconfig) | public | Report only |
| 15 | System inventory — `/Applications`, macOS version, arch, shell, hostname | public | `doctor` and report only |

### Reported, not automatable

Accessibility / Full Disk Access / Input Monitoring grants, Keychain, app licences and logins, Mac App Store without Apple ID, MDM-managed apps, browser profiles, **corporate CA certificates and proxy configuration** (detected in `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, JDK `cacerts`, `git http.sslCAInfo` and listed as a checklist), **git commit signing keys** (detected from `.gitconfig` and listed), credentials scrubbed at capture.

Listing these honestly in the README is a feature, not an apology.

---

## 6. Catalog

Everything macstash knows lives in `catalog/*.yaml`, embedded with `go:embed`. A contribution is a fifteen-line PR. A JSON schema and CI validation reject bad entries — including any path on the `never` list — without maintainer involvement.

```yaml
id: iterm2
name: iTerm2
category: terminal
detect:
  app: /Applications/iTerm.app
  brew_cask: iterm2
capture:
  defaults:
    - domain: com.googlecode.iterm2
  paths:
    - path: ~/Library/Application Support/iTerm2/DynamicProfiles
      class: public
skip:
  - ~/Library/Application Support/iTerm2/Cache
restore:
  quit_first: true            # iTerm2 rewrites its plist on quit
  permissions: [full_disk_access]
```

A scrub entry:

```yaml
id: npm
name: npm
category: toolchain
detect:
  command: npm
capture:
  paths:
    - path: ~/.npmrc
      class: scrub
      scrub:
        - pattern: '^\s*//.*:_authToken\s*=.*$'
          reason: registry auth token
        - pattern: '^\s*//.*:_auth\s*=.*$'
          reason: registry basic auth
```

The accumulated `quit_first` flags, permission lists, and scrub patterns *are* the product. They are what no one else has written down.

---

## 7. Restore sequence

1. **Preflight** — not root; macOS; architecture recorded; username matches bundle (or `--from-other-user`); management advisory if a managed device is detected; `--plan` output if requested.
2. **Xcode Command Line Tools** — `xcode-select --install` (Apple, interactive).
3. **Rosetta 2** on Apple Silicon — `softwareupdate --install-rosetta` (Apple).
4. **Homebrew present?** If not: print the official command, exit 0 with instructions. macstash does not install it.
5. **`brew bundle install`** — third-party taps listed first; continues past individual failures; checkpointed so a failure at minute forty does not restart from zero.
6. **SDK versions** — exact versions via the user's version managers.
7. **Dotfiles, `~/bin`, Application Support paths** — collisions backed up to `~/.macstash/backups/<ts>/`.
8. **Preferences** — `defaults import` per catalog domain; `NSGlobalDomain` allowlist; refuse a `quit_first` app that is running.
9. **Editor extensions, toolchain manifests.**
10. **Write `~/.macstash/manifest.json`** — paths, checksums, versions, scrub records. No file contents.
11. **Print the report** and the manual checklist: permissions, credentials to re-enter, apps to reinstall by hand, CA certificates, signing keys.

Every step is idempotent; the whole sequence is safe to re-run.

---

## 8. Bundle layout

```
~/macstash/macstash-<host>-<date>/
  macstash.json      # schema version, source machine, item index, checksums, scrub records
  Brewfile
  home/              # captured paths mirroring $HOME
  prefs/             # exported plists, catalog-named domains only
  manifests/         # SDK versions, toolchain lists, repo list, inventory
  report.md          # human-readable, remotes and tap URLs redacted by default
```

Written `0700` / `0600`. Packaged as `tar.gz`. No encryption in v1.0 — there is nothing in the bundle that needs it, and that is the point.

---

## 9. Residual items for external review

Small, and none block v0.1.

1. **`sandbox-exec` deprecation.** Apple has deprecated it for years without removing it. If it disappears, invariant 2 falls back to the import-graph check alone. Is that acceptable, or should capture also be offered as a `launchd`-free, network-extension-free build variant?
2. **Scrub pattern completeness.** The rules in §2.5 are per-format best knowledge. Each format deserves a reviewer who uses it daily.
3. **`.aws/config` as public.** Contains SSO start URLs, account IDs and role ARNs. Accepted because bundles are personal and the report redacts. A reviewer in a stricter environment may disagree.
4. **`~/bin` in v0.1.** Personal scripts routinely embed tokens. Included with mandatory scanner reporting; the alternative is to defer to v0.2.

---

## 10. Milestones

| | Contents |
|---|---|
| **v0.1** | `capture` (sandboxed), `restore`, `--plan`. Allowlist + scrub classification, `never` list in code, username guard, Homebrew-absent behaviour. ~30 catalog entries covering the apps in the prototype scripts. SDK version restore, `~/bin` with scanner, scrub records. Plain tarball. **A working laptop migration and nothing else** |
| **v0.2** | `doctor`, `doctor --deep`, manifest. `report.md` with redaction. Repo list, dirty-tree warnings, `clone`. Cloud-sync refusal (R2). Management advisory (R3). Backup retention |
| **v0.3** | `inspect`, `catalog`, contribution docs, schema CI including `never`-list rejection. Published checksums, owned Homebrew tap. **This is the release to announce** |
| **v1.0** | `export --to brewfile\|chezmoi`, 150+ catalog entries, corporate CA and signing-key detection in `doctor`, keyboard/default-app/`/etc/hosts` restore |
| **Not planned** | Secrets transport. Reconsidered only after an external review specifically asks for it, with `filippo.io/age` in passphrase mode as the implementation if it ever happens |

Apache-2.0. Local-only, single-machine, no commercial tier. The security posture is the differentiator and is never traded for convenience.

---

## 11. Changes from the v0 draft

| Finding | Change |
|---|---|
| Restore installed Homebrew via `curl \| bash`, contradicting the network rule | macstash never installs Homebrew; prints the command and exits (invariant 4, §7 step 4) |
| "No `net/http`" was a weak guarantee | Import-graph CI check; capture runs under a no-network sandbox (invariants 1–2) |
| "Shred" and "wipe" over-promised on APFS/SSD | Removed. Plain delete; FileVault and local-snapshot caveat stated (R7) |
| Wholesale `~/.config` and plist capture were default-open | Allowlist-only for all directories and domains; `NSGlobalDomain` key allowlist (§2.3) |
| Semi-config files (`.npmrc`, `gradle.properties`, `settings.xml`, …) were public | New **scrub** class with recorded removals; `doctor` reports them (§2.5) |
| `never` list was short and lived in YAML | Expanded (§2.4), moved into Go code, CI-enforced (R10) |
| `--include-secrets` and encryption | Removed from v1.0 entirely (§2.1); age library noted if ever revisited |
| Shell history undecided | Excluded (`never`) for v1 (R8) |
| R2 missed `~/Library/CloudStorage/` and iCloud Desktop & Documents | Added; default output `~/macstash/` (R2) |
| R6 covered paths only | Added hardlinks, device nodes, setuid, xattrs (R6) |
| R12 implied notarization was required | Clarified: formula path is unaffected by Gatekeeper; notarize later for direct downloads (R12) |
| MDM detection described as one call | Heuristic set; warn-and-proceed decided (R3) |
| `state.vscdb` was captured in the prototype | On the `never` list; noted as the archetype of "looks like state, is a token store" |
| Report leaked internal remotes and tap URLs | Redacted by default (R14) |
| Bundle sharing handled only by docs | Username-mismatch guard (invariant 9) |
| Scanner role ambiguous | Report-only, never "clean" (§2.6) |
