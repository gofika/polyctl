# polyctl

`polyctl` is a single command-line tool for the accounts most small teams end up juggling: cloud platforms (AWS, GCP, Alibaba Cloud), CDN/DNS (Cloudflare) and domain registrars (name.com, GoDaddy).

It does two things at once:

- **Platform-neutral commands** (`polyctl dns ...`, `polyctl domain ...`) work on any domain regardless of where it lives. polyctl looks the domain up in a local index, finds the account that owns it and routes the call there.
- **Platform-specific commands** (`polyctl cloudflare ...`, `polyctl aws ...`, ...) expose each platform's native features with that platform's own vocabulary. Nothing is flattened to a lowest common denominator.

Everything it learns about your accounts is cached in a local SQLite inventory, so reads are instant and work offline; writes always go to the platform and update the cache.

## Features

- Six platforms: Cloudflare, name.com, GoDaddy, AWS, GCP, Alibaba Cloud.
- Profiles that group accounts: one profile holds one account on each platform a project uses (`acme` = its Cloudflare, name.com and AWS accounts), and you can keep as many profiles as you have projects or customers.
- Secrets in the OS keyring (macOS Keychain, Windows Credential Manager, Secret Service on Linux) with an automatic fallback to a `0600` file; `config.yaml` never holds a secret.
- Domain routing: `polyctl dns list example.com` finds the right zone and account by itself. Conflicts (the same domain in two accounts) are reported instead of guessed; `--profile` and `--platform` pick one.
- Local inventory (`inventory.db`): per-resource-type TTLs, `--refresh` to force a fetch, `--offline` to forbid the network, `polyctl sync` to bulk-load.
- `table` (default), `json` and `yaml` output for every command.
- Distinct exit codes for usage, auth, not-found, ambiguous, offline and not-supported errors.
- Shell completion for bash, zsh, fish and PowerShell, including profile, platform, domain-name and record-id completion from the local inventory.

## Install

Prebuilt binaries are published for macOS, Linux and Windows (x86-64 and ARM64). No Go toolchain is needed.

### Homebrew (macOS, Linux)

```sh
brew install --cask gofika/tap/polyctl
```

Shell completions for bash, zsh and fish are installed with it. Upgrade with `brew upgrade --cask polyctl`.

### Scoop (Windows)

```powershell
scoop bucket add gofika https://github.com/gofika/scoop-bucket
scoop install polyctl
```

Upgrade with `scoop update polyctl`.

### Install script

macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/gofika/polyctl/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/gofika/polyctl/main/install.ps1 | iex
```

The scripts download the latest release for your platform, verify its SHA-256 checksum and install the binary into `~/.local/bin` (macOS, Linux) or `%LOCALAPPDATA%\polyctl\bin` (Windows, added to your user `PATH`). Run the same command again to upgrade.

| Variable | Effect |
| --- | --- |
| `POLYCTL_VERSION` | Install a specific version (for example `0.3.0`) instead of the latest release. |
| `POLYCTL_INSTALL_DIR` | Install the binary into this directory. |

```sh
curl -fsSL https://raw.githubusercontent.com/gofika/polyctl/main/install.sh | POLYCTL_VERSION=0.3.0 POLYCTL_INSTALL_DIR="$HOME/bin" sh
```

### Manual download

Download the archive for your platform from the [releases page](https://github.com/gofika/polyctl/releases), check it against `checksums.txt`, and put `polyctl` somewhere on your `PATH`.

### Build from source

For contributors; requires Go.

```sh
git clone https://github.com/gofika/polyctl.git
cd polyctl
make build        # writes bin/polyctl
```

### Shell completion

Homebrew installs completions automatically, and the release archives ship them under `completions/`. To generate them yourself:

```sh
# bash
polyctl completion bash > /etc/bash_completion.d/polyctl        # or: source <(polyctl completion bash)

# zsh
polyctl completion zsh > "${fpath[1]}/_polyctl"                 # then restart the shell

# fish
polyctl completion fish > ~/.config/fish/completions/polyctl.fish

# PowerShell
polyctl completion powershell | Out-String | Invoke-Expression
```

Completion is context-aware: `--profile`, `auth use` and the first argument of `auth rename` complete configured profiles, `auth login`, `auth logout` and `--platform` complete platform names, and the `<domain>` argument of `dns` / `domain` commands completes from the local domain index.

## Quick start

```sh
# 1. Log in to the accounts you use (secrets go to the keyring).
#    With no profile current, the first login creates the profile "default"
#    and makes it current; the following ones add their platform to it.
polyctl auth login cloudflare
polyctl auth login namecom
polyctl auth login aws --set method=sso --set start_url=https://acme.awsapps.com/start --set sso_region=us-east-1

#    A second project gets its own profile
polyctl auth login cloudflare --profile acme
polyctl auth login godaddy    --profile acme

# 2. Check that everything works
polyctl auth status

# 3. Build the domain index (which account owns which domain / zone)
polyctl domain index

# 4. Use platform-neutral commands; routing is automatic
polyctl domain which example.com
polyctl dns list example.com
polyctl dns set example.com --type A --name www --value 203.0.113.10
polyctl domain ns set example.com ns1.cloudflare.com ns2.cloudflare.com

#    When several accounts know the domain, say which one you mean
polyctl dns list example.com --platform cloudflare
polyctl dns list example.com --profile acme --platform cloudflare

# 5. Or talk to one platform directly
polyctl aws ec2 instance list                 # the AWS account of the current profile
polyctl cloudflare zone list --profile acme   # the Cloudflare account of another profile
```

Status lines (`zone example.com via cloudflare/default`) go to **stderr**; results go to **stdout**, so `polyctl dns list example.com -o json | jq` works as expected.

## Configuration

All state lives in one directory, `~/.config/polyctl/` by default (created with mode `0700`):

| File | Purpose |
| --- | --- |
| `config.yaml` | Profiles and settings. Metadata only, never secrets. Written atomically with mode `0600`. |
| `inventory.db` | SQLite cache of platform resources and the domain index. |
| `credentials.json` | Secrets, **only** when the OS keyring is unavailable or `credential_store: file` is set. Mode `0600`. |
| `credentials.lock` | Empty lock file next to it. polyctl holds a lock on it while it changes stored secrets, so that several polyctl processes running at once do not drop each other's entries. Safe to delete when no polyctl is running. |

### Environment variables and global flags

| Variable | Effect |
| --- | --- |
| `POLYCTL_CONFIG_DIR` | Use this directory instead of `~/.config/polyctl`: it holds `config.yaml`, the file credential store and `inventory.db`. `--config-dir` overrides it. |
| `POLYCTL_OUTPUT` | Output format (`table`, `json`, `yaml`). `--output` overrides it; it overrides the `output:` key in `config.yaml`. |
| `POLYCTL_CREDENTIAL_STORE` | Overrides `credential_store` in `config.yaml` (`auto`, `keyring`, `file`). |
| `POLYCTL_INVENTORY_DB` | Path of the SQLite inventory file (default `<config dir>/inventory.db`). |
| `POLYCTL_NON_INTERACTIVE` | `1`, `true` or `yes` forces the non-interactive flow, like `--non-interactive`: nothing is ever asked. `0`, `false`, `no` or empty leave it off; any other value is a usage error (exit code 2). See [Interactive and non-interactive use](#interactive-and-non-interactive-use). |

| Global flag | Effect |
| --- | --- |
| `--config-dir <dir>` | The configuration directory: the one that holds `config.yaml`, the file credential store (`credentials.json`) and `inventory.db`. The exact counterpart of `POLYCTL_CONFIG_DIR`, which it overrides. Created with mode `0700` when missing. |
| `-p, --profile <name>` | Use this profile. Overrides the current profile and restricts automatic routing, `sync`, `domain index` and `auth status` to the accounts of this profile. For `auth login` it names the profile the account is added to. |
| `--refresh` | Ignore the cache: fetch from the platform and update the inventory. |
| `--offline` | Never touch the network; serve from the inventory only. Mutually exclusive with `--refresh`. |
| `-o, --output <fmt>` | `table` (default), `json` or `yaml`. Overrides `POLYCTL_OUTPUT` and `output:` in `config.yaml`. |
| `-v, --verbose` | Extra diagnostics on stderr. |
| `-y, --yes` | Assume "yes" for confirmations (multi-record `dns delete`, `aliyun ecs instance stop`, the interactive `auth logout`, the removal inside `auth manage`), in both flows. In the non-interactive flow it is the only way to confirm: without it such a command is a usage error (exit code 2). It confirms, it does not choose: a missing argument is still asked for on a terminal, and still a usage error without one. |
| `--non-interactive` | Force the non-interactive flow, also on a terminal: never ask, choose or confirm anything. Missing arguments and unconfirmed actions are usage errors (exit code 2) that name what to pass. Same as `POLYCTL_NON_INTERACTIVE=1`, which the flag overrides: `--non-interactive=false` keeps a terminal interactive although the variable is set. With `--yes`: no question at all, and destructive actions proceed. |
| `--version` | Print the build version. |

Every setting follows one rule of precedence: **command-line flag > environment variable > `config.yaml` > built-in default**. So `--config-dir` beats `POLYCTL_CONFIG_DIR`, `--output` beats `POLYCTL_OUTPUT` beats `output:`, `POLYCTL_CREDENTIAL_STORE` beats `credential_store:`, and `--non-interactive` beats `POLYCTL_NON_INTERACTIVE`: either one switches the non-interactive flow on, and `--non-interactive=false` leaves the choice to the terminal check even when the variable is set. (Nothing makes a command interactive without a terminal on stdin and stderr.)

Help never depends on a setting: `--help`, `polyctl help <command>`, bare `polyctl` and a bare command group (`polyctl dns`, `polyctl aws ec2`) print help and exit with code 0 without reading the configuration or creating the configuration directory. `polyctl help` followed by a word that names no command is a usage error (exit code 2), like the command itself.

Flags that only some commands have are local to them:

- `auth login` and `auth manage` take `--no-browser`: during a login, print URLs instead of opening a browser. It is implied in the non-interactive flow, which never opens one.
- The `dns` and `domain` command groups take `--platform <platform>`, which routes to the account on that one platform (and restricts any indexing to it); see [Routing rules](#routing-rules).
- `sync` and `inventory list` have a `--platform` of their own, a filter that takes a list of platforms; see [Caching](#caching).

### `config.yaml`

```yaml
current_profile: acme             # the profile platform commands and `auth login` use by default
credential_store: auto            # auto (default) | keyring | file
output: table                     # table | json | yaml

ttl:                              # freshness window per resource type (Go durations)
  default: 24h
  dns_record: 1h
  zone: 24h
  domain: 24h
  instance: 15m

profiles:
  acme:                           # one profile, one account per platform
    platforms:
      cloudflare:
        metadata:
          account_id: 0123456789abcdef0123456789abcdef
          email: ops@example.com
        credential_backend: keyring
        created_at: 2026-11-01T10:00:00Z
        updated_at: 2026-11-01T10:00:00Z
      namecom:
        metadata:
          username: acme
          env: production
        credential_backend: keyring
      aws:
        metadata:
          method: sso
          start_url: https://acme.awsapps.com/start
          sso_region: us-east-1
          account_id: "123456789012"
          role_name: AdministratorAccess
          region: eu-west-1
        credential_backend: keyring
  lab:
    platforms:
      aws:
        metadata:
          method: keys
          region: us-east-1
        credential_backend: keyring
```

Keys:

- `current_profile`: the profile a **platform-specific** command uses when you did not pass `--profile`, provided it has an account on that platform. If it has none, polyctl falls back to "the only profile with an account on that platform", and errors with the candidate list when there are several. It is also the profile `auth login` adds an account to when `--profile` is not given. Set by `auth use`, and by `auth login` when no profile is current. A value that names no profile (after a hand edit) is treated as not set: `auth login` then says so, uses `default` and makes that profile current.
- `credential_store`: `auto` tries the keyring and falls back to the file (printing a warning once); `keyring` fails if no keyring is available; `file` always uses `credentials.json`.
- `ttl`: how long a synced set stays fresh. Unset types use `default`; the built-in defaults are `dns_record: 1h`, `zone: 24h`, `domain: 24h`, `instance: 15m`, `default: 24h`.
- `output`: default output format.
- `profiles.<name>.platforms.<platform>`: the profile's account on one platform; `<platform>` is one of `cloudflare`, `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. A profile holds at most one account per platform.
- `profiles.<name>.platforms.<platform>.metadata`: non-secret values the provider needs (account id, region, project, login method...). Populated by `auth login`; you can edit them by hand.
- `profiles.<name>.platforms.<platform>.credential_backend`: where the secret was written (`keyring` or `file`). Written by polyctl, also when a refreshed token moves the secret from the file to the keyring. `auth rename` and `auth logout` use it to tell whether the secret is within reach in this run.
- `profiles.<name>.platforms.<platform>.created_at` / `updated_at`: when the account was first added and last logged in.
- `profiles.<name>.platforms.<platform>.legacy_secret`: written by polyctl only, while an account converted from a 0.1.x config still has its secret under the old key (see [Upgrading from 0.1.x](#upgrading-from-01x)). It disappears once the secret has been moved, or once the backend that would hold it says there is none.
- `profiles.<name>.platforms.<platform>.legacy_backend`: written by polyctl only, next to `legacy_secret`, when the account was logged in again while the backend holding the old entry was out of reach: it names that backend, so the old entry can still be removed once the backend is available.

Profile names must not contain spaces or slashes.

Files written by 0.1.x, where a profile was a single platform (`profiles.<name>.platform: cloudflare` with `metadata` next to it), are still read: each such profile becomes a profile holding that one platform. See [Upgrading from 0.1.x](#upgrading-from-01x). A profile that mixes the two layouts is rejected when the config is loaded (exit code 2) instead of being loaded with a part of it dropped: both a `platform:` and a `platforms:` key (keep only `platforms:`), a `platform:` key without a value, or `metadata`, `credential_backend`, `created_at` or `updated_at` set on the profile itself without `platform:` (move them under `platforms.<platform>`).

polyctl reads `config.yaml` when a command starts and writes it back as a whole. If the file was changed in between, by another polyctl process or by hand, the command does not save its older copy over that change: it fails with "the config file was changed since it was read", changes nothing in the file, and can simply be run again. `auth login` reads the file again after its login flow, which can wait for you for minutes, so changes made meanwhile are kept and the login is still saved. `auth logout` checks the file before it removes anything: the interactive form reads it again after its last question and removes what is still there (an entry that is gone by then is skipped with a note), and `auth logout --profile` works on the file as it is when the removal starts. A removal that still finds the file changed stops with nothing removed.

### Credential storage

`auth login` stores the secret of each account as one keyring entry (service `polyctl`, account = `<profile>/<platform>`, for example `acme/cloudflare`) through `github.com/zalando/go-keyring`:

- macOS: Keychain
- Windows: Credential Manager
- Linux / BSD: Secret Service (GNOME Keyring, KWallet via the D-Bus API)

When the keyring cannot be reached (headless servers, containers, no D-Bus session), polyctl falls back to `<config dir>/credentials.json` with mode `0600` and prints a one-line warning. Reads consult both backends, so an account created on a headless box keeps working after a keyring becomes available, and vice versa. `auth logout` removes the secret from every backend. In the file backend the entries of `credentials.json` are keyed the same way. Changes to stored secrets are serialised between polyctl processes with a lock on `credentials.lock`, so commands started in parallel (from a script, say) do not lose each other's entries.

Force a backend with `credential_store: file` / `keyring` in `config.yaml` or the `POLYCTL_CREDENTIAL_STORE` environment variable.

### `inventory.db` schema

The inventory is a WAL-mode SQLite database with three tables:

```sql
CREATE TABLE resources (
  platform      TEXT    NOT NULL,     -- cloudflare, aws, ...
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,     -- domain | zone | dns_record | instance
  resource_id   TEXT    NOT NULL,     -- platform-native id (domain name for type domain)
  name          TEXT    NOT NULL,
  parent_id     TEXT    NOT NULL DEFAULT '',   -- zone id for dns_record
  domain        TEXT    NOT NULL DEFAULT '',   -- apex / zone name used for routing
  data          TEXT    NOT NULL,     -- JSON, the platform-native object
  updated_at    INTEGER NOT NULL,     -- unix seconds
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, resource_id)
);

CREATE TABLE domain_index (            -- domain -> owning resource (zones and registered domains only)
  domain        TEXT NOT NULL,
  platform      TEXT NOT NULL,
  profile       TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   TEXT NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (domain, platform, profile, resource_type, resource_id)
);

CREATE TABLE sync_state (              -- freshness of each synced set
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  scope         TEXT    NOT NULL DEFAULT '',   -- '' = whole type, or a zone id for per-zone record sets
  synced_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, scope)
);
```

`resources.data` keeps each object in its platform-native shape (serialised as JSON), so `-o json` on a cached read shows the same fields a live read would. The version of that JSON is kept in SQLite's `user_version`; whenever a database is opened that still holds DNS records written by 0.1.x, their `content` field is renamed to `value`, so they keep their values without a new sync. `domain_index` is rebuilt from `zone` and `domain` resources on every sync; DNS records are never indexed, they are looked up through their zone. The file is safe to delete at any time: polyctl recreates it and re-fetches on demand.

`polyctl inventory path` prints the database actually in use (`POLYCTL_INVENTORY_DB` when set, otherwise `<config dir>/inventory.db`).

## Interactive and non-interactive use

polyctl has two call flows, and every command behaves the same way within one of them.

- **Interactive**: a person at a terminal. A missing argument may be asked for with an arrow-key list, destructive actions ask for confirmation (default No), and login flows prompt for credentials and open a browser.
- **Non-interactive**: scripts, CI, pipes, cron. polyctl never shows a menu, never asks you to choose or confirm anything, never reads an answer from a terminal and never opens a browser, so it never waits for a person. What the interactive flow would have asked for has to be passed; when it is missing the command fails right away with a usage error (exit code 2) that names the argument, flag, `--set` key or environment variable to pass, and changes nothing.

The flow is decided once per command, in one place:

| Situation | Flow |
| --- | --- |
| stdin **and** stderr are terminals | interactive |
| stdin or stderr is not a terminal (pipe, redirect, `</dev/null`, CI, cron) | non-interactive |
| `--non-interactive`, or `POLYCTL_NON_INTERACTIVE` set to `1` / `true` / `yes` | non-interactive, also on a terminal |

`--yes` / `-y` means "assume yes for confirmations" in both flows. On a terminal it skips the confirmation questions only; a missing argument is still asked for. `--non-interactive --yes` together mean no question at all, and destructive actions proceed.

In the non-interactive flow stdin is data, not a conversation: a piped `y` does not confirm anything and piped lines do not answer questions. stdin is read only where a command says so: `--set key=-` on `auth login` reads the value of that one key (one line per such key, in the order given, no label printed), and nothing else: no login reads a token from stdin on its own, so a pipe that stays open without data never blocks a command. Notes and errors are plain lines on stderr (no colours, no drawing), results go to stdout.

What each command asks, and what it needs instead:

| Command | Interactive flow asks | Non-interactive flow requires |
| --- | --- | --- |
| `auth login` | the platform, from a list | `auth login <platform>` |
| `auth login <platform> --set key=-` | the value of `key`, typed at a prompt (hidden for secrets) | the value piped on stdin, one line per `key=-` |
| `auth use` | the profile, from a list | `auth use <profile>` |
| `auth logout [platform]` | the accounts to remove (multiple choice), "Remove N entries?" and "Keep cached inventory?"; `--yes` skips the two confirmations | `--profile <name>` (naming the profile is the confirmation; `--keep-inventory` keeps the cache) |
| `auth manage` | everything, in a menu | not available: use `auth list`, `auth use <profile>`, `auth login <platform>`, `auth status`, `auth rename <old> <new>`, `auth logout [platform] --profile <name>` |
| `dns delete <domain>` matching several records | "delete N records in zone ... (y/N)" after listing them; `--yes` skips it | `--yes` (the matching records are still listed on stderr with the refusal) |
| `aliyun ecs instance stop <instance-id>` | "stop instance ... (y/N)"; `--yes` skips it | `--yes` (refused before the account is opened) |
| `auth login cloudflare` | the API token (after opening the token page); the account, when the token sees several | `CLOUDFLARE_API_TOKEN` or `--set token=-` (stdin is read only for `--set token=-`); `--set account_id=<id>` when the token sees several accounts |
| `auth login namecom` | username and API token | `--set username=<user>` and `--set token=-` |
| `auth login godaddy` | the Personal Access Token (or, with `--set method=api_key`, key and secret) | `--set token=-`, or `--set api_key=<key> --set api_secret=-` |
| `auth login aws` | the method | `--set method=sso\|keys\|profile` |
| `auth login aws --set method=keys` | access key id, secret access key, optional session token | `--set access_key_id=<id> --set secret_access_key=-` (and `--set session_token=-`), or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`) |
| `auth login aws --set method=profile` | the AWS profile name (default `default`) | nothing: `--set aws_profile=<name>`, else the profile of the previous login, else `default` |
| `auth login aws --set method=sso` | start URL, Identity Center region; then, after the browser approval, the account and the role when several are accessible | `--set start_url=<url>` (the region defaults to `us-east-1`, or `--set sso_region=`); `--set account_id=<id>` and `--set role_name=<name>` when several are accessible |
| `auth login gcp` (`adc`) | the project, from the visible ones | nothing when the project is unambiguous (`--set project=<id>`, the previous login's, the ADC project, the only visible one); otherwise `--set project=<id>` |
| `auth login gcp --set method=service_account` | the key file path; the project when the key names none | `--set key_file=<path>`; `--set project=<id>` when the key names none |
| `auth login gcp --set method=oauth` | client id and secret; the project | `--set client_id=<id> --set client_secret=- --set project=<id>` |
| `auth login aliyun` | AccessKey ID and Secret, region | `--set access_key_id=<id> --set access_key_secret=-`, or `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, or `--set aliyun_profile=<profile>`; the region defaults to the previous login's, then `cn-hangzhou` |

A re-authentication (`auth login` for an account the profile already has) reuses what the previous login recorded (username, start URL, account, role, project, region, method), so in the non-interactive flow usually only the secret has to be passed again.

Two login flows need a person in a browser but nothing typed into polyctl, so they stay available in the non-interactive flow: polyctl prints the URL, does not open a browser, and waits for a bounded time.

- `auth login aws --set method=sso` prints the verification URL and code and polls until the device code expires (the lifetime AWS gives the code; 10 minutes when it names none). If the approved login can access several accounts or roles and `--set account_id` / `--set role_name` were not given, it then fails with a usage error that lists them, so pass both in scripts.
- `auth login gcp --set method=oauth` prints the consent URL and waits up to 5 minutes for the browser to return to its loopback listener. On a terminal it waits until you press Ctrl-C.

Every other command (`auth list`, `auth status`, `auth rename`, `sync`, `inventory`, `domain`, `dns list` / `set` / `add`, single-record `dns delete`, and the remaining platform-specific commands) asks nothing in either flow.

```sh
# scripts and CI: nothing is asked
printf '%s\n' "$NAMECOM_TOKEN" | polyctl auth login namecom --profile acme --set username=acme --set token=-
polyctl dns delete example.com --type A --name www --yes
polyctl aliyun ecs instance stop i-0123456789 --yes

# the same guarantees on your own terminal
polyctl --non-interactive auth use            # usage error: auth use: <profile> is required
POLYCTL_NON_INTERACTIVE=1 polyctl dns delete example.com --type A --name www
#   usage error: confirmation required: pass --yes to proceed (would delete 2 records in zone example.com)
```

## Accounts

A **profile** is a named set of accounts, at most one per platform. It usually stands for one project or one customer: the profile `acme` holds acme's Cloudflare account, its name.com account and its AWS account, so one name selects all of them. Two accounts on the same platform (production and a test environment, two AWS organisations) go into two profiles. Commands:

```text
polyctl auth login <platform> [--profile <name>] [--set key=value ...]
polyctl auth list
polyctl auth use <profile>
polyctl auth status [--profile <name>]
polyctl auth rename <old> <new>
polyctl auth logout [platform] --profile <name> [--keep-inventory]
polyctl auth manage
```

- `auth login` runs the platform's login flow, stores the secret and writes the account's metadata to `config.yaml`. The account is added to `--profile` when given, otherwise to the current profile, otherwise (no profile is current, or `current_profile` names a profile that does not exist) to a profile named `default`; a profile that does not exist is created, and the target profile becomes current if none was. Logging in to a platform the profile already has re-authenticates that account and leaves the profile's other accounts alone. Without `--profile`, when the target profile has no account on the platform but another profile does, nothing is changed and the command fails with a usage error (exit code 2) that lists those profiles: pass `--profile <name>` to re-authenticate one of them, or `--profile <target>` to really add a second account on that platform. Platform-specific inputs are passed with `--set key=value` (repeatable); `--set key=-` reads the value of that key from stdin instead of the command line. Anything not given is asked in the interactive flow; in the non-interactive flow nothing is asked, no browser is opened, and a value or choice that is still missing is a usage error (exit code 2) naming the `--set` key (see [Interactive and non-interactive use](#interactive-and-non-interactive-use)). Every login flow verifies against the platform, so with `--offline` `auth login` fails with exit code 6 before anything is asked, read from stdin or stored. Platform names accept aliases (`cf`, `name.com`, `gd`, `google`, `alibaba`, ...). `--set` takes the keys of that platform only (see [Login flows per platform](#login-flows-per-platform)); an unknown key is a usage error (exit code 2) listing the valid ones.
- `auth list` shows one row per account: profile, platform, whether the profile is current (`*`), the credential backend and a summary of the metadata. A profile without accounts gets one row too, marked `(no accounts)`; in JSON and YAML that row has `name` and `current` only, no `platform`.
- `auth use` sets `current_profile`; an unknown profile is an error (exit code 4). In the interactive flow, `auth use` without a name asks which profile; when no profile is configured there is nothing to pick, which is a `nothing to do` note and exit code 0. In the non-interactive flow the name is required (usage error, exit code 2).
- `auth status` calls the platform of every account (or only those of `--profile`) to verify the stored credentials and prints the resolved identity (account, user, email, ARN, project...), one row per account. It exits with code 3 if any account fails. With `--offline` it only checks that credentials are present.
- `auth rename <old> <new>` renames a profile. Its accounts, their secrets (copied to the `<new>/<platform>` keys before the old entries are deleted) and their cached resources move to the new name, and `current_profile` follows when it was the renamed profile. An unknown `<old>` is an error (exit code 4); a `<new>` that already exists, is empty or contains spaces or slashes is a usage error (exit code 2). If a step fails before `config.yaml` is saved, the copies are removed and the profile keeps its old name. A profile with an account still marked `legacy_secret` (see [Upgrading from 0.1.x](#upgrading-from-01x)) cannot be renamed until the old entry has been moved or removed: the message names the backend that has to be available for that, or says to log in to the account again when the backend is not on record or the entry could not be moved. An old account that simply has no stored secret is not held back by this. The rename is also refused, with nothing changed, when an account's `credential_backend` names a backend that is not available in this run (for example `keyring` while only the file store is in use), because its secret could not be moved.
- `auth logout --profile <name>` removes the whole profile: every account in it, their secrets from every backend, and their cached resources from the inventory (keep those with `--keep-inventory`). `auth logout <platform> --profile <name>` removes only that account; the profile itself is removed when it was its last one. The platform is optional; `--profile` is required, except in the interactive flow, where leaving it out opens a list of accounts to choose from (see [Interactive management](#interactive-management)). `config.yaml` is saved after each removed account; if it was changed by another process in the meantime the command stops before anything of the next account is removed (see [Configuration](#configuration)). When an account's `credential_backend` names a backend that is not available in this run, the account is still removed from `config.yaml`, with a warning that its credentials in that backend were not removed; the same goes for an old 0.1.x entry recorded in `legacy_backend`. Removing the current profile leaves no current profile until the next `auth use` or `auth login`. `auth logout <platform> --profile <name>` for a platform the profile has no account on is an error (exit code 4); the interactive list with no account to offer (none at all, or none on the given platform) is not: it prints a `nothing to do` note and exits with code 0.

```sh
polyctl auth login cloudflare --profile acme     # creates the profile acme (and makes it current if no profile was)
polyctl auth login namecom    --profile acme     # adds a second platform to it
polyctl auth use acme                            # later logins and platform commands default to acme
polyctl auth login aws                           # added to acme, provided no other profile has an AWS account
polyctl auth login aws --profile acme            # always unambiguous
polyctl auth rename acme acme-prod               # same accounts, secrets and cache under a new name
polyctl auth logout namecom --profile acme-prod  # drop one account
polyctl auth logout --profile acme-prod          # drop the whole profile
```

### Interactive management

In the interactive flow, `polyctl auth manage` opens a menu for everything above (it is interactive only: without a terminal, with `--non-interactive` or with `POLYCTL_NON_INTERACTIVE=1` it is a usage error that names the commands to use instead). It prints the table of `auth list` (accounts, and profiles without accounts) and offers:

| Menu entry | What it does |
| --- | --- |
| View account details | Pick an account and see its profile, platform, credential store, whether credentials are present, creation and update times, every metadata key, and how many resources of each type are cached. Nothing is fetched from the platform. |
| Switch current profile | `auth use`, with the profile picked from a list. |
| Add an account (log in) | Pick a platform, then an existing profile or "New profile..." (you type the name), then the login flow of `auth login` runs. The profile is chosen explicitly, as with `--profile`. |
| Verify credentials | Tick the accounts to check (Ctrl-A ticks all) and get the table of `auth status`. |
| Rename a profile | `auth rename`, with the profile picked from a list. |
| Remove accounts or profiles | Tick any number of accounts across profiles. polyctl lists what will be removed (a profile goes when its last account does), asks for confirmation (default No), asks whether to keep the cached inventory (default No), then removes them the way `auth logout` does. With `--yes` (`auth manage --yes`) both questions are skipped: the ticked entries are removed right after the selection, and their cached inventory with them. |
| Quit | Leave the menu (`q` does the same). |

Arrow keys or `j` / `k` move, space ticks an entry of a multiple choice, `/` filters a list, enter confirms; the keys are shown under every question, the ones that confirm and leave first, so a narrow terminal still shows them. In a yes/no question `y` and `n` select the answer, which is underlined (it shows without colours too), and enter confirms it; they do not answer on their own, so a habitual `y` + enter never runs on into the next question. A multiple choice needs at least one ticked entry: enter with nothing ticked keeps the question open and says so, until an entry is ticked. Keys pressed before a yes/no question appeared are discarded, so nothing typed ahead confirms it. Esc or Ctrl-C leaves the current question and returns to the menu; at the top level Esc, Ctrl-C or `q` leaves the menu, with exit code 0. While a `/` filter is in use Esc first closes the filter input, then clears the filter if one is applied, and only then leaves the question. A filter that matches nothing takes no enter: change the text, or press Esc. While the filter text is typed, space and the editing keys belong to the text (Ctrl-U deletes it, Ctrl-A and Ctrl-E jump to its ends, Ctrl-K and Ctrl-D delete forward) and do not tick or move anything; the arrow keys still move. The key hints only list what works in the current state. Labels too long for the terminal are cut with an ellipsis, and a terminal that does not report its size is treated as 80 by 24. A failing action is reported and the menu stays open. An action that finds nothing to act on (no profile to switch to, no account to show) prints a `nothing to do` note, not an error, and the menu stays open too.

The menu can stay open for a long time, so it reads `config.yaml` again before it draws the table and before every action: changes made meanwhile by other polyctl commands show up and are kept. An action whose save fails changes nothing, in the file or in the table.

In the interactive flow three commands ask for a missing argument the same way instead of failing:

```sh
polyctl auth use                 # pick the profile from a list
polyctl auth login               # pick the platform, then the usual login
polyctl auth logout              # tick the accounts to remove, then confirm
polyctl auth logout cloudflare   # the same, listing Cloudflare accounts only
```

`--yes` skips the confirmations of the interactive `auth logout` (the cached inventory is then removed unless `--keep-inventory` is given). Leaving one of these prompts prints `cancelled`, changes nothing and exits with code 0. So does having nothing to choose from: with no profile for `auth use`, or no account for `auth logout`, the command prints a `nothing to do: ...` note instead of a list and exits with code 0.

The questions of a login flow (token, key, region, ...) can be left the same way: Ctrl-C, or Ctrl-D on an empty line, ends `auth login` with `cancelled` and exit code 0, stores nothing, and inside `auth manage` returns to the menu. A secret is never echoed, and the terminal is put back as it was. On Windows Ctrl-C at such a question interrupts the command, which also leaves `auth manage`.

Prompts and menus are drawn on stderr, so stdout still carries results only. They appear only in the interactive flow, when both stdin and stderr are terminals and neither `--non-interactive` nor `POLYCTL_NON_INTERACTIVE` is set: in a pipe, a script or CI the same invocations fail with a usage error (exit code 2) that names the argument to pass, and `auth manage` says which commands to use instead. polyctl never waits for an answer there; see [Interactive and non-interactive use](#interactive-and-non-interactive-use).

### Upgrading from 0.1.x

In 0.1.x a profile was a single account on a single platform. From 0.2 on a profile is a named set of accounts, one per platform.

- **`config.yaml` is converted automatically.** Each old profile becomes a profile of the same name holding that one platform; profile names, `current_profile`, metadata and the inventory are kept. Nothing has to be done by hand.
- **Secrets move to new keys.** They were stored under the bare profile name and now live under `<profile>/<platform>` (for example `cloudflare/cloudflare` for an old profile named `cloudflare`). The first command that opens the credential store copies each secret to its new key, deletes the old entry and rewrites `config.yaml` in the new layout. An account that turns out to have no secret at all (the backend named in its `credential_backend` is in use and holds nothing under either key) is rewritten without the mark as well: there is nothing to move, and `auth login` gives it a secret again. Until the move has succeeded for an account, for example because its secret sits in a keyring this machine cannot reach right now, or because the old config does not say which backend held it and not every backend is in use, the account stays marked as legacy (`config.yaml` keeps the old layout, or shows `legacy_secret: true` once it has been rewritten), keeps reading the old entry, and the move is retried on later runs. `-v` prints any error met while moving a secret. Logging in to such an account again while that backend is still out of reach stores the new secret where it can, and the mark stays, with `legacy_backend` naming the backend of the old entry, until a run that can reach it removes the entry. Several polyctl processes started at the same time after the upgrade take turns at this.
- **`auth login <platform>` no longer names the profile after the platform.** In 0.1.x `polyctl auth login cloudflare` wrote the profile `cloudflare`; now it targets the current profile (or `default`). To re-authenticate a converted profile, pass its old name: `polyctl auth login cloudflare --profile cloudflare`. If you forget, polyctl does not quietly create a second account: when the platform is configured only in other profiles, the login stops with a usage error naming them.
- **`auth logout` takes an optional platform.** `polyctl auth logout --profile <name>` still removes the whole profile; `polyctl auth logout <platform> --profile <name>` removes one account of it.
- **Merging is optional.** To gather converted one-platform profiles into one, log the platforms in again under a common `--profile` and remove the old profiles with `auth logout` (or tick them in `auth manage`). A converted profile that only has an unfortunate name, like `cloudflare`, does not need a new login: `polyctl auth rename cloudflare acme` keeps its account, secret and cached resources.

**Renamed flags, variables, commands and fields.** The command line was tidied before it freezes at 1.0. Nothing below has an alias (apart from `cf`): an old spelling is an unknown flag or command and exits with code 2, so update scripts when you upgrade.

Global flags and environment:

- **Without a terminal polyctl no longer reads answers from stdin.** 0.1.x took every prompt (token, username, `y/N`) from a piped stdin; the non-interactive flow asks nothing and reads stdin only where a command line says so. A token or username piped to `auth login` is ignored: pass `--set token=-` (one line of stdin per `key=-`) together with `--set username=...`, `--set method=...` and whatever else the platform needs, so `echo "$TOKEN" | polyctl auth login cloudflare` becomes `echo "$TOKEN" | polyctl auth login cloudflare --set token=-`, and `auth login aws` needs `--set method=`. A piped `y` no longer confirms a multi-record `dns delete` or `aliyun ecs instance stop`: pass `--yes`. What is missing is a usage error (exit code 2) naming what to pass. See [Interactive and non-interactive use](#interactive-and-non-interactive-use).
- New: `--non-interactive` and `POLYCTL_NON_INTERACTIVE=1` force that flow on a terminal as well. (Builds from `main` before 0.2.0 called them `--no-input` / `POLYCTL_NO_INPUT`; those spellings are gone.)
- `--config <file>` is now `--config-dir <dir>`: it names the directory that holds `config.yaml`, the file credential store and `inventory.db`, exactly like `POLYCTL_CONFIG_DIR`, and overrides that variable. Replace `--config /path/to/config.yaml` with `--config-dir /path/to`; the file inside is always called `config.yaml`.
- `POLYCTL_OUTPUT` now overrides `output:` in `config.yaml` (it used to be the other way round). Every setting is resolved flag > environment > config file > default.
- `--no-browser` is a flag of `auth login` and `auth manage` only, no longer a global one: write it after the command (`polyctl auth login aws --no-browser`).
- A word that names no subcommand of a group (`polyctl dns nosuch`, or any command removed below) is now a usage error with exit code 2; it used to print the group's help and exit with code 0. The same goes for `polyctl help dns nosuch`.

Platform-neutral commands:

- `dns update <domain> ...` is now `dns set <domain> ...` (create the record, or update the one with that name and type), and `dns update ... --add` is now `dns add <domain> ...` (always create one more record). The `--add` flag is gone.
- `domain ns set <domain> --ns a,b` is now `domain ns set <domain> a b`: nameservers are arguments, at least one, and an argument may still be a comma-separated list (`a,b`). The `--ns` flag is gone, here and in the `namecom`, `godaddy`, `aliyun` and `aws` trees.
- `--proxied true|false` is now a boolean flag: `--proxied` or `--proxied=false`. `--proxied false` with a space is a usage error that says so.
- `inventory list --platform` and `--type` take lists (comma-separated or repeated), as on `sync`. A single value still works.
- `domain which` now narrows its list with `--profile` / `--platform`; it used to accept and ignore them. Drop the flags to see every owner.
- A record's data is `value` in the output as well: the table column `CONTENT` is now `VALUE`, and the `content` field of `-o json` / `-o yaml` records is now `value` (`jq '.records[].content'` becomes `jq '.records[].value'`). DNS records already cached in `inventory.db` are converted when the database is opened (also later, should a 0.1.x binary write to the same directory again); nothing has to be synced again.

Platform-specific commands:

| 0.1.x | now |
| --- | --- |
| `cf ...` | `cloudflare ...` (`cf` remains as an alias) |
| `cf token verify` | `cloudflare whoami` |
| `namecom hello` | `namecom whoami` |
| `aws sts whoami` | `aws whoami` |
| `aliyun sts whoami` | `aliyun whoami` |
| (none) | `gcp whoami`, `godaddy whoami` |
| `cf dns update <zone> --id <id>`, `cf dns delete <zone> --id <id>` | `cloudflare dns update <zone> <id>`, `cloudflare dns delete <zone> <id>` |
| `namecom dns update <domain> --id <id>`, `namecom dns delete <domain> --id <id>` | `namecom dns update <domain> <id>`, `namecom dns delete <domain> <id>` |
| `aliyun dns record update <domain> --id <id>`, `aliyun dns record delete <domain> --id <id>` | `aliyun dns record update <domain> <id>`, `aliyun dns record delete <domain> <id>` |
| `aliyun dns record add` | `aliyun dns record create` |
| `godaddy dns replace` | `godaddy dns upsert` |
| `godaddy domain available` | `godaddy domain check` |
| `aws route53domains domain list`, `aws route53domains domain get <domain>` | `aws route53domains list`, `aws route53domains get <domain>` |
| `aws ec2 list\|start\|stop` | `aws ec2 instance list\|start\|stop` |
| `gcp compute list\|start\|stop` | `gcp compute instance list\|start\|stop` |
| `aliyun ecs list\|start\|stop` | `aliyun ecs instance list\|start\|stop` |
| `<platform> ... ns set <domain> --ns a,b` | `<platform> ... ns set <domain> a b` |
| `cf dns create\|update ... --proxied true\|false` | `cloudflare dns create\|update ... --proxied` / `--proxied=false` |

`--id` stays a flag where it is an optional second way to address a record: `dns delete`, `godaddy dns delete` and `gcp dns record delete`. The output of the `whoami` commands has one shape on every platform now (`profile`, `platform`, `identity`), which differs from what `cf token verify`, `namecom hello` and the two `sts whoami` commands printed.

Login options (`auth login --set key=value`):

- A `--set` key the platform does not know is now a usage error (exit code 2) that lists the valid keys, before anything is read or asked; 0.1.x ignored it. That includes the two renamed keys below.
- Alibaba Cloud: `from_cli=<profile>` is now `aliyun_profile=<profile>`.
- GoDaddy legacy key pair: `key=` / `secret=` are now `api_key=` / `api_secret=`.
- Option values have one spelling each; the undocumented aliases are usage errors now: GCP `method=adc|service_account|oauth` (not `service-account` or `sa`), GoDaddy `method=pat|api_key` (not `token`, `key`, `sso-key`, `sso_key`) and `env=production|ote` (not `prod`, `test`), name.com `env=production|test` (not `prod`, `dev`, `development`). Accounts that are already stored keep working: what `config.yaml` and the credential store hold is read as before.

### Login flows per platform

Browser-based flows open your default browser; pass `--no-browser` to `auth login` (or `auth manage`) to print the URL instead (useful over SSH). What follows describes the interactive flow first. In the non-interactive flow no browser is opened, nothing is asked and nothing is read from a terminal: each platform's "Non-interactive" line says what to pass, and whatever is still missing is a usage error (exit code 2) naming the `--set` key. Any `--set key=-` reads that value from stdin, one line per key in the order given, which keeps secrets out of the process list and the shell history.

#### Cloudflare

Uses an API token. polyctl opens <https://dash.cloudflare.com/profile/api-tokens>, where you create a token (the "Edit zone DNS" template is a good start; required: `Zone:Read` and `DNS:Edit`; optional: `Account:Read` to list accounts, `Zone:Edit` for cache purge / development mode / SSL mode, `User:Read` to show your email), then prompts for it. Non-interactive: export `CLOUDFLARE_API_TOKEN` (the same variable Terraform and wrangler use), or pass `--set token=-` with the token on stdin; `--set token` wins over the variable, and without either the login is a usage error (exit code 2). stdin is read only for `--set token=-`: a token piped without it is ignored, so a login whose stdin is an idle pipe fails at once instead of waiting.

```sh
polyctl auth login cloudflare                                        # added to the current profile (or to "default" when no profile is current)
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile acme --set account_id=...
polyctl auth login cloudflare --profile acme --set token=...         # works, but warns: the token lands in shell history / process list
```

`account_id` is optional; when omitted polyctl discovers the accounts the token can see and asks you to pick one if there are several. In the non-interactive flow several accounts are a usage error that lists them: pass `--set account_id=<id>` (a re-authentication keeps the account it had). The token is verified before it is stored.

#### name.com

Username plus API token. polyctl opens <https://www.name.com/account/settings/api> for token creation and prompts for both values. Non-interactive: `--set username=<user> --set token=-` with the token on stdin; a missing one is a usage error (the two are never read as lines of a piped conversation).

```sh
polyctl auth login namecom --profile acme
printf '%s\n' "$NAMECOM_TOKEN" | polyctl auth login namecom --profile acme --set username=acme --set token=-   # scripts
polyctl auth login namecom --profile acme-test --set username=acme --set token=... --set env=test   # a second name.com account needs its own profile
```

`env=test` points the account at name.com's test environment (`api.dev.name.com`). That environment requires a token generated for it and your username with `-test` appended; polyctl adds the suffix automatically when it is missing. `env` takes `production` (the default) or `test`; any other value is a usage error. API access must be enabled in the account settings, and name.com may require your IP address to be whitelisted there.

#### GoDaddy

Personal Access Token (PAT) created at <https://developer.godaddy.com/personal-access-token>. GoDaddy does not offer an OAuth flow for third-party CLIs, so polyctl opens that page and prompts for the token. The legacy API key + secret pair is still accepted (`--set api_key=... --set api_secret=...`, which selects `--set method=api_key` by itself) but GoDaddy has deprecated it for the Domains API. Non-interactive: `--set token=-` with the token on stdin (legacy pair: `--set api_key=<key> --set api_secret=-`); a missing value is a usage error. `method` takes `pat` (the default) or `api_key`; any other value is a usage error, also when a credential is passed along, and so is a method that contradicts the credential given (`method=api_key` with `token=`, `method=pat` with `api_key=` / `api_secret=`) or a token together with the pair.

```sh
polyctl auth login godaddy --profile acme
printf '%s\n' "$GODADDY_TOKEN" | polyctl auth login godaddy --profile acme --set token=-   # scripts
polyctl auth login godaddy --profile acme-ote --set token=... --set env=ote
polyctl auth login godaddy --profile legacy --set api_key=... --set api_secret=-   # legacy API key pair, the secret on stdin
```

`env=ote` targets the OTE environment at `api.ote-godaddy.com`; `env` takes `production` (the default) or `ote`, and any other value is a usage error. For production API access GoDaddy requires the account to hold at least one domain or be on a plan that grants API management access; paid operations need a billing method on file. Requests that fail this check return `403 ACCESS_DENIED`, which polyctl reports as an authentication failure (exit code 3) with a hint to use an OTE credential for development.

#### AWS

Three methods, selected with `--set method=`. On a terminal the method is asked for when it is not given; in the non-interactive flow `--set method=` is required (a re-authentication keeps its method).

| Method | What happens |
| --- | --- |
| `sso` (default) | IAM Identity Center device-code flow. polyctl registers an OIDC client, opens the verification URL in your browser, waits for approval and stores the SSO token. `--set start_url=`, `--set sso_region=`, `--set account_id=`, `--set role_name=` are prompted for when omitted; when the token can access several accounts/roles you pick one. Non-interactive: `--set start_url=` is required (`sso_region` defaults to `us-east-1`), the URL and code are printed without opening a browser and polyctl waits for the approval until the code expires; `--set account_id=` and `--set role_name=` are required when several are accessible (otherwise a usage error lists them). Short-lived role credentials are minted on each use and refreshed automatically; when the SSO session itself expires, run `auth login` again. |
| `keys` | Static access key id (prompted) and secret access key (prompted without echo), optionally a session token. They can be passed instead with `--set access_key_id=<id> --set secret_access_key=-` (and `--set session_token=-`), or, when neither of the two is given with `--set`, taken as a whole from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`; then nothing is asked. Non-interactive: one of those is required, and the session token is never asked for. |
| `profile` | Delegate to a profile in `~/.aws/config` / `~/.aws/credentials` (`--set aws_profile=<name>`). Nothing is copied; polyctl stores only a reference and lets the AWS SDK's own credential chain resolve it. Non-interactive: without `--set aws_profile=` the profile of the previous login is used, else `default`, with a note. |

`--set region=` sets the default region for regional services (EC2). Route 53 and Route 53 Domains are global.

```sh
polyctl auth login aws --profile acme --set method=sso --set start_url=https://acme.awsapps.com/start --set sso_region=us-east-1 --set account_id=123456789012 --set role_name=AdministratorAccess --set region=eu-west-1
polyctl auth login aws --profile lab --set method=keys
printf '%s\n' "$SECRET" | polyctl auth login aws --profile ci --set method=keys --set access_key_id=AKIA... --set secret_access_key=-   # scripts
polyctl auth login aws --profile legacy --set method=profile --set aws_profile=default
```

#### GCP

| Method | What happens |
| --- | --- |
| `adc` (default) | Uses Application Default Credentials. If none exist polyctl prints the `gcloud auth application-default login` command to run (and opens the ADC documentation page), then exits with code 3; re-run `auth login` after completing it. (The page is not opened in the non-interactive flow.) |
| `service_account` | `--set key_file=<path>`; the service-account JSON key is read and its contents stored in the credential store. `--set project=` defaults to the key's `project_id`. Non-interactive: `--set key_file=` is required, and `--set project=` when the key names no project. |
| `oauth` | Your own OAuth client (`--set client_id=`, `--set client_secret=`); polyctl opens the consent screen, receives the code on a loopback listener and stores the refresh token. Non-interactive: `--set client_id=`, `--set client_secret=-` and `--set project=` are all required up front (a re-authentication keeps its project); the URL is printed without opening a browser and polyctl waits up to 5 minutes for the browser to return. |

`--set method=` takes exactly `adc`, `service_account` or `oauth`; any other value is a usage error.

`--set project=` sets the default project; when omitted polyctl lists the projects the credentials can see and asks you to choose. In the non-interactive flow nothing is asked: the project of the previous login, then the ADC project, then the only visible project is used (with a note); several visible projects and no default are a usage error that lists them.

```sh
polyctl auth login gcp --profile acme --set project=acme-prod
polyctl auth login gcp --profile acme-ci --set method=service_account --set key_file=./sa.json --set project=acme-ci
```

#### Alibaba Cloud

RAM AccessKey pair from <https://ram.console.aliyun.com/manage/ak>. polyctl opens the page and prompts for the key id and secret, then for the region. Both can be passed with `--set access_key_id=<id> --set access_key_secret=-` or, when neither is given with `--set`, taken as a pair from `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`; then they are not asked for. Non-interactive: one of those, or `--set aliyun_profile=`, is required, and the region is never asked for (`--set region=`, else the CLI profile's, else the previous login's, else `cn-hangzhou`).

```sh
polyctl auth login aliyun --profile acme --set region=cn-hangzhou
printf '%s\n' "$AK_SECRET" | polyctl auth login aliyun --profile ci --set access_key_id=LTAI... --set access_key_secret=-   # scripts
polyctl auth login aliyun --profile acme --set aliyun_profile=default   # import from an `aliyun` CLI profile
```

`--set aliyun_profile=<name>` names a profile of the Alibaba Cloud CLI (`~/.aliyun/config.json`, or the file named by `ALIBABA_CLOUD_CLI_CONFIG`; `aliyun_profile=current` picks the CLI's current profile; only AK-mode profiles can be imported). It is the counterpart of `aws_profile` with one difference: the AccessKey of that profile is copied into polyctl's credential store, not referenced, so later changes to the CLI profile are not picked up until the next login. `--set region=` is the default region for ECS (default `cn-hangzhou`); Alidns is region-independent. `--set site=cn|intl` selects the Domain (registrar) API site: `cn` for aliyun.com accounts, `intl` for alibabacloud.com accounts; when omitted it is derived from the region (`cn-*` = `cn`, otherwise `intl`). Grant the RAM user `AliyunDNSFullAccess`, `AliyunDomainFullAccess` and/or `AliyunECSReadOnlyAccess` as needed.

## Platform-neutral commands

These commands take a domain name and route it to the account that owns it: a platform and a profile. Both command groups accept `--profile <name>` and `--platform <platform>` to narrow the choice; `--platform` names one platform here (it routes to the account on that platform) and takes the same names and aliases as `auth login`.

### DNS

```text
polyctl dns list   <domain> [--type A] [--name www]
polyctl dns set    <domain> --type <T> --value <V> [--name www|@] [--ttl 300] [--priority 10] [--proxied[=false]]
polyctl dns add    <domain> --type <T> --value <V> [--name www|@] [--ttl 300] [--priority 10] [--proxied[=false]]
polyctl dns delete <domain> (--type <T> [--name www|@] [--value <V>] | --id <record-id>) [-y]
```

Every `dns` command also takes `[--profile <name>] [--platform <platform>]`.

- `<domain>` may be the zone apex or any name under it (`www.example.com` resolves to the `example.com` zone). `--name` is relative to the zone (`www`, `@`); when omitted, the record name is `<domain>` itself.
- `dns set` creates or updates, keyed on name + type: one existing record is updated (TTL, priority and proxy status are kept unless given), none means create. Several existing records are an error that changes nothing and points to `dns add` and `dns delete`.
- `dns add` always creates one more record and leaves the existing ones of that name and type alone; this is how round-robin `A` records or several `TXT` / `MX` records are built up.
- A record's data is called its **value** everywhere: the `--value` flag, the `VALUE` table column and the `value` field of `-o json` / `-o yaml`, so what a command prints can be passed back to another.
- In tables, a TTL that is a platform marker rather than a number of seconds is shown by name: `auto` (Cloudflare automatic TTL, `1` in the API), `alias` (Route 53 alias records, which use the target's TTL) and `default` (a GoDaddy record just written without `--ttl`). `-o json` and `-o yaml` keep the raw value.
- `dns delete` with a selector that matches several records shows them and asks for confirmation (skip with `-y`). Answering no, or leaving the question, deletes nothing: the command prints `nothing to do: no record was deleted` and exits with code 0. In the non-interactive flow (no terminal, `--non-interactive`, `POLYCTL_NON_INTERACTIVE=1`) the question is never asked and stdin is not read: the records are shown, nothing is deleted, and the command fails with the usage error `confirmation required: pass --yes to proceed (would delete N records in zone <domain>)` (exit code 2) unless `-y` is given. A selector that matches no record is an error (exit code 4). `--value` narrows the match; `--id` deletes exactly one record by platform id (here the id is an optional second way to address a record, so it is a flag).
- `--proxied` applies to Cloudflare only and is a boolean flag: `--proxied` switches the proxy on, `--proxied=false` switches it off (the `=` is required: a boolean flag does not take its value from the next argument), and without it `dns set` keeps what the record has and `dns add` uses Cloudflare's default. The `PROXIED` column appears for Cloudflare zones.
- After a successful write the record is upserted into (or removed from) the inventory, so the next `dns list` shows it without a refresh.

### Domains

```text
polyctl domain info  <domain>
polyctl domain ns get <domain>
polyctl domain ns set <domain> <nameserver>...
polyctl domain which <domain>
polyctl domain index [--profile <name>] [--platform <platform>]
polyctl domain list  [--refresh] [--profile <name>] [--platform <platform>]
```

`domain info`, `ns get` and `ns set` also take `[--profile <name>] [--platform <platform>]`.

- `domain info` combines the registrar view (status, expiry, auto-renew, lock, privacy, nameservers) with the DNS zone that serves the domain and the zone's nameservers; either half may be absent if only one kind of account knows the domain. `--platform` applies to both halves, so with it the half that lives on another platform is reported as a note on stderr.
- `domain ns get` / `ns set` read and write the nameservers **at the registrar** (name.com, GoDaddy, Route 53 Domains, Alibaba Cloud Domains). `ns set` takes the nameservers as arguments, at least one: `polyctl domain ns set example.com ns1.example.net ns2.example.net`. An argument may itself be a comma-separated list (`ns1.example.net,ns2.example.net`), which helps when pasting. The platform trees' `ns set` commands have the same shape.
- `domain which` prints every index entry for the domain and its parents: kind (`zone` or `domain`), platform, profile, resource id and when it was indexed. Without `--profile` / `--platform` every owner is shown, so this is the place to look when routing surprises you. With them the list is narrowed to the owners in that profile and on that platform, as on `domain list`; a domain that has no owner under the selection is not found (exit code 4), and an unknown profile (exit code 4) or platform (exit code 2) is reported as such.
- `domain index` fetches zones and registered domains from every domain-capable account of every profile and rebuilds the index; `--profile` and `--platform` limit it to the matching accounts. `domain list` prints the index, narrowed by `--profile` / `--platform` when given (`--refresh` re-indexes first). For both, an unknown `--profile` is an error (exit code 4). A `--profile` / `--platform` selection that names no domain-capable account is not: `domain list` lists nothing, and `domain index` has nothing to index, as it has when no domain-capable account is configured at all. It then prints an empty report on stdout (the table header, or `[]` with `-o json`) and a `nothing to do: ...` note on stderr, and exits with code 0.

### Routing rules

1. Without `--profile` and `--platform`, every account of every profile is searched. `--profile <name>` restricts the search (and any indexing) to the accounts of that profile, `--platform <platform>` to the accounts on that platform; together they name exactly one account.
2. Among those accounts polyctl looks up the domain and each of its parents (`a.b.example.com`, `b.example.com`, `example.com`) in `domain_index`, restricted to the kind the command needs (`zone` for `dns ...`, `domain` for registrar operations). **The longest matching domain wins**, so a delegated sub-zone `b.example.com` beats its parent zone.
3. If the best match belongs to more than one account, the command fails with exit code 5, lists the candidates as `platform/profile (kind resource-id)` and names the flag that tells them apart: `--profile` when they are in different profiles, `--platform` when they are on different platforms, either or both when both differ.
4. If nothing matches, polyctl indexes the relevant accounts automatically the first time (when no index exists yet for any of them) or when `--refresh` is given, then retries. Otherwise it reports "domain not found in local index" (exit code 4) and suggests `polyctl domain index` or `--refresh`; when only some of the accounts have never been indexed, the message lists them as `platform/profile`.
5. With `--offline` no indexing happens; an unknown domain is an error.
6. An unknown `--profile`, or a `--profile` / `--platform` pair that names no account able to hold the domain, is reported as such (exit code 4), with `--offline` too, and not as a domain missing from the index.

The usual source of ambiguity is a single profile, not two. A registrar account lists every domain it holds as a zone too (name.com and GoDaddy do), so when the profile `acme` has the domain at name.com and serves its DNS from Cloudflare, both accounts report a zone `example.com` and `--profile` cannot tell them apart:

```text
$ polyctl dns list example.com
error: ambiguous owner of zone "example.com": candidates are [cloudflare/acme (zone 9a1...) namecom/acme (zone example.com)]; pass --platform <platform> to choose

$ polyctl dns list example.com --platform cloudflare
zone example.com via cloudflare/acme
...
```

Registrar operations (`domain ns ...`) are not affected in this setup, because only name.com holds the registration. `--platform` cannot separate two resources of the same account with one name (two Route 53 hosted zones called `example.com`, say); for those, use the platform's own command with the resource id.

The status line on stderr always tells you which account was used, as `<platform>/<profile>`, for example `zone example.com via cloudflare/acme (local inventory)`.

## Caching

Every read goes through the inventory:

| Situation | Behaviour |
| --- | --- |
| Set is cached and younger than its TTL | Served from `inventory.db`; the output notes `(local inventory)`. |
| Set is missing or expired | Fetched from the platform, stored, then served. |
| `--refresh` | Always fetched and stored. |
| `--offline` | Always served from the cache, even if expired. A set that was never synced is an error (exit code 4); any command that must write to a platform fails with exit code 6. |

TTLs are per resource type (`ttl:` in `config.yaml`, defaults `dns_record: 1h`, `zone: 24h`, `domain: 24h`, `instance: 15m`). DNS records are tracked per zone, so listing one zone never forces a fetch of every zone in the account.

```text
polyctl sync [--platform cloudflare,aws] [--profile <name>] [--type domain,zone,dns_record,instance]
polyctl inventory stats
polyctl inventory list [--platform cloudflare,aws] [--type domain,zone,dns_record,instance] [--name <exact name>] [--profile <name>]
polyctl inventory path
```

- `sync` fetches the selected resource types (default: everything each platform supports) for the selected accounts (default: every account of every profile; `--profile` keeps one profile's accounts, `--platform` keeps the given platforms) and **replaces** them in the inventory atomically, one set at a time. It prints a per-set report (count, duration, failures). An authentication failure stops the sync of that account. An unknown `--profile` is an error (exit code 4), an unknown platform or type a usage error (exit code 2). Having nothing to sync is not an error: when the selection names no account (a `--profile` without an account on the given `--platform`, or a platform nobody is logged in to), when no selected account supports the requested `--type`, or when no account is configured at all, `sync` prints an empty report on stdout (the table header, or `[]` with `-o json`) and a `nothing to do: ...` note on stderr, and exits with code 0.
- `inventory stats` shows row counts and the synced/expiry time of each set; `inventory list` dumps cached rows, filtered by `--profile`, `--name` and by `--platform` / `--type`, which take lists exactly as on `sync` (comma-separated or repeated; an unknown platform or type is a usage error); `inventory path` prints the database path.

## Platform-specific commands

Each platform has its own subtree, named after its platform id: `cloudflare` (also available under the alias `cf`), `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. Profile selection for these commands is `--profile` (which must have an account on that platform, otherwise the command fails with exit code 3) > `current_profile` (if it has an account on that platform) > the only profile that has one > an error listing the candidates (exit code 5). They honour `--refresh` / `--offline` for list operations the same way the neutral commands do, and always write through to the platform.

The trees follow each platform's own model, but the same operation has the same verb and shape in all of them:

- **`<platform> whoami`** verifies the account's credentials against the platform and shows the identity behind them. It exists at the top of all six trees and prints the same shape everywhere: `profile`, `platform` and `identity` (`account`, `user`, and an `extra` map with what else the platform reports). It needs the network (exit code 6 with `--offline`); credentials that no longer work exit with code 3.
- **Registrar groups** have `list`, `get <domain>`, `ns get <domain>` and `ns set <domain> <nameserver>...`.
- **Platforms that give every record an id** (Cloudflare, name.com, Alibaba Cloud) have `create`, `update <zone-or-domain> <record-id>` and `delete <zone-or-domain> <record-id>`. The record id is required there, so it is an argument.
- **Platforms that address records by name and type** (Route 53, Cloud DNS, GoDaddy) have `upsert`, which sets the whole record set, and a `delete` that takes `--name` / `--type`. There `--id` is an optional second way to pick one record, so it stays a flag, as on the neutral `dns delete`.
- **Compute services** name the resource: `<service> instance list|start|stop`.

### Cloudflare (`polyctl cloudflare`, alias `polyctl cf`)

```text
cloudflare whoami                 # verifies the API token; shows its id, status and expiry
cloudflare zone list              cloudflare zone get <zone|id>
cloudflare dns list <zone> [--type] [--name]
cloudflare dns create <zone> --type A --name www --value 203.0.113.10 [--ttl 1] [--proxied[=false]] [--priority] [--comment]
cloudflare dns update <zone> <record-id> [--type] [--name] [--value ...] [--ttl ...] [--priority] [--proxied[=false]] [--comment]
cloudflare dns delete <zone> <record-id>
cloudflare cache purge <zone> (--everything | --url <url>... | --host <h>... | --tag <t>... | --prefix <p>...)   # host/tag/prefix need Enterprise
cloudflare dev-mode <zone> [on|off]       # Development Mode (bypass cache for 3 hours)
cloudflare ssl-mode <zone> [off|flexible|full|strict]
cloudflare account list
```

Every command above can be written with `cf` in place of `cloudflare` (`polyctl cf zone list`). Inventory types: `zone`, `dns_record`. Record ids are the Cloudflare record ids; `proxied` is the orange cloud, a boolean flag: `--proxied` switches it on, `--proxied=false` off, and without the flag `dns update` keeps the current setting.

### name.com (`polyctl namecom`)

```text
namecom whoami                    # GET /v4/hello: user name, environment, server time
namecom domain list               namecom domain get <domain>
namecom domain ns get <domain>    namecom domain ns set <domain> <nameserver>...
namecom domain lock <domain>      namecom domain unlock <domain>
namecom domain autorenew <domain> on|off
namecom domain check <name>...  # availability and price
namecom dns list <domain> [--type] [--name]
namecom dns create <domain> --type A --name www --value 203.0.113.10 [--ttl 300] [--priority]
namecom dns update <domain> <record-id> [--type] [--name] [--value] [--ttl] [--priority]
namecom dns delete <domain> <record-id>
```

Inventory types: `domain`, `zone`, `dns_record` (every name.com domain is also its own zone).

### GoDaddy (`polyctl godaddy`)

```text
godaddy whoami                    # verified by listing one domain: method, environment
godaddy domain list [--status ACTIVE,EXPIRED]   godaddy domain get <domain>
godaddy domain ns get <domain>    godaddy domain ns set <domain> <nameserver>...
godaddy domain lock <domain>      godaddy domain unlock <domain>
godaddy domain autorenew <domain> on|off
godaddy domain check <name>...  # availability and price
godaddy dns list <domain> [--type] [--name]
godaddy dns add <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority]             # one more record; the others stay
godaddy dns upsert <domain> --type A --name www --value <v> [--value <v>...] [--ttl] [--priority]   # sets the whole name+type set
godaddy dns delete <domain> (--type A --name www | --id <TYPE|name|value>)
```

Inventory types: `domain`, `zone`, `dns_record`. GoDaddy has no per-record ids; records are addressed by type + name. `upsert` creates the record set or replaces all of it (the API's "replace all records of this type and name"), like `record upsert` on Route 53 and Cloud DNS; `add` appends one record to the set. polyctl derives a stable synthetic id of the form `TYPE|name|value` (each part percent-encoded, e.g. `TXT|@|v=spf1%20include:_spf.example.com%20~all`) so the neutral `dns` commands and `godaddy dns delete --id` can target single records.

### AWS (`polyctl aws`)

```text
aws whoami                                        # sts GetCallerIdentity: account, ARN, user id
aws route53 zone list                             aws route53 zone get <zone-id|name>
aws route53 record list <zone> [--type] [--name]
aws route53 record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300]
aws route53 record delete <zone> --type A --name www               # deletes the whole record set
aws route53domains list                           aws route53domains get <domain>
aws route53domains ns get <domain>                aws route53domains ns set <domain> <nameserver>...
aws ec2 instance list [--region <r>]              aws ec2 instance start <instance-id> [--region]     aws ec2 instance stop <instance-id> [--region] [--force]
```

Inventory types: `zone`, `dns_record`, `domain`, `instance`. `route53domains` is this tree's registrar group, the counterpart of `domain` in the other trees.

Route 53 stores a *record set* (name + type) with several values. polyctl exposes **one record per value** both in the inventory and in `dns list`, with a synthetic id of the form `<zone-id>|<TYPE>|<name>|<set-identifier>|<value>` (each part URL-encoded); updating or deleting one of them rewrites the whole record set with that value changed or removed. `record upsert` with several `--value` flags writes the set in one call.

### GCP (`polyctl gcp`)

```text
gcp whoami                        # the profile's project, account and login method
gcp project list                  gcp project current
gcp dns zone list                 gcp dns zone get <managed-zone>
gcp dns record list <zone> [--type] [--name]
gcp dns record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300]
gcp dns record delete <zone> (--type A --name www [--value <v>] [--priority] | --id <zone|TYPE|name|value>)
gcp compute instance list                         gcp compute instance start <instance> [--zone <z>] [--wait]     gcp compute instance stop <instance> [--zone <z>] [--wait]
```

Inventory types: `zone`, `dns_record`, `instance`. Cloud DNS record sets are split one record per value exactly like Route 53 (see above); writes are applied as a single atomic change.

### Alibaba Cloud (`polyctl aliyun`)

```text
aliyun whoami                                     # sts GetCallerIdentity: account, ARN, identity type
aliyun dns domain list                            # Alidns domains (zones)
aliyun dns record list <domain> [--type] [--name]
aliyun dns record create <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority] [--line default|telecom|unicom|mobile|oversea]
aliyun dns record update <domain> <record-id> [--name] [--type] [--value] [--ttl] [--priority] [--line]
aliyun dns record delete <domain> <record-id>
aliyun domain list                                aliyun domain get <domain>       # registered domains
aliyun domain ns get <domain>                     aliyun domain ns set <domain> <nameserver>...
aliyun ecs instance list [--region]               aliyun ecs instance start <instance-id> [--region]     aliyun ecs instance stop <instance-id> [--region] [--force]
```

`aliyun ecs instance stop` asks for confirmation on a terminal (default No; declining is a `nothing to do` note and exit code 0) unless `--yes` is given. In the non-interactive flow it never asks: without `--yes` it is a usage error (exit code 2) raised before the account is opened.

Inventory types: `zone` (Alidns domains), `dns_record`, `domain` (registered domains), `instance`. Alidns stores the relative record name as `RR`; both the native `aliyun dns record` commands and the neutral `dns` commands expose it as `--name`. Records also carry a resolution line (`--line`), shown in the `LINE` column.

## Output formats

```sh
polyctl dns list example.com                 # table (default)
polyctl dns list example.com -o json         # pretty-printed JSON
polyctl dns list example.com -o yaml
POLYCTL_OUTPUT=json polyctl auth list        # from the environment
```

Precedence: `--output` > `POLYCTL_OUTPUT` > `output:` in `config.yaml` > `table`: flag, environment, config file, default, as for every setting.

Tables are tab-aligned and contain only the most useful columns. JSON and YAML encode the full result, including routing information, for example:

```json
{
  "target": { "platform": "cloudflare", "profile": "acme", "resource_type": "zone", "resource_id": "9a1...", "domain": "example.com" },
  "cached": true,
  "records": [
    { "id": "f3c...", "zone_id": "9a1...", "name": "www.example.com", "type": "A", "value": "203.0.113.10", "ttl": 1, "proxied": true }
  ]
}
```

Human-readable progress and notes always go to stderr, so stdout is safe to pipe.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. Also a menu or selection prompt left with Esc or Ctrl-C, a question of a login flow left with Ctrl-C or Ctrl-D, and a command that had nothing to do: no account to `sync` or `domain index` (none configured, none matching `--profile` / `--platform`, none supporting `--type`), no profile or account to pick from in `auth use` / `auth logout` / `auth manage`, a declined or left confirmation of `dns delete` or `aliyun ecs instance stop`. The prompts in this row exist in the interactive flow only. |
| `1` | Generic error (API failure, I/O error, a login that was not approved in time, `config.yaml` changed by another process while the command ran, ...). |
| `2` | Usage error: bad flag combination, unknown flag or command (also below a command group: `polyctl dns nosuch`), unknown platform or resource type, missing required flag or argument, an unknown value of a login option (`--set env=`, `--set method=`), an invalid or already used name for `auth rename`, invalid config, an invalid `POLYCTL_NON_INTERACTIVE` value, `auth login` without `--profile` for a platform that only other profiles have. Also everything the non-interactive flow cannot ask for: `auth manage`, a missing argument (`auth login` without a platform, `auth use` without a profile, `auth logout` without `--profile`), a confirmation without `--yes` (`dns delete` of several records, `aliyun ecs instance stop`), and a login value or choice that was not passed (the message names the `--set` key or environment variable). |
| `3` | Authentication: missing credentials, no account on the platform in the selected profile, rejected token, expired SSO session, `auth status` with a failing account. |
| `4` | Not found: unknown domain / zone / record / profile, a `--profile` / `--platform` selection that names no account able to hold the requested domain (`dns list`, `domain info`, ...), `auth logout <platform>` for a platform the profile has no account on, or a set that was never synced in `--offline` mode. |
| `5` | Ambiguous: the domain has more than one candidate account (pass `--profile` and/or `--platform`, as the message says), or the platform more than one candidate profile (pass `--profile`). |
| `6` | Offline: the command needs the network but `--offline` was given. |
| `7` | Not supported: the platform (or the profile's client) cannot perform the operation. |

A non-zero code means the request could not be carried out. Having nothing to do is success: the command exits with code 0 and says why on stderr as a note, `nothing to do: <reason>`, without the `error:` prefix, and a command that prints a report still prints it, empty (`[]` with `-o json`), so scripts can test the exit code and parse stdout either way.

Errors are printed to stderr as `error: <message>`.

## Project layout

```text
cmd/polyctl/                 main(): calls internal/cli.Main and exits with its code
internal/cli/                Cobra command tree (root, auth, dns, domain, sync/inventory, platform mounts), exit-code mapping
internal/app/                Runtime shared by all commands: config, credential store, inventory, profile selection,
                             domain routing (ResolveDomain), cache policy (EnsureSet / NeedsRefresh), SyncAccount
internal/platform/           Provider-neutral contracts: Provider, Client, DNSService, RegistrarService, Zone/Record/Domain,
                             resource types, sentinel errors, provider registry, DNS name helpers
internal/providers/
  cloudflare/  namecom/  godaddy/  aws/  gcp/  aliyun/
                             One package per platform: provider.go (login, client, sync) and commands.go (native commands)
internal/config/             config.yaml loading/saving (profiles and their accounts), TTL defaults
internal/creds/              Keyring store, 0600 file store, Multi (read from any, write to primary)
internal/inventory/          SQLite schema, Replace/Upsert/Delete, Purge/RenameProfile, domain lookup, stats
internal/output/             table / json / yaml rendering
internal/httpx/              Small JSON REST client with retries (Cloudflare, name.com, GoDaddy)
internal/prompt/             Line / secret / confirm prompts in the flow handed to them (they refuse in the
                             non-interactive one); Picker (arrow-key select, multi-select, confirm, input) drawn on stderr
internal/browser/            Open a URL in the default browser (macOS, Windows, Linux)
```

Adding a platform means implementing `platform.Provider` (and `DNSService` / `RegistrarService` as applicable) in a new `internal/providers/<name>` package, registering it in `init()`, and mounting its Cobra subtree in `internal/cli/platforms.go`. The neutral commands, routing, caching and output need no changes.

## Security notes

- Secrets never enter `config.yaml`, the inventory or command output. `auth list` shows metadata only.
- Keyring entries are created under the service name `polyctl`; on macOS you may be asked once to allow `polyctl` access to the Keychain item.
- When the keyring is unavailable, `credentials.json` is written with mode `0600` inside a `0700` directory. Treat that file like `~/.aws/credentials`. Set `credential_store: keyring` if you would rather fail than fall back.
- `inventory.db` contains the full record data of every zone you synced (including TXT verification strings and the public IPs of instances). It is not encrypted; keep the config directory private or point `POLYCTL_INVENTORY_DB` at a protected location.
- Secrets are read from the terminal without echo. Passing them on the command line with `--set token=...` is convenient for scripts but leaves them in shell history and in the process list; prefer the interactive prompt, or `--set key=-` with the value piped on stdin by a secrets manager.
- AWS SSO role credentials and GCP OAuth access tokens are short-lived and minted on demand; polyctl stores the Identity Center access/refresh tokens (plus the registered OIDC client) and the Google refresh token, and refreshes them when possible.
- Create least-privilege tokens: Cloudflare tokens scoped to the zones you manage, GoDaddy/name.com tokens per machine, AWS roles limited to Route 53 / EC2, GCP service accounts with the DNS Administrator and Compute Instance Admin roles only.
- Network access goes directly to each platform's public API over HTTPS with a `polyctl/<version>` User-Agent; there is no telemetry and no intermediary service.

## Roadmap

- Cloud resources beyond DNS are skeletons: for AWS, GCP and Alibaba Cloud only instance listing, start and stop are implemented (`aws ec2`, `gcp compute`, `aliyun ecs`). Storage, networking, IAM and the rest of each cloud's surface are deliberately out of scope for now.
- GoDaddy and name.com registrar features beyond nameservers, lock, auto-renew and availability (transfers, contacts, purchases) are not planned for the first releases.
- Cloudflare coverage is limited to zones, DNS, cache purge, development mode and SSL mode; Workers, Pages, R2 and Access are not exposed.
- Planned: record import/export (zone-file and bulk JSON), `polyctl domain expiring` across registrars, encrypted file fallback for the credential store, and a `--watch` mode for `inventory stats`.

## License

[MIT](LICENSE)
