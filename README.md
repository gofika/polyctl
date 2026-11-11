# polyctl

`polyctl` is a single command-line tool for the accounts most small teams end up juggling: cloud platforms (AWS, GCP, Alibaba Cloud), CDN/DNS (Cloudflare) and domain registrars (name.com, GoDaddy).

It does two things at once:

- **Platform-neutral commands** (`polyctl dns ...`, `polyctl domain ...`) work on any domain regardless of where it lives. polyctl looks the domain up in a local index, finds the account that owns it and routes the call there.
- **Platform-specific commands** (`polyctl cf ...`, `polyctl aws ...`, ...) expose each platform's native features with that platform's own vocabulary. Nothing is flattened to a lowest common denominator.

Everything it learns about your accounts is cached in a local SQLite inventory, so reads are instant and work offline; writes always go to the platform and update the cache.

## Features

- Six platforms: Cloudflare, name.com, GoDaddy, AWS, GCP, Alibaba Cloud.
- Multiple profiles per platform (`work-aws`, `personal-aws`, ...), one platform per profile.
- Secrets in the OS keyring (macOS Keychain, Windows Credential Manager, Secret Service on Linux) with an automatic fallback to a `0600` file; `config.yaml` never holds a secret.
- Domain routing: `polyctl dns list example.com` finds the right zone and account by itself. Conflicts (the same domain in two profiles) are reported instead of guessed.
- Local inventory (`inventory.db`): per-resource-type TTLs, `--refresh` to force a fetch, `--offline` to forbid the network, `polyctl sync` to bulk-load.
- `table` (default), `json` and `yaml` output for every command.
- Distinct exit codes for usage, auth, not-found, ambiguous, offline and not-supported errors.
- Shell completion for bash, zsh, fish and PowerShell, including profile, platform and domain-name completion.

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

Completion is context-aware: `--profile` completes configured profiles, `auth login` completes platform names, and the `<domain>` argument of `dns` / `domain` commands completes from the local domain index.

## Quick start

```sh
# 1. Log in to the accounts you use (secrets go to the keyring)
polyctl auth login cloudflare --profile cf-main
polyctl auth login namecom    --profile namecom
polyctl auth login aws        --profile work-aws --set method=sso --set start_url=https://acme.awsapps.com/start --set sso_region=us-east-1

# 2. Check that everything works
polyctl auth status

# 3. Build the domain index (which account owns which domain / zone)
polyctl domain index

# 4. Use platform-neutral commands; routing is automatic
polyctl domain which example.com
polyctl dns list example.com
polyctl dns update example.com --type A --name www --value 203.0.113.10
polyctl domain ns set example.com --ns ns1.cloudflare.com,ns2.cloudflare.com

# 5. Or talk to one platform directly
polyctl cf zone list
polyctl aws ec2 list --profile work-aws
```

Status lines (`zone example.com via cloudflare/cf-main`) go to **stderr**; results go to **stdout**, so `polyctl dns list example.com -o json | jq` works as expected.

## Configuration

All state lives in one directory, `~/.config/polyctl/` by default (created with mode `0700`):

| File | Purpose |
| --- | --- |
| `config.yaml` | Profiles and settings. Metadata only, never secrets. Written atomically with mode `0600`. |
| `inventory.db` | SQLite cache of platform resources and the domain index. |
| `credentials.json` | Secrets, **only** when the OS keyring is unavailable or `credential_store: file` is set. Mode `0600`. |

### Environment variables and global flags

| Variable | Effect |
| --- | --- |
| `POLYCTL_CONFIG_DIR` | Use this directory instead of `~/.config/polyctl`. |
| `POLYCTL_OUTPUT` | Default output format (`table`, `json`, `yaml`). Lower priority than `--output` and the `output:` key in `config.yaml`. |
| `POLYCTL_CREDENTIAL_STORE` | Overrides `credential_store` in `config.yaml` (`auto`, `keyring`, `file`). |
| `POLYCTL_INVENTORY_DB` | Path of the SQLite inventory file (default `<config dir>/inventory.db`). |

| Global flag | Effect |
| --- | --- |
| `--config <file>` | Config file to use; its directory becomes the config directory. |
| `-p, --profile <name>` | Use this profile. Overrides automatic routing and the current profile. |
| `--refresh` | Ignore the cache: fetch from the platform and update the inventory. |
| `--offline` | Never touch the network; serve from the inventory only. Mutually exclusive with `--refresh`. |
| `-o, --output <fmt>` | `table` (default), `json` or `yaml`. |
| `-v, --verbose` | Extra diagnostics on stderr. |
| `--no-browser` | During login, print URLs instead of opening a browser. |
| `-y, --yes` | Assume "yes" on confirmation prompts (for example multi-record deletes). |
| `--version` | Print the build version. |

### `config.yaml`

```yaml
current_profile: cf-main          # used when a platform command has several candidate profiles
credential_store: auto            # auto (default) | keyring | file
output: table                     # table | json | yaml

ttl:                              # freshness window per resource type (Go durations)
  default: 24h
  dns_record: 1h
  zone: 24h
  domain: 24h
  instance: 15m

profiles:
  cf-main:
    platform: cloudflare
    metadata:
      account_id: 0123456789abcdef0123456789abcdef
      email: ops@example.com
    credential_backend: keyring
    created_at: 2026-11-01T10:00:00Z
    updated_at: 2026-11-01T10:00:00Z
  namecom:
    platform: namecom
    metadata:
      username: acme
      env: production
    credential_backend: keyring
  work-aws:
    platform: aws
    metadata:
      method: sso
      start_url: https://acme.awsapps.com/start
      sso_region: us-east-1
      account_id: "123456789012"
      role_name: AdministratorAccess
      region: eu-west-1
    credential_backend: keyring
```

Keys:

- `current_profile`: the profile a **platform-specific** command uses when you did not pass `--profile` and the profile's platform matches. If it does not match, polyctl falls back to "the only profile on that platform", and errors with the candidate list when there are several.
- `credential_store`: `auto` tries the keyring and falls back to the file (printing a warning once); `keyring` fails if no keyring is available; `file` always uses `credentials.json`.
- `ttl`: how long a synced set stays fresh. Unset types use `default`; the built-in defaults are `dns_record: 1h`, `zone: 24h`, `domain: 24h`, `instance: 15m`, `default: 24h`.
- `output`: default output format.
- `profiles.<name>.platform`: one of `cloudflare`, `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`.
- `profiles.<name>.metadata`: non-secret values the provider needs (account id, region, project, login method...). Populated by `auth login`; you can edit them by hand.
- `profiles.<name>.credential_backend`: where the secret was written (`keyring` or `file`). Informational.

Profile names must not contain spaces or slashes.

### Credential storage

`auth login` stores each profile's secret as one keyring entry (service `polyctl`, account = profile name) through `github.com/zalando/go-keyring`:

- macOS: Keychain
- Windows: Credential Manager
- Linux / BSD: Secret Service (GNOME Keyring, KWallet via the D-Bus API)

When the keyring cannot be reached (headless servers, containers, no D-Bus session), polyctl falls back to `<config dir>/credentials.json` with mode `0600` and prints a one-line warning. Reads consult both backends, so a profile created on a headless box keeps working after a keyring becomes available, and vice versa. `auth logout` removes the secret from every backend.

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

`resources.data` keeps each object in its platform-native shape (serialised as JSON), so `-o json` on a cached read shows the same fields a live read would. `domain_index` is rebuilt from `zone` and `domain` resources on every sync; DNS records are never indexed, they are looked up through their zone. The file is safe to delete at any time: polyctl recreates it and re-fetches on demand.

`polyctl inventory path` prints the database actually in use (`POLYCTL_INVENTORY_DB` when set, otherwise `<config dir>/inventory.db`).

## Accounts

A **profile** is one account on one platform. Commands:

```text
polyctl auth login <platform> [--profile <name>] [--set key=value ...]
polyctl auth list
polyctl auth use <profile>
polyctl auth status [--profile <name>]
polyctl auth logout --profile <name> [--keep-inventory]
```

- `auth login` runs the platform's login flow, stores the secret, writes the metadata to `config.yaml` and makes the profile current if none was set. The profile name defaults to the platform name. Logging in again with an existing profile name re-authenticates it (the platform must match). Platform-specific inputs are passed with `--set key=value` (repeatable); anything not given is asked interactively. Platform names accept aliases (`cf`, `name.com`, `gd`, `google`, `alibaba`, ...).
- `auth list` shows every profile, which one is current (`*`), its credential backend and a summary of its metadata.
- `auth use` sets `current_profile`.
- `auth status` calls each platform (or just `--profile`) to verify the stored credentials and prints the resolved identity (account, user, email, ARN, project...). It exits with code 3 if any profile fails. With `--offline` it only checks that credentials are present.
- `auth logout` deletes the secret from every backend, removes the profile from `config.yaml` and purges the profile's cached resources from the inventory (keep them with `--keep-inventory`).

### Login flows per platform

Browser-based flows open your default browser; pass `--no-browser` to print the URL instead (useful over SSH).

#### Cloudflare

Uses an API token. polyctl opens <https://dash.cloudflare.com/profile/api-tokens>, where you create a token (the "Edit zone DNS" template is a good start; required: `Zone:Read` and `DNS:Edit`; optional: `Account:Read` to list accounts, `Zone:Edit` for cache purge / development mode / SSL mode, `User:Read` to show your email), then prompts for it. Non-interactive: export `CLOUDFLARE_API_TOKEN` (the same variable Terraform and wrangler use) or pipe the token on stdin.

```sh
polyctl auth login cloudflare --profile cf-main
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile cf-main --set account_id=...
polyctl auth login cloudflare --profile cf-main --set token=...      # works, but warns: the token lands in shell history / process list
```

`account_id` is optional; when omitted polyctl discovers the accounts the token can see and asks you to pick one if there are several. The token is verified before it is stored.

#### name.com

Username plus API token. polyctl opens <https://www.name.com/account/settings/api> for token creation and prompts for both values.

```sh
polyctl auth login namecom --profile namecom
polyctl auth login namecom --profile namecom-test --set username=acme --set token=... --set env=test
```

`env=test` (aliases `dev`, `development`) points the profile at name.com's test environment (`api.dev.name.com`). That environment requires a token generated for it and your username with `-test` appended; polyctl adds the suffix automatically when it is missing. API access must be enabled in the account settings, and name.com may require your IP address to be whitelisted there.

#### GoDaddy

Personal Access Token (PAT) created at <https://developer.godaddy.com/personal-access-token>. GoDaddy does not offer an OAuth flow for third-party CLIs, so polyctl opens that page and prompts for the token. The legacy API key + secret pair is still accepted (`--set key=... --set secret=...` or `--set method=api_key`) but GoDaddy has deprecated it for the Domains API.

```sh
polyctl auth login godaddy --profile godaddy
polyctl auth login godaddy --profile godaddy-ote --set token=... --set env=ote
polyctl auth login godaddy --profile godaddy-legacy --set key=... --set secret=...   # legacy API key pair
```

`env=ote` (alias `test`) targets the OTE environment at `api.ote-godaddy.com`. For production API access GoDaddy requires the account to hold at least one domain or be on a plan that grants API management access; paid operations need a billing method on file. Requests that fail this check return `403 ACCESS_DENIED`, which polyctl reports as an authentication failure (exit code 3) with a hint to use an OTE credential for development.

#### AWS

Three methods, selected with `--set method=`:

| Method | What happens |
| --- | --- |
| `sso` (default) | IAM Identity Center device-code flow. polyctl registers an OIDC client, opens the verification URL in your browser, waits for approval and stores the SSO token. `--set start_url=`, `--set sso_region=`, `--set account_id=`, `--set role_name=` are prompted for when omitted; when the token can access several accounts/roles you pick one. Short-lived role credentials are minted on each use and refreshed automatically; when the SSO session itself expires, run `auth login` again. |
| `keys` | Static access key id (prompted) and secret access key (prompted without echo), optionally a session token. |
| `profile` | Delegate to a profile in `~/.aws/config` / `~/.aws/credentials` (`--set aws_profile=<name>`). Nothing is copied; polyctl stores only a reference and lets the AWS SDK's own credential chain resolve it. |

`--set region=` sets the default region for regional services (EC2). Route 53 and Route 53 Domains are global.

```sh
polyctl auth login aws --profile work-aws --set method=sso --set start_url=https://acme.awsapps.com/start --set sso_region=us-east-1 --set account_id=123456789012 --set role_name=AdministratorAccess --set region=eu-west-1
polyctl auth login aws --profile lab --set method=keys
polyctl auth login aws --profile legacy --set method=profile --set aws_profile=default
```

#### GCP

| Method | What happens |
| --- | --- |
| `adc` (default) | Uses Application Default Credentials. If none exist polyctl prints the `gcloud auth application-default login` command to run (and opens the ADC documentation page), then exits with code 3; re-run `auth login` after completing it. |
| `service-account` (alias `sa`; stored as `service_account`) | `--set key_file=<path>`; the service-account JSON key is read and its contents stored in the credential store. `--set project=` defaults to the key's `project_id`. |
| `oauth` | Your own OAuth client (`--set client_id=`, `--set client_secret=`); polyctl opens the consent screen, receives the code on a loopback listener and stores the refresh token. |

`--set project=` sets the default project; when omitted polyctl lists the projects the credentials can see and asks you to choose.

```sh
polyctl auth login gcp --profile gcp-prod --set project=acme-prod
polyctl auth login gcp --profile gcp-ci --set method=service-account --set key_file=./sa.json --set project=acme-ci
```

#### Alibaba Cloud

RAM AccessKey pair from <https://ram.console.aliyun.com/manage/ak>. polyctl opens the page and prompts for the key id and secret.

```sh
polyctl auth login aliyun --profile aliyun --set region=cn-hangzhou
polyctl auth login aliyun --profile aliyun --set from_cli=default     # import from an `aliyun` CLI profile
```

`--set from_cli=<name>` copies the AccessKey of an existing Alibaba Cloud CLI profile (`~/.aliyun/config.json`, or the file named by `ALIBABA_CLOUD_CLI_CONFIG`; `from_cli=current` picks the CLI's current profile; only AK-mode profiles can be imported) into the keyring. `--set region=` is the default region for ECS (default `cn-hangzhou`); Alidns is region-independent. `--set site=cn|intl` selects the Domain (registrar) API site: `cn` for aliyun.com accounts, `intl` for alibabacloud.com accounts; when omitted it is derived from the region (`cn-*` = `cn`, otherwise `intl`). Grant the RAM user `AliyunDNSFullAccess`, `AliyunDomainFullAccess` and/or `AliyunECSReadOnlyAccess` as needed.

## Platform-neutral commands

These commands take a domain name and route it to the right platform and profile.

### DNS

```text
polyctl dns list   <domain> [--type A] [--name www]
polyctl dns update <domain> --type <T> --value <V> [--name www|@] [--ttl 300] [--priority 10] [--proxied true|false] [--add]
polyctl dns delete <domain> (--type <T> [--name www|@] [--value <V>] | --id <record-id>) [-y]
```

- `<domain>` may be the zone apex or any name under it (`www.example.com` resolves to the `example.com` zone). `--name` is relative to the zone (`www`, `@`); when omitted, the record name is `<domain>` itself.
- `dns update` is an upsert keyed on name + type: one existing record is updated (TTL, priority and proxy status are kept unless given), none means create, several means an error unless `--add` is passed, which always creates another record.
- In tables, a TTL that is a platform marker rather than a number of seconds is shown by name: `auto` (Cloudflare automatic TTL, `1` in the API), `alias` (Route 53 alias records, which use the target's TTL) and `default` (a GoDaddy record just written without `--ttl`). `-o json` and `-o yaml` keep the raw value.
- `dns delete` with a selector that matches several records shows them and asks for confirmation (skip with `-y`). `--value` narrows the match; `--id` deletes exactly one record by platform id.
- `--proxied` applies to Cloudflare only; the `PROXIED` column appears for Cloudflare zones.
- After a successful write the record is upserted into (or removed from) the inventory, so the next `dns list` shows it without a refresh.

### Domains

```text
polyctl domain info  <domain>
polyctl domain ns get <domain>
polyctl domain ns set <domain> --ns ns1.example.net,ns2.example.net
polyctl domain which <domain>
polyctl domain index [--profile <name>]
polyctl domain list  [--refresh] [--profile <name>]
```

- `domain info` combines the registrar view (status, expiry, auto-renew, lock, privacy, nameservers) with the DNS zone that serves the domain and the zone's nameservers; either half may be absent if only one kind of profile knows the domain.
- `domain ns get` / `ns set` read and write the nameservers **at the registrar** (name.com, GoDaddy, Route 53 Domains, Alibaba Cloud Domains).
- `domain which` prints every index entry for the domain and its parents: kind (`zone` or `domain`), platform, profile, resource id and when it was indexed. This is the place to look when routing surprises you.
- `domain index` fetches zones and registered domains from every domain-capable profile and rebuilds the index. `domain list` prints the index (`--refresh` re-indexes first).

### Routing rules

1. `--profile <name>` wins: only that profile is searched (and indexed, if needed).
2. Otherwise polyctl looks up the domain and each of its parents (`a.b.example.com`, `b.example.com`, `example.com`) in `domain_index`, restricted to the kind the command needs (`zone` for `dns ...`, `domain` for registrar operations). **The longest matching domain wins**, so a delegated sub-zone `b.example.com` beats its parent zone.
3. If the best match belongs to more than one profile, the command fails with exit code 5 and lists the candidates. Pick one with `--profile`.
4. If nothing matches, polyctl indexes the relevant profiles automatically the first time (when no index exists yet for them) or when `--refresh` is given, then retries. Otherwise it reports "domain not found in local index" (exit code 4) and suggests `polyctl domain index` or `--refresh`.
5. With `--offline` no indexing happens; an unknown domain is an error.

The status line on stderr always tells you which profile was used, for example `zone example.com via cloudflare/cf-main (local inventory)`.

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
polyctl inventory list [--platform <p>] [--type <t>] [--name <exact name>] [--profile <name>]
polyctl inventory path
```

- `sync` fetches the selected resource types (default: everything each platform supports) for the selected profiles (default: all) and **replaces** them in the inventory atomically, one set at a time. It prints a per-set report (count, duration, failures). An authentication failure stops the sync of that profile.
- `inventory stats` shows row counts and the synced/expiry time of each set; `inventory list` dumps cached rows; `inventory path` prints the database path.

## Platform-specific commands

Each platform has its own subtree under its short name: `cf`, `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. Profile selection for these commands is `--profile` > `current_profile` (if it belongs to that platform) > the only profile on that platform > an error listing the candidates. They honour `--refresh` / `--offline` for list operations the same way the neutral commands do, and always write through to the platform.

### Cloudflare (`polyctl cf`)

```text
cf zone list                      cf zone get <zone|id>
cf dns list <zone> [--type] [--name]
cf dns create <zone> --type A --name www --value 203.0.113.10 [--ttl 1] [--proxied true|false] [--priority] [--comment]
cf dns update <zone> --id <record-id> [--type] [--name] [--value ...] [--ttl ...] [--priority] [--proxied true|false] [--comment]
cf dns delete <zone> --id <record-id>
cf cache purge <zone> (--everything | --url <url>... | --host <h>... | --tag <t>... | --prefix <p>...)   # host/tag/prefix need Enterprise
cf dev-mode <zone> [on|off]       # Development Mode (bypass cache for 3 hours)
cf ssl-mode <zone> [off|flexible|full|strict]
cf account list
cf token verify
```

Inventory types: `zone`, `dns_record`. Record ids are the Cloudflare record ids; `proxied` is the orange cloud.

### name.com (`polyctl namecom`)

```text
namecom domain list               namecom domain get <domain>
namecom domain ns get <domain>    namecom domain ns set <domain> --ns ns1,ns2
namecom domain lock <domain>      namecom domain unlock <domain>
namecom domain autorenew <domain> on|off
namecom domain check <domain>...  # availability and price
namecom dns list <domain>
namecom dns create <domain> --type A --name www --value 203.0.113.10 [--ttl 300] [--priority]
namecom dns update <domain> --id <record-id> [--type] [--name] [--value] [--ttl] [--priority]
namecom dns delete <domain> --id <record-id>
namecom hello                     # API connectivity check (/v4/hello)
```

Inventory types: `domain`, `zone`, `dns_record` (every name.com domain is also its own zone).

### GoDaddy (`polyctl godaddy`)

```text
godaddy domain list [--status ACTIVE,EXPIRED]   godaddy domain get <domain>
godaddy domain ns get <domain>    godaddy domain ns set <domain> --ns ns1,ns2
godaddy domain lock <domain>      godaddy domain unlock <domain>
godaddy domain autorenew <domain> on|off
godaddy domain available <domain>...
godaddy dns list <domain> [--type] [--name]
godaddy dns add <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority]
godaddy dns replace <domain> --type A --name www --value <v> [--value <v>...] [--ttl] [--priority]   # replaces the whole name+type set
godaddy dns delete <domain> (--type A --name www | --id <TYPE|name|data>)
```

Inventory types: `domain`, `zone`, `dns_record`. GoDaddy has no per-record ids; records are addressed by type + name, and `replace` follows the API's "replace all records of this type and name" semantics. polyctl derives a stable synthetic id of the form `TYPE|name|data` (each part percent-encoded, e.g. `TXT|@|v=spf1%20include:_spf.example.com%20~all`) so the neutral `dns` commands and `godaddy dns delete --id` can target single records.

### AWS (`polyctl aws`)

```text
aws sts whoami                                    # GetCallerIdentity
aws route53 zone list                             aws route53 zone get <zone-id|name>
aws route53 record list <zone> [--type] [--name]
aws route53 record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300]
aws route53 record delete <zone> --type A --name www               # deletes the whole record set
aws route53domains domain list                    aws route53domains domain get <domain>
aws route53domains ns set <domain> --ns ns1,ns2
aws ec2 list [--region <r>]                       aws ec2 start <instance-id> [--region]     aws ec2 stop <instance-id> [--region] [--force]
```

Inventory types: `zone`, `dns_record`, `domain`, `instance`.

Route 53 stores a *record set* (name + type) with several values. polyctl exposes **one record per value** both in the inventory and in `dns list`, with a synthetic id of the form `<zone-id>|<TYPE>|<name>|<set-identifier>|<value>` (each part URL-encoded); updating or deleting one of them rewrites the whole record set with that value changed or removed. `record upsert` with several `--value` flags writes the set in one call.

### GCP (`polyctl gcp`)

```text
gcp project list                  gcp project current
gcp dns zone list                 gcp dns zone get <managed-zone>
gcp dns record list <zone> [--type] [--name]
gcp dns record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300]
gcp dns record delete <zone> (--type A --name www [--value <v>] [--priority] | --id <zone|TYPE|name|value>)
gcp compute list                                  gcp compute start <instance> [--zone <z>] [--wait]     gcp compute stop <instance> [--zone <z>] [--wait]
```

Inventory types: `zone`, `dns_record`, `instance`. Cloud DNS record sets are split one record per value exactly like Route 53 (see above); writes are applied as a single atomic change.

### Alibaba Cloud (`polyctl aliyun`)

```text
aliyun sts whoami                                 # GetCallerIdentity
aliyun dns domain list                            # Alidns domains (zones)
aliyun dns record list <domain> [--type] [--name]
aliyun dns record add <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority] [--line default|telecom|unicom|mobile|oversea]
aliyun dns record update <domain> --id <record-id> [--name] [--type] [--value] [--ttl] [--priority] [--line]
aliyun dns record delete <domain> --id <record-id>
aliyun domain list                                aliyun domain get <domain>       # registered domains
aliyun domain ns set <domain> --ns ns1,ns2
aliyun ecs list [--region]                        aliyun ecs start <instance-id> [--region]     aliyun ecs stop <instance-id> [--region] [--force]
```

Inventory types: `zone` (Alidns domains), `dns_record`, `domain` (registered domains), `instance`. Alidns stores the relative record name as `RR`; both the native `aliyun dns record` commands and the neutral `dns` commands expose it as `--name`. Records also carry a resolution line (`--line`), shown in the `LINE` column.

## Output formats

```sh
polyctl dns list example.com                 # table (default)
polyctl dns list example.com -o json         # pretty-printed JSON
polyctl dns list example.com -o yaml
POLYCTL_OUTPUT=json polyctl auth list        # environment default
```

Precedence: `--output` > `output:` in `config.yaml` > `POLYCTL_OUTPUT` > `table`.

Tables are tab-aligned and contain only the most useful columns. JSON and YAML encode the full result, including routing information, for example:

```json
{
  "target": { "platform": "cloudflare", "profile": "cf-main", "resource_type": "zone", "resource_id": "9a1...", "domain": "example.com" },
  "cached": true,
  "records": [
    { "id": "f3c...", "zone_id": "9a1...", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "ttl": 1, "proxied": true }
  ]
}
```

Human-readable progress and notes always go to stderr, so stdout is safe to pipe.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. |
| `1` | Generic error (API failure, I/O error, aborted prompt, ...). |
| `2` | Usage error: bad flag combination, unknown platform or resource type, missing required flag, invalid config. |
| `3` | Authentication: missing credentials, rejected token, expired SSO session, `auth status` with a failing profile. |
| `4` | Not found: unknown domain / zone / record / profile, or a set that was never synced in `--offline` mode. |
| `5` | Ambiguous: the domain or platform has more than one candidate profile; pass `--profile`. |
| `6` | Offline: the command needs the network but `--offline` was given. |
| `7` | Not supported: the platform (or the profile's client) cannot perform the operation. |

Errors are printed to stderr as `error: <message>`.

## Project layout

```text
cmd/polyctl/                 main(): calls internal/cli.Main and exits with its code
internal/cli/                Cobra command tree (root, auth, dns, domain, sync/inventory, platform mounts), exit-code mapping
internal/app/                Runtime shared by all commands: config, credential store, inventory, profile selection,
                             domain routing (ResolveDomain), cache policy (EnsureSet / NeedsRefresh), SyncProfile
internal/platform/           Provider-neutral contracts: Provider, Client, DNSService, RegistrarService, Zone/Record/Domain,
                             resource types, sentinel errors, provider registry, DNS name helpers
internal/providers/
  cloudflare/  namecom/  godaddy/  aws/  gcp/  aliyun/
                             One package per platform: provider.go (login, client, sync) and commands.go (native commands)
internal/config/             config.yaml loading/saving, TTL defaults
internal/creds/              Keyring store, 0600 file store, Multi (read from any, write to primary)
internal/inventory/          SQLite schema, Replace/Upsert/Delete, domain lookup, stats
internal/output/             table / json / yaml rendering
internal/httpx/              Small JSON REST client with retries (Cloudflare, name.com, GoDaddy)
internal/prompt/             Line / secret / confirm prompts with TTY detection
internal/browser/            Open a URL in the default browser (macOS, Windows, Linux)
```

Adding a platform means implementing `platform.Provider` (and `DNSService` / `RegistrarService` as applicable) in a new `internal/providers/<name>` package, registering it in `init()`, and mounting its Cobra subtree in `internal/cli/platforms.go`. The neutral commands, routing, caching and output need no changes.

## Security notes

- Secrets never enter `config.yaml`, the inventory or command output. `auth list` shows metadata only.
- Keyring entries are created under the service name `polyctl`; on macOS you may be asked once to allow `polyctl` access to the Keychain item.
- When the keyring is unavailable, `credentials.json` is written with mode `0600` inside a `0700` directory. Treat that file like `~/.aws/credentials`. Set `credential_store: keyring` if you would rather fail than fall back.
- `inventory.db` contains the full record data of every zone you synced (including TXT verification strings and the public IPs of instances). It is not encrypted; keep the config directory private or point `POLYCTL_INVENTORY_DB` at a protected location.
- Secrets are read from the terminal without echo. Passing them on the command line with `--set token=...` is convenient for scripts but leaves them in shell history and in the process list; prefer the interactive prompt or a secrets manager that injects them.
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
