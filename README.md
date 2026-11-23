# polyctl

`polyctl` is a single command-line tool for the accounts most small teams end up juggling: cloud platforms (AWS, GCP, Alibaba Cloud), CDN/DNS (Cloudflare) and domain registrars (name.com, GoDaddy).

It does two things at once:

- **Platform-neutral commands** (`polyctl dns ...`, `polyctl domain ...`, `polyctl cert ...`) work on any domain regardless of where it lives. polyctl looks the domain up in a local index, finds the account that owns it and routes the call there.
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
polyctl dns ensure example.com -r www:A:203.0.113.10:300 -r @:MX:"10 mail.example.com"
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
| `-y, --yes` | Assume "yes" for confirmations (multi-record `dns delete`, `dns delete --all`, `aliyun ecs instance stop`, `delete` and the `resize` of a running instance, `aliyun ecs security-group delete` and `rule remove`, `cloudflare r2 domain detach`, the interactive `auth logout`, the removal inside `auth manage`), in both flows. In the non-interactive flow it is the only way to confirm: without it such a command is a usage error (exit code 2). It confirms, it does not choose: a missing argument is still asked for on a terminal, and still a usage error without one. |
| `--dry-run` | Write commands report what they would change and write nothing: every command that writes to a platform honours it, prints the change report of [Dry runs and change reports](#dry-runs-and-change-reports) with `would create` / `would update` / `would delete`, and exits with code 0. Reads still happen (a dry run looks at the current state to tell what would change). Nothing is confirmed either: a dry run asks no question and needs no `--yes`, also together with `--yes`. Read-only commands ignore the flag. The commands that change local configuration only (`auth login`, `auth use`, `auth logout`, `auth rename`, `auth manage`) refuse it with a usage error rather than change anything. |
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
- `ttl`: how long a synced set stays fresh, per resource type (see [Caching](#caching) for the types). Unset types use `default`; the built-in defaults are `dns_record: 1h`, `zone: 24h`, `domain: 24h`, `instance: 15m`, `security_group: 1h`, `load_balancer: 1h`, `certificate: 24h`, `volume: 1h`, `db_instance: 15m`, `eip: 1h`, `key_pair: 24h`, `default: 24h`.
- `output`: default output format.
- `profiles.<name>.platforms.<platform>`: the profile's account on one platform; `<platform>` is one of `cloudflare`, `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. A profile holds at most one account per platform.
- `profiles.<name>.platforms.<platform>.metadata`: non-secret values the provider needs (account id, region, project, login method...). Populated by `auth login`; you can edit them by hand.
- `profiles.<name>.platforms.<platform>.credential_backend`: where the secret was written (`keyring` or `file`). Written by polyctl, also when a refreshed token moves the secret from the file to the keyring. `auth rename` and `auth logout` use it to tell whether the secret is within reach in this run.
- `profiles.<name>.platforms.<platform>.created_at` / `updated_at`: when the account was first added and last logged in.
- `profiles.<name>.platforms.<platform>.legacy_secret`: written by polyctl only, while an account converted from a 0.1.x config still has its secret under the old key (see [Upgrading from 0.1.x](#upgrading-from-01x)). It disappears once the secret has been moved, or once the backend that would hold it says there is none.
- `profiles.<name>.platforms.<platform>.legacy_backend`: written by polyctl only, next to `legacy_secret`, when the account was logged in again while the backend holding the old entry was out of reach: it names that backend, so the old entry can still be removed once the backend is available.

- `profiles.<name>.defaults.<platform>.<key>`: overrides `defaults.<platform>.<key>` for the accounts of this profile (see below).

Profile names must not contain spaces or slashes.

#### Defaults, naming, hooks and certificates

These keys configure the commands that create resources. None of them holds a secret, and no built-in default is a value of a particular account (no account name, public key, address, VPC or security group id): a value that has no neutral default and is not configured has to be passed as a flag, otherwise the command is a usage error (exit code 2) that names the flag and the key.

```yaml
defaults:                         # per-platform defaults: defaults.<platform>.<key>
  aws:
    region: eu-west-1
    vpc_id: vpc-0123456789abcdef0
    subnet_id: subnet-0123456789abcdef0
    security_group_ids: [sg-0123456789abcdef0]
    key_name: ops
    instance_type: t3.small
    elb_security_group_ids: [sg-0fedcba9876543210]
    tags: { team: ops }
    rds:
      default_class: db.t3.micro
      subnet_group: default
      security_group_ids: [sg-0123456789abcdef0]
      parameter_group: default.mysql8.0
      default_tags: { backup: daily }
  gcp:
    network: default
    subnet: default
    zone: europe-west1-b
    machine_type: e2-small
    tags: [web]
    lb_network_tag: lb-health-check
    ssh_keys: []
  aliyun:
    region: cn-hongkong
    resource_group: rg-0123456789   # a name or an rg- id (aliyun eip address allocate / ensure)
    eip:
      bandwidth: 200              # Mbps of the EIPs polyctl allocates
      isp: BGP_PRO
    ecs_instance_type: ecs.u1-c1m1.large   # aliyun ecs instance create / ensure --type
    ecs_security_group_rules: ["icmp:all:0.0.0.0/0", "tcp:80:0.0.0.0/0", "tcp:443:0.0.0.0/0"]   # aliyun ecs instance ensure --rule
    cas_region: ap-southeast-1
    cas_endpoint: cas.ap-southeast-1.aliyuncs.com
  cloudflare:
    ssl: strict

profiles:
  acme:
    platforms: { ... }
    defaults:                     # per-profile overrides: profiles.<name>.defaults.<platform>.<key>
      aws:
        instance_type: t3.large

naming:                           # names of the resources ensure commands create
  aws_elbv2_load_balancer: "{name}-lb"
  aws_elbv2_target_group: "{name}-{port}-target"
  aliyun_alb_load_balancer: "lb-{name}"
  aliyun_alb_server_group: "{service}-{protocol}"
  aliyun_vpc: "{region}-vpc"
  aliyun_vswitch: "{region}-switch-{zone}"
  aliyun_ecs_security_group: "sg-common"
  gcp_lb_prefix: "lb-"
  gcp_instance_group_prefix: "ig-"
  gcp_backend_service_prefix: "bs-"
  gcp_proxy_prefix: "proxy-"
  gcp_forwarding_rule_prefix: "fr-"
  gcp_instance_external_ip: "{name}-external-ip"   # static addresses of gcp compute instance create / resize
  gcp_instance_internal_ip: "{name}-internal-ip"
  gcp_lb_firewall: "allow-lb-health-check-{network}"   # rule of gcp compute firewall ensure --preset lb-health-check

hooks:
  on_failure: https://hooks.example.com/polyctl   # or a shell command

cert:
  email: you@your-domain.tld      # ACME account address (CAs refuse example.com addresses)
  agree_tos: false                # must be set to true explicitly
  dir: ""                         # default <config dir>/certs; a leading ~ is the home directory
  acme_directory: https://acme-v02.api.letsencrypt.org/directory
  key_type: ec256                 # ec256 | ec384 | rsa2048 | rsa4096
  reuse_key: false                # keep the private key on renewal
  renew_days: 30                  # default of --days
  name_template: "upload_{name}_{not_after}"
  skip_accounts: []               # accounts (or account:deployer) certificate deployment leaves alone
  dns:
    resolvers: ["1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53", "114.114.114.114:53"]
    min_resolvers: 2              # how many of them must see a TXT record
    propagation_timeout: 5m
    poll_interval: 10s
    settle_delay: 20s
  aws:
    regions: [us-east-1]          # regions certificate deployment scans (default: the account's region)
  aliyun:
    regions: [cn-hongkong]

dns:                              # live queries of `domain ns check`
  resolvers: [1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4]   # IP or IP:port, asked in order
  timeout: 5s                     # per query
```

- `defaults.<platform>.<key>`: the value a command uses when its flag is not given. `<platform>` is a platform id (`aws`, `gcp`, `aliyun`, `cloudflare`, `namecom`, `godaddy`; aliases are not accepted here), and a key may be nested (`defaults.aws.rds.default_class`). Values are single values, lists or mappings, as shown. A profile overrides them with `profiles.<name>.defaults.<platform>.<key>`, which wins for that profile's accounts. The order is the usual one: the command-line flag, then the profile's value, then the top-level value, then the built-in default. Only two keys have a built-in default: `defaults.gcp.lb_network_tag` (`lb-health-check`) and `defaults.cloudflare.ssl` (`strict`; it takes `flexible`, `full` or `strict`, and any other value is reported when the config is loaded, exit code 2).
- `naming.<key>`: the template of the names `ensure` commands give to resources they create, unless a flag names the resource. Templates use `{name}`, `{service}`, `{protocol}`, `{port}`, `{region}`, `{zone}` and `{network}`; which ones a resource provides is documented with its command, and a template that uses a variable the resource does not provide is an error. The defaults are the ones shown. An unknown key, an unknown variable or an unbalanced brace is reported when the config is loaded (exit code 2).
- `hooks.on_failure`: called when an `ensure`-style command fails (not for usage errors, not in a dry run), typically from cron. A value starting with `http://` or `https://` is a webhook: it receives a `POST` with a JSON body `{"event": "<command>.failed", "platform", "profile", "target", "domain", "error", "time", "changes"}`. Any other value is a shell command (`/bin/sh -c`, `cmd /C` on Windows) that gets the same JSON on stdin and the fields in `POLYCTL_EVENT`, `POLYCTL_PLATFORM`, `POLYCTL_PROFILE`, `POLYCTL_DEPLOYER`, `POLYCTL_TARGET`, `POLYCTL_DOMAIN` and `POLYCTL_ERROR`. A hook gets 15 seconds; a hook that fails or times out is a warning on stderr and never changes the exit code. Empty (the default): no notification.
- `cert.*`: the settings of the certificate commands, with the defaults shown (see [Certificates](#certificates)). `cert.email` and `cert.agree_tos` are only used to register the ACME account on the first issuance. `cert.dir` is the certificate store. `cert.acme_directory` is the CA (Let's Encrypt production by default). `cert.key_type` (`ec256`, `ec384`, `rsa2048` or `rsa4096`) is the default of `--key-type` and `cert.renew_days` the default of `--days`. `cert.reuse_key: true` keeps the private key on renewal instead of creating a new one. `cert.dns.*` tune the DNS-01 challenge: the resolvers (IP or IP:port) asked whether the TXT records are visible, how many of them must see them (`min_resolvers`, at most the number of resolvers), the longest wait (`propagation_timeout`), the interval between checks (`poll_interval`) and the pause before the CA validates (`settle_delay`, also waited after stale challenge records were deleted).
- `dns.resolvers` / `dns.timeout`: the recursive resolvers `domain ns check` asks, in order, and the timeout of one query, with the defaults shown; `--resolver` and `--timeout` override them. A resolver that is not an IP address or IP:port, or a negative timeout, is reported when the config is loaded (exit code 2).

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
  resource_type TEXT    NOT NULL,     -- see the resource types under Caching
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
| `dns delete <domain> --all` | "delete N records in zone ... (y/N)" after a summary (records to delete by type, records to unbind, system records kept); `--yes` skips it | `--yes` (refused before the zone is read) |
| `aliyun ecs instance stop <instance-id>` | "stop instance ... (y/N)"; `--yes` skips it | `--yes` (refused before the account is opened) |
| `aliyun ecs instance delete <name\|id>` | "Delete instance ... (y/N)" after showing it; `--yes` skips it | `--yes` (refused before the account is opened) |
| `aliyun ecs instance resize <name\|id>` of a running instance | "Stop instance ... to change its type ...? (y/N)"; `--yes` skips it | `--yes` (the instance is read first; a stopped one needs no confirmation) |
| `aliyun ecs instance create` / `ensure` when a key pair has to be created | as `aliyun ecs key-pair ensure`: the public key file, then the name of the key pair (from `--key-pair` when given) | `--ssh-key` / `--ssh-key-file` and `--key-pair` (exit code 2 without them), or `--key-pair` naming an existing key pair |
| `aliyun ecs security-group delete <name\|id>` | "Delete security group ... (y/N)" after showing it; `--yes` skips it | `--yes` (refused before the account is opened) |
| `aliyun ecs key-pair ensure` without a key or a name, when a key pair has to be created | the public key file (from `~/.ssh/*.pub` or a path), then the name of the key pair; the key pair to use when the key is registered under several names | `--ssh-key` / `--ssh-key-file` and `<name>` (exit code 2 without them; exit code 5 when the key is under several names and `<name>` picks none) |
| `aliyun ecs security-group rule remove <sg>` | "Remove N rule(s) from security group ... (y/N)" after listing them; nothing to remove asks nothing; `--yes` skips it | `--yes` (the rules to remove are read first) |
| `cloudflare r2 domain detach <bucket> <domain>` | "unbind ... from R2 bucket ... (y/N)"; `--yes` skips it | `--yes` (refused before the account is opened) |
| `auth login cloudflare` | the API token (after opening the token page); the account, when the token sees several | `CLOUDFLARE_API_TOKEN` or `--set token=-` (stdin is read only for `--set token=-`); `--set account_id=<id>` when the token sees several accounts |
| `auth login cloudflare --set method=oauth` | nothing typed: the approval in the browser (the URL is printed too; `--no-browser` only prints it), waiting up to 5 minutes; the account, when the authorization covers several | not available: a person has to approve, so it is a usage error naming `CLOUDFLARE_API_TOKEN` / `--set token=-` |
| `auth login namecom` | username and API token | `--set username=<user>` and `--set token=-` |
| `auth login godaddy` | the Personal Access Token (or, with `--set method=api_key`, key and secret) | `--set token=-`, or `--set api_key=<key> --set api_secret=-` |
| `auth login aws` | the method | `--set method=sso\|keys\|profile` |
| `auth login aws --set method=keys` | access key id, secret access key, optional session token | `--set access_key_id=<id> --set secret_access_key=-` (and `--set session_token=-`), or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`) |
| `auth login aws --set method=profile` | the AWS profile name (default `default`) | nothing: `--set aws_profile=<name>`, else the profile of the previous login, else `default` |
| `auth login aws --set method=sso` | start URL, Identity Center region; then, after the browser approval, the account and the role when several are accessible | `--set start_url=<url>` (the region defaults to `us-east-1`, or `--set sso_region=`); `--set account_id=<id>` and `--set role_name=<name>` when several are accessible |
| `auth login gcp` (`adc`) | the project, from the visible ones | nothing when the project is unambiguous (`--set project=<id>`, the previous login's, the ADC project, the only visible one); otherwise `--set project=<id>` |
| `auth login gcp --set method=service_account` | the key file path; the project when the key names none | `--set key_file=<path>`; `--set project=<id>` when the key names none |
| `auth login gcp --set method=oauth` | client id and secret; the project | `--set client_id=<id> --set client_secret=- --set project=<id>` |
| `auth login aliyun` | the site (`cn` or `intl`, from a list, no default), then AccessKey ID and Secret, region | `--set site=cn\|intl` (a re-authentication keeps the site of the first login) and `--set access_key_id=<id> --set access_key_secret=-`, or `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, or `--set aliyun_profile=<profile>`; the region defaults to the previous login's, then `cn-hangzhou` |

A re-authentication (`auth login` for an account the profile already has) reuses what the previous login recorded (username, start URL, account, role, project, region, method), so in the non-interactive flow usually only the secret has to be passed again.

Two login flows need a person in a browser but nothing typed into polyctl, so they stay available in the non-interactive flow: polyctl prints the URL, does not open a browser, and waits for a bounded time.

- `auth login aws --set method=sso` prints the verification URL and code and polls until the device code expires (the lifetime AWS gives the code; 10 minutes when it names none). If the approved login can access several accounts or roles and `--set account_id` / `--set role_name` were not given, it then fails with a usage error that lists them, so pass both in scripts.
- `auth login gcp --set method=oauth` prints the consent URL and waits up to 5 minutes for the browser to return to its loopback listener. On a terminal it waits until you press Ctrl-C.

`auth login cloudflare --set method=oauth` is not one of them: it runs in the interactive flow only, and is a usage error otherwise.

Every other command (`auth list`, `auth status`, `auth rename`, `sync`, `inventory`, `domain`, `dns list` / `set` / `add` / `ensure`, single-record `dns delete`, and the remaining platform-specific commands) asks nothing in either flow.

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
- `auth logout --profile <name>` removes the whole profile: every account in it, their secrets from every backend, and their cached resources from the inventory (keep those with `--keep-inventory`). `auth logout <platform> --profile <name>` removes only that account; the profile itself is removed when it was its last one. The platform is optional; `--profile` is required, except in the interactive flow, where leaving it out opens a list of accounts to choose from (see [Interactive management](#interactive-management)). `config.yaml` is saved after each removed account; if it was changed by another process in the meantime the command stops before anything of the next account is removed (see [Configuration](#configuration)). When an account's `credential_backend` names a backend that is not available in this run, the account is still removed from `config.yaml`, with a warning that its credentials in that backend were not removed; the same goes for an old 0.1.x entry recorded in `legacy_backend`. An account whose login left an authorization on the platform (a Cloudflare browser login) has it revoked there before its secret is removed; when the platform cannot be reached, or with `--offline`, a note says so and the account is removed all the same. Removing the current profile leaves no current profile until the next `auth use` or `auth login`. `auth logout <platform> --profile <name>` for a platform the profile has no account on is an error (exit code 4); the interactive list with no account to offer (none at all, or none on the given platform) is not: it prints a `nothing to do` note and exits with code 0.

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
- Alibaba Cloud: the account's site is now required when an account is added: `auth login aliyun` asks for it on a terminal, and needs `--set site=cn|intl` in the non-interactive flow (it used to be optional and derived from the region). A re-authentication keeps the recorded site.
- GoDaddy legacy key pair: `key=` / `secret=` are now `api_key=` / `api_secret=`.
- Option values have one spelling each; the undocumented aliases are usage errors now: GCP `method=adc|service_account|oauth` (not `service-account` or `sa`), GoDaddy `method=pat|api_key` (not `token`, `key`, `sso-key`, `sso_key`) and `env=production|ote` (not `prod`, `test`), name.com `env=production|test` (not `prod`, `dev`, `development`). Accounts that are already stored keep working: what `config.yaml` and the credential store hold is read as before.

### Login flows per platform

Browser-based flows open your default browser; pass `--no-browser` to `auth login` (or `auth manage`) to print the URL instead (useful over SSH). What follows describes the interactive flow first. In the non-interactive flow no browser is opened, nothing is asked and nothing is read from a terminal: each platform's "Non-interactive" line says what to pass, and whatever is still missing is a usage error (exit code 2) naming the `--set` key. Any `--set key=-` reads that value from stdin, one line per key in the order given, which keeps secrets out of the process list and the shell history.

#### Cloudflare

Two methods, chosen with `--set method=`:

| `method` | Flow |
|---|---|
| `token` (default) | An API token. polyctl opens <https://dash.cloudflare.com/profile/api-tokens>, where you create a token (the "Edit zone DNS" template is a good start; required: `Zone:Read` and `DNS:Edit`; optional: `Account:Read` to list accounts, `Zone:Edit` for cache purge / development mode / SSL mode, R2 read and write for `cloudflare r2`, `User:Read` to show your email), then prompts for it. Non-interactive: export `CLOUDFLARE_API_TOKEN` (the same variable Terraform and wrangler use), or pass `--set token=-` with the token on stdin; `--set token` wins over the variable, and without either the login is a usage error (exit code 2). stdin is read only for `--set token=-`: a token piped without it is ignored, so a login whose stdin is an idle pipe fails at once instead of waiting. |
| `oauth` | Approval in the browser (OAuth, authorization code with PKCE). polyctl prints the authorization URL, opens it in your browser, and waits up to 5 minutes for the answer on a listener bound to `127.0.0.1`; on Cloudflare's page you choose the account and approve the access. Nothing is typed or pasted, and no token has to be created. With `--no-browser` the URL is only printed: open it in a browser on the same machine (the answer comes back to `127.0.0.1`, so a browser on another machine cannot deliver it; over SSH use an API token, or forward the port shown in the URL). Ctrl-C ends the wait. Interactive only: a person has to approve, so in the non-interactive flow `--set method=oauth` is a usage error (exit code 2) that points to the API token. |

Which one to use:

- **Browser (`oauth`)**: one approval and you are done. The authorization covers a whole account for the scopes you approve; it cannot be limited to single zones. polyctl asks for `zone.read`, `dns.read`, `dns.write` and `offline_access` (required), and for `cache.purge`, `zone-settings.read`, `zone-settings.write`, `account-settings.read` and `user-details.read` (optional: decline any of them on the consent page, and the command that needs it says which scope is missing and that logging in again grants it). polyctl stores the access token, the refresh token, the expiry and the granted scopes in the credential store, renews the access token by itself, and revokes the authorization at Cloudflare on `auth logout`. If an account administrator has disabled third-party OAuth applications, that account does not appear on the consent page: use an API token there.
- **API token (`token`)**: for scripts, CI and every other non-interactive use, and for least privilege: a token can be limited to single zones and to exactly the permissions you pick, and it works without a browser. You create and delete it yourself in the dashboard; `auth logout` only forgets it.

> **The browser login is not open to everybody yet.** polyctl's OAuth client is registered with Cloudflare but not published, so for now `--set method=oauth` works only for members of the publisher's Cloudflare account; everybody else gets an error on Cloudflare's page and should log in with an API token. Until the client is published, `auth login cloudflare` without `--set method` asks for an API token, as it always did. Once it is published, the browser becomes the default of the interactive flow, and the non-interactive flow keeps requiring a token.

Without `--set method`, a token passed with `--set token` or `CLOUDFLARE_API_TOKEN` selects `token`, and logging in again to an account keeps the method it was stored with (an account stored by 0.1.x is a token account). `--set method=oauth` together with `--set token` is a usage error; `CLOUDFLARE_API_TOKEN` is ignored, with a note, when `--set method=oauth` is given. `method` takes exactly `oauth` or `token`; any other value is a usage error.

```sh
polyctl auth login cloudflare                                        # API token; added to the current profile (or to "default" when no profile is current)
polyctl auth login cloudflare --set method=oauth                     # approve in the browser (see the note above)
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile acme --set account_id=...
polyctl auth login cloudflare --profile acme --set token=...         # works, but warns: the token lands in shell history / process list
```

`account_id` is optional; when omitted polyctl discovers the accounts the credentials can see and asks you to pick one if there are several. In the non-interactive flow several accounts are a usage error that lists them: pass `--set account_id=<id>` (a re-authentication keeps the account it had; after a browser login that approved another account, that one is used). An API token is verified at Cloudflare's token endpoint before it is stored, a browser login by listing zones.

When the access token of a browser login has expired, the next command renews it with the refresh token and stores the result; polyctl processes that run at the same time take turns at this, so a rotating refresh token is never spent twice. If Cloudflare refuses the refresh token (the authorization was revoked in the dashboard, or has expired), the command fails with exit code 3 and asks you to run `polyctl auth login cloudflare` again. `--offline` never renews.

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

RAM AccessKey pair from <https://ram.console.aliyun.com/manage/ak>. polyctl first asks which site the account belongs to, then opens the page and prompts for the key id and secret, then for the region. Both can be passed with `--set access_key_id=<id> --set access_key_secret=-` or, when neither is given with `--set`, taken as a pair from `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`; then they are not asked for. Non-interactive: `--set site=cn|intl` and one of those, or `--set aliyun_profile=`, are required, and the region is never asked for (`--set region=`, else the CLI profile's, else the previous login's, else `cn-hangzhou`).

**The site.** Alibaba Cloud runs two sites with separate accounts: the China site (`cn`, aliyun.com) and the International site (`intl`, alibabacloud.com). An account usually belongs to one of them, and no API call a key can make tells them apart reliably, so the site is stated when the account is added: the interactive flow asks for it from a list before anything else (there is no default), and the non-interactive flow needs `--set site=cn|intl` (without it the login is a usage error, exit code 2, before anything is read or sent). The site is stored in the account's metadata, shown by `auth list` and `auth status`, and used by the commands that differ per site (the registrar API, console links). A later `auth login` of the account keeps it; `--set site` with another value is a usage error, because the site of an account does not change: remove the account with `auth logout aliyun --profile <name>` and add it again. After the key is verified, the site of a main account is cross-checked with the billing API (`QueryAccountBalance` on the chosen site's endpoint): when that site refuses the account (`AuthSiteFail`) a warning says the key may belong to the other site, and the login goes on with the site you chose. RAM users usually lack the billing permission, so for them the check is skipped with a note. Accounts added before the site was required work as before (the registrar site is then derived from the region: `cn-*` regions use `cn`); log in again with `--set site=` to record it.

```sh
polyctl auth login aliyun --profile acme --set region=cn-hangzhou
printf '%s\n' "$AK_SECRET" | polyctl auth login aliyun --profile ci --set site=intl --set access_key_id=LTAI... --set access_key_secret=-   # scripts
polyctl auth login aliyun --profile acme --set site=cn --set aliyun_profile=default   # import from an `aliyun` CLI profile
```

`--set aliyun_profile=<name>` names a profile of the Alibaba Cloud CLI (`~/.aliyun/config.json`, or the file named by `ALIBABA_CLOUD_CLI_CONFIG`; `aliyun_profile=current` picks the CLI's current profile; only AK-mode profiles can be imported). It is the counterpart of `aws_profile` with one difference: the AccessKey of that profile is copied into polyctl's credential store, not referenced, so later changes to the CLI profile are not picked up until the next login. `--set region=` is the default region for ECS (default `cn-hangzhou`); Alidns is region-independent. `--set site=cn|intl` is the account's site (see above); it also selects the Domain (registrar) API site. Grant the RAM user `AliyunDNSFullAccess`, `AliyunDomainFullAccess` and/or `AliyunECSReadOnlyAccess` as needed; the ECS write commands (instances, security groups, key pairs) need `AliyunECSFullAccess`, the VPC lookups of the security group commands and the `aliyun vpc` listings `AliyunVPCReadOnlyAccess`, and the `aliyun vpc` and `aliyun eip` write commands `AliyunVPCFullAccess` (plus `AliyunResourceManagerReadOnlyAccess` to look a resource group up by name).

## Platform-neutral commands

These commands take a domain name and route it to the account that owns it: a platform and a profile. The `dns` and `domain` command groups and `cert ensure` accept `--profile <name>` and `--platform <platform>` to narrow the choice; `--platform` names one platform here (it routes to the account on that platform) and takes the same names and aliases as `auth login`.

### DNS

```text
polyctl dns list   <domain> [--type A] [--name www]
polyctl dns set    <domain> --type <T> --value <V> [--name www|@] [--ttl 300] [--priority 10] [--proxied[=false]]
polyctl dns add    <domain> --type <T> --value <V> [--name www|@] [--ttl 300] [--priority 10] [--proxied[=false]]
polyctl dns ensure <domain> (-r <name:type:value[:ttl[:proxied]]>... | -f records.yaml) [--prune-duplicates]
polyctl dns delete <domain> (--type <T> [--name www|@] [--value <V>] | --id <record-id>) [-y]
polyctl dns delete <domain> --all [--type <T>[,<T>...]]... [--keep-bound] [-y]
```

Every `dns` command also takes `[--profile <name>] [--platform <platform>]`.

- `<domain>` may be the zone apex or any name under it (`www.example.com` resolves to the `example.com` zone). `--name` is relative to the zone (`www`, `@`); when omitted, the record name is `<domain>` itself.
- `dns set` creates or updates, keyed on name + type: one existing record is updated (TTL, priority and proxy status are kept unless given), none means create. Several existing records are an error that changes nothing and points to `dns add` and `dns delete`.
- `dns add` always creates one more record and leaves the existing ones of that name and type alone; this is how round-robin `A` records or several `TXT` / `MX` records are built up.
- `dns ensure` converges a set of records of one zone in one run, and can be repeated safely. Each record (`--record` / `-r`, repeatable, and/or the records of `--file` / `-f`) is matched on name + type: one that is already as desired is reported `unchanged` and not written, one that differs is updated in place (keeping its id), a missing one is created; records that are not named are never touched. Names are relative to the zone (`www`, `@`, `a.b`) or names in it (`www.example.com`, `www.example.com.`); a name that ends in a top-level domain but is not in the zone (`www.other.com`) is a usage error rather than stored as `www.other.com.example.com`. The TTL (seconds or `auto`) and proxied (`true` / `false`) fields are optional: left out, an existing record keeps what it has and a new one gets the platform default (Cloudflare: automatic TTL, not proxied). `auto` is Cloudflare's automatic TTL there and the same as leaving the TTL out elsewhere; a TTL of `0` is accepted on Cloudflare only (where it means automatic). Values are compared the way the platforms store them (host names without case or trailing dot, IPv6 addresses compressed, TXT text without quotes and joined), so a record written differently but meaning the same is unchanged. An MX record's priority goes in front of its value (`@:MX:10 mail.example.com`) or in the file's `priority` field, and a new MX record needs one; an SRV value is `<priority> <weight> <port> <target>`. Inline, a value that ends in `:<number>` and an IPv6 address that could also be read with a TTL are refused as ambiguous: put such records in the file. The file is YAML:

  ```yaml
  records:
    - name: www
      type: A
      value: 203.0.113.10
      ttl: 300          # optional; a number or auto
      proxied: true     # optional, Cloudflare only
    - name: "@"
      type: MX
      value: mail.example.com
      priority: 10      # MX only
  ```

  Unknown fields, a record given twice, two CNAMEs of one name, a CNAME next to an A / AAAA record of the input, `proxied` on a type other than A, AAAA and CNAME, and `SOA` are usage errors (exit code 2); a type the platform cannot write is exit code 7. All of these are found before the zone is read. A CNAME whose name already has A / AAAA records (or the reverse) is an error before anything is written. Several records with the same name and type form a set: each missing value is created and nothing is updated (several MX or TXT values). One record against several existing ones of that name and type is fine when one of them is as desired (the others are left alone and the detail says so); when none is, the command stops before writing anything (exit code 5), unless `--prune-duplicates` is given, which keeps one (updating the oldest when none matches) and deletes the others, after all creates and updates and without asking. `proxied=true` on a platform other than Cloudflare reports the record as `skipped` and leaves it alone; `proxied=false` there is ignored, and on a proxied Cloudflare record the TTL is not compared (it is always automatic). The zone is always read live, so `--offline` is refused (exit code 6). The first failing write stops the run: the change report shows what was done and the failed record, and running the command again picks up from there. The report names records `dns-record/<name>/<TYPE>` with the name relative to the zone; an update lists its changed fields (`value a -> b; ttl 300 -> 600`) and, in JSON, `attrs.changed` (`value`, `ttl`, `proxied`, `priority`) with the old and new values.
- A record's data is called its **value** everywhere: the `--value` flag, the `VALUE` table column and the `value` field of `-o json` / `-o yaml`, so what a command prints can be passed back to another.
- In tables, a TTL that is a platform marker rather than a number of seconds is shown by name: `auto` (Cloudflare automatic TTL, `1` in the API), `alias` (Route 53 alias records, which use the target's TTL) and `default` (a GoDaddy record just written without `--ttl`). `-o json` and `-o yaml` keep the raw value.
- `dns delete` with a selector that matches several records shows them and asks for confirmation (skip with `-y`). Answering no, or leaving the question, deletes nothing: the command prints `nothing to do: no record was deleted` and exits with code 0. In the non-interactive flow (no terminal, `--non-interactive`, `POLYCTL_NON_INTERACTIVE=1`) the question is never asked and stdin is not read: the records are shown, nothing is deleted, and the command fails with the usage error `confirmation required: pass --yes to proceed (would delete N records in zone <domain>)` (exit code 2) unless `-y` is given. A selector that matches no record is an error (exit code 4). `--value` narrows the match; `--id` deletes exactly one record by platform id (here the id is an optional second way to address a record, so it is a flag).
- `dns delete --all` deletes every record of the zone, for retiring a domain or clearing it before a move; `--type` (repeatable or comma-separated, any case) limits it to those types across the whole zone (`--all --type TXT` clears every TXT record). It cannot be combined with `--name`, `--value` or `--id` (usage error), and `--type` takes a single type without `--all`. Only the account the domain routes to is cleared: a zone held by several accounts is ambiguous (exit code 5) until `--profile` / `--platform` picks one. The zone is read live and in full before anything is deleted, so `--offline` is refused (exit code 6). The SOA (of any name) and the NS records of the zone apex are never deleted and are reported `skipped` (`system record`), also with `--type NS`; NS records of names below the apex (delegations) are deleted. A record owned by another service (on Cloudflare the CNAME of an R2 custom domain) is unbound there, which removes it, and never deleted through the DNS API; `--keep-bound` reports such records `skipped` and leaves them alone. The interactive flow prints a summary on stderr (how many records of each type will be deleted, how many of them by unbinding, which system records are kept) and asks `delete N records in zone <domain> (y/N)`; answering no deletes nothing and exits with code 0. The non-interactive flow requires `--yes` and refuses without it (exit code 2) before reading the zone; `--dry-run` asks nothing and needs no `--yes`. Records are deleted one at a time in listed order, and a record that cannot be deleted (a platform refusal, an owned record that cannot be unbound, a record without an id) is reported `failed` without stopping the others; the command then exits with code 1. A zone with nothing to delete prints `no records to clean up` and exits with code 0. The change report lists every record (`dns-record/<name>/<TYPE>`, the name relative to the zone) as `deleted` (or `would delete`), `skipped` or `failed`; in JSON each deleted record keeps its full data in `attrs` (`value`, `ttl`, `priority`, `proxied`), so it can be written again with `dns ensure`, and a `summary` object counts `deleted`, `skipped` and `failed`. Deleted records leave the inventory one by one. The zone itself is never deleted.
- `--proxied` applies to Cloudflare only and is a boolean flag: `--proxied` switches the proxy on, `--proxied=false` switches it off (the `=` is required: a boolean flag does not take its value from the next argument), and without it `dns set` keeps what the record has and `dns add` uses Cloudflare's default. The `PROXIED` column appears for Cloudflare zones.
- After a successful write the record is upserted into (or removed from) the inventory, so the next `dns list` shows it without a refresh.
- On Cloudflare, the CNAME record created for the custom domain of an R2 bucket (a proxied CNAME to an `r2.dev` host, whose record metadata names the bucket) cannot be deleted through the DNS API. `dns delete` and `cloudflare dns delete` delete it by unbinding the domain from its bucket, which makes Cloudflare remove the record; the confirmation question and a dry run say so. The account of the zone is tried first; when the bucket is not there, the other Cloudflare profiles are searched for a bucket of that name that has the domain bound. When the domain cannot be unbound (no R2 permission, R2 not enabled, no bucket named in the record), the record is left in place and the command fails; when several records match, the others are still deleted first (exit code 1).

### Domains

```text
polyctl domain info  <domain>
polyctl domain ns get <domain>
polyctl domain ns set <domain> <nameserver>...
polyctl domain ns check <domain> [--resolver <ip>[,<ip>...]] [--timeout 5s] [--no-registrar] [--no-zone]
polyctl domain which <domain>
polyctl domain index [--profile <name>] [--platform <platform>]
polyctl domain list  [--refresh] [--profile <name>] [--platform <platform>]
```

`domain info`, `ns get`, `ns set` and `ns check` also take `[--profile <name>] [--platform <platform>]`.

- `domain info` combines the registrar view (status, expiry, auto-renew, lock, privacy, nameservers) with the DNS zone that serves the domain and the zone's nameservers; either half may be absent if only one kind of account knows the domain. `--platform` applies to both halves, so with it the half that lives on another platform is reported as a note on stderr.
- `domain ns get` / `ns set` read and write the nameservers **at the registrar** (name.com, GoDaddy, Route 53 Domains, Alibaba Cloud Domains). `ns set` takes the nameservers as arguments, at least one: `polyctl domain ns set example.com ns1.example.net ns2.example.net`. An argument may itself be a comma-separated list (`ns1.example.net,ns2.example.net`), which helps when pasting. The platform trees' `ns set` commands have the same shape.
- `domain ns check` answers "who really serves this domain, and is the delegation in place?" by comparing three sets of nameservers: the ones set **at the registrar** (`registrar`), the ones the platform assigned to the **hosted zone** (`zone`; Cloudflare, Alibaba Cloud DNS, Route 53, Cloud DNS, ...) and the ones public resolvers return **now** (`live`). A name below a registered domain is checked as its registered domain by the Public Suffix List (`www.example.com` checks `example.com`, `example.co.uk` stays itself; private suffixes such as `github.io` count), and the output names both (`domain`, `checked_domain`); an internationalized name is checked in its punycode form; a name that is not a valid host name (a URL, a name with a port) or has no registered domain (`localhost`, an IP address, `co.uk`) is a usage error (exit code 2). The live side asks `--resolver` (IP or IP:port, comma-separated or repeated; default `1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4`, or `dns.resolvers`), never the system resolver, one after the other with `--timeout` per query (default `5s`, or `dns.timeout`), retries a truncated answer over TCP, and uses the first answer that has NS records. The registrar and zone sides are read live from the accounts that hold the domain (the index is built or refreshed first when it has no entry for it, or with `--refresh`); every hosted zone of the domain is listed (`zones`, each with `live_match`: `equal`, `partial` or `none`) instead of being reported as ambiguous, and the one the live nameservers point to is compared (`zone`); a zone a registrar account keeps for the registration itself, whose nameservers are the registration's, is compared only when there is no other. Private zones are left out. The live lookup runs at the same time as the account lookups. Nameservers are compared without case, trailing dot, order or duplicates. `status` is `ok` (live equals the zone, and the registrar too when it is known), `partial` (live and zone share some nameservers, or live equals the zone while the registrar lists others), `mismatch` (they share none), `no-zone` (no account hosts the domain), `no-live` (resolvers answer NXDOMAIN, NODATA or SERVFAIL; the reason says which, SERVFAIL with a hint about DNSSEC and the DS record) or `unknown` (a side needed for the comparison was skipped or could not be read), with `no-zone` > `no-live` > `ok` > `partial` > `mismatch`; `match` holds the pairwise comparisons (`null` when a side is missing), `provider_guess` names the DNS host recognized in the live (else the zone) nameservers (`cloudflare`, `aliyun`, `aws`, `gcp`, `mixed` with `providers`, or `unknown`; a hint only), and `message` says what to do. The zone status the platform reports (Cloudflare `active` / `pending`) is shown as it is and does not decide the status. A side that is unavailable says why in `reason` (`available: false`, `ns: []`): a domain no logged-in registrar holds, a platform error, or every resolver timing out (which is not `no-live`). `--no-registrar` / `--no-zone` skip a side (not both: usage error). The command is a report: every status exits with code 0, so scripts read `status` from `-o json`. It exits with code 1 only when every side that was asked failed (the report is printed first), with code 3 when the accounts selected with `--profile` / `--platform` cannot authenticate, with code 4 when the `--platform` named holds the domain neither as a registration nor as a zone, with code 7 when that platform cannot read the requested sides, and with code 6 under `--offline`. It writes nothing, and `--dry-run` changes nothing in it.
- `domain which` prints every index entry for the domain and its parents: kind (`zone` or `domain`), platform, profile, resource id and when it was indexed. Without `--profile` / `--platform` every owner is shown, so this is the place to look when routing surprises you. With them the list is narrowed to the owners in that profile and on that platform, as on `domain list`; a domain that has no owner under the selection is not found (exit code 4), and an unknown profile (exit code 4) or platform (exit code 2) is reported as such.
- `domain index` fetches zones and registered domains from every domain-capable account of every profile and rebuilds the index; `--profile` and `--platform` limit it to the matching accounts. `domain list` prints the index, narrowed by `--profile` / `--platform` when given (`--refresh` re-indexes first). For both, an unknown `--profile` is an error (exit code 4). A `--profile` / `--platform` selection that names no domain-capable account is not: `domain list` lists nothing, and `domain index` has nothing to index, as it has when no domain-capable account is configured at all. It then prints an empty report on stdout (the table header, or `[]` with `-o json`) and a `nothing to do: ...` note on stderr, and exits with code 0.

### Certificates

```text
polyctl cert ensure <domain> [--days 30] [--force] [--staging] [--email <addr>] [--agree-tos]
                             [--key-type ec256|ec384|rsa2048|rsa4096] [--timeout 15m]
                             [--profile <name>] [--platform <platform>]
polyctl cert get    <domain> [--print fullchain|cert|chain|privkey] [--staging]
```

`cert ensure` makes sure the local certificate store holds a Let's Encrypt certificate of a domain and its wildcard that is not about to expire, and `cert get` shows it. Typical use is a daily cron job:

```sh
polyctl cert ensure example.com            # issues when missing, renews at 30 days left or fewer, else does nothing
polyctl cert ensure example.com --dry-run  # what it would do, writing nothing
polyctl cert get www.example.com --print fullchain > fullchain.pem
polyctl cert get example.com --print privkey > privkey.pem && chmod 600 privkey.pem
```

- Every certificate is issued for a **root domain** and its wildcard (`example.com` and `*.example.com`). `<domain>` may be any name under it: `www.example.com`, `*.example.com` and `example.com` all mean the certificate of `example.com`. The root domain is the registered domain by the Public Suffix List (`a.b.example.co.uk` gives `example.co.uk`, private suffixes such as `github.io` count); a name in another case, with a trailing dot or internationalized (converted to punycode) is accepted, a name without a registered domain (`com`, `localhost`, an IP address) is a usage error (exit code 2).
- **When it issues.** The certificate is left alone (`unchanged`) when it has more than `--days` whole days left (rounded down: with `--days 30`, 30 days and 23 hours left renews, 31 days does not), holds both names and has the `--key-type` key; otherwise it is issued (`created`) or renewed (`updated`). `--force` renews in any case; mind the CA's rate limits. A run that leaves the certificate unchanged touches neither the CA nor the DNS account.
- **DNS-01 through your DNS account.** The CA checks a TXT record `_acme-challenge.<root>`, which polyctl writes in the zone of the account the root domain routes to, as every `dns` command does (see [Routing rules](#routing-rules)); no separate DNS credentials are needed. A root domain no account hosts is exit code 4 (the message points to `auth login`, `sync` and `domain ns check`), one hosted by several accounts exit code 5 until `--profile` / `--platform` picks one; the records are only ever written to that one account. The two names need two TXT records of the same name, which exist side by side: polyctl creates records (never replaces one) and deletes exactly its own values afterwards. Records of an earlier run that did not clean up are deleted first. Before issuing, polyctl warns when the nameservers public resolvers return for the domain share none with the ones of the hosting zone (validation would most likely fail), and refuses a CNAME at `_acme-challenge.<root>` (delegated validation is not supported; exit code 1). The records are created with the lowest TTL the platform accepts (60 seconds, 300 on name.com, 600 on GoDaddy and Alibaba Cloud DNS).
- **Propagation.** The CA is told to validate once at least `cert.dns.min_resolvers` (default 2) of `cert.dns.resolvers` (default `1.1.1.1`, `8.8.8.8`, `223.5.5.5`, `114.114.114.114`; never the system resolver) return the expected value, checked every `poll_interval` (10s) for at most `propagation_timeout` (5m), and after a further `settle_delay` (20s). `-v` prints what each resolver returned on every check; a timeout reports their last answers.
- **The ACME account.** The first issuance registers an account with the CA. It needs an e-mail address (`--email` or `cert.email`, for expiry notices; the CA refuses addresses such as `@example.com`, which is a usage error carrying the CA's message) and the agreement to the CA's terms of service (`--agree-tos` or `cert.agree_tos: true`). The interactive flow asks for whichever is missing (answering no to the terms issues nothing and exits with code 0); the non-interactive flow fails with exit code 2 before anything is written. Later runs find the account in the store (by the address, or the only registered account when no address is set) and check it with the CA before ordering; an account the CA no longer knows is registered again.
- **Private keys.** Each issuance gets a new private key (`cert.reuse_key: true` keeps the current one). The key is written to the store before the CA is asked for the certificate; when a run fails after that, the next one uses the same key again. The certificate is checked before it is installed (its key matches, it holds both names, it has not expired); anything wrong leaves the store as it was.
- **Failures.** A failed issuance is never retried (the CA limits failed validations and duplicate certificates). The error carries the CA's problem type and detail, a DNSSEC hint when the CA reports a DNSSEC problem, the CA's `Retry-After` on a rate limit, and the resolvers' last answers on a propagation timeout; exit code 1, or 3 when the DNS account's credentials are rejected and 7 when its platform cannot write TXT records. A failure (not a usage error, not in a dry run) is sent to `hooks.on_failure` as `{"event": "cert.ensure.failed", "domain", "error", "time"}`. `--timeout` (default 15m) bounds the whole run, including the wait for the lock.
- **Concurrent runs.** A lock per root domain (`locks/<root>.lock`) keeps two processes from issuing the same certificate; the one that waited reads the store again and reports `unchanged` when the other has just renewed it. A lock that does not come free within `--timeout` is exit code 1.
- `--dry-run` reads the store, routes the domain and checks the nameservers and the challenge name (so routing errors exit as they would for real) and reports `would create` / `would update` with the reason, plus `would create acme-account/<ca>` when no account exists yet; it registers nothing, writes no record, orders nothing and creates no file. `--offline` is exit code 6 when a certificate would have to be issued, and fine when the current one is good.
- `--staging` uses the Let's Encrypt staging CA (certificates no browser trusts, for trying things out) and keeps its accounts and certificates apart in `ca/acme-staging-v02.api.letsencrypt.org/` of the store, where the commands without `--staging` never look; it cannot be combined with a custom `cert.acme_directory` (exit code 2). Any directory other than Let's Encrypt production is stored the same way under `ca/<host>/`.
- The change report lists `acme-account/<ca>` (`letsencrypt`, `letsencrypt-staging` or the CA's host; its id is the account number) when an account was used or registered, and `cert/<root>` with `names=... not_after=YYYY-MM-DD days_left=N`. In JSON the target is `{"store": "<cert.dir>", "acme": "<directory URL>", "dns": "<platform>/<profile>"}`, and the certificate's id is its serial number (lowercase hex, one byte per two digits, no colons), with `attrs` holding `names`, `not_before`, `not_after`, `days_left`, `key_type` and `path`. An issued certificate is also recorded in the inventory (platform `local`, `inventory list --type certificate`).
- `cert get` reads the store only and shows the domain, the names (root first), subject, issuer, serial number, validity, days left, key type (`ecdsa-p256`, ...), the SHA-256 fingerprint of the certificate and its directory; JSON fields are `domain`, `names`, `subject`, `issuer`, `serial`, `not_before`, `not_after`, `days_left`, `key_type`, `fingerprint_sha256` and `path`. It never shows the private key: `--print` writes one PEM file to stdout as it is (`fullchain`, `cert`, `chain` or `privkey`, the last with a note on stderr). A domain without a certificate is exit code 4.

The store (`cert.dir`, default `<config dir>/certs`) follows the `live/<domain>/` layout of certbot, so a certificate can be moved in by copying `fullchain.pem` and `privkey.pem` of certbot's `live/<domain>/` there:

```text
<cert.dir>/                          0700
  accounts/<CA host>/<id>/           account.key (0600), account.json
  live/<root>/                       fullchain.pem  cert.pem  chain.pem  privkey.pem (0600, PKCS#8)  meta.json
  archive/<root>/<UTC time>/         the bundles live/<root> held before (the last 3)
  pending/<root>/privkey.pem         the key of an issuance in progress
  locks/<root>.lock
  history.log                        one JSON line per certificate created or updated
  ca/<host>/...                      accounts, live, archive and pending of any other CA (staging)
```

A certificate is replaced by writing the new files next to `live/<root>` and renaming directories, so a reader sees the old certificate or the new one, never a mix; an interrupted replacement is repaired by the next `cert ensure` from the archive. A private key readable by others is reported, and made `0600` by `cert ensure`. A certificate whose key does not belong to it is an error (exit code 1), never used.

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

Commands that address a resource by its name or id (an instance, a load balancer, ...) find the account the same way, so the profile does not have to be named: the inventory rows of that resource type are searched by id and by name across the accounts able to hold it (those of the command's platform for a platform-specific command; for a platform-neutral one, all platforms or only `--platform`; only the accounts of `--profile` when it is given). An id match wins over name matches. One match is used; several are ambiguous (exit code 5: pass `--profile`, also `--platform` when the matches are on several platforms, or the id when one account holds several resources of that name); none syncs that resource type once for the accounts whose cached set is missing or expired (all of them with `--refresh`, none with `--offline`) and looks again before reporting not found (exit code 4). When an account could not be synced, the lookup fails with that account's error instead of "not found", since the resource may be there.

## Caching

Every read goes through the inventory:

| Situation | Behaviour |
| --- | --- |
| Set is cached and younger than its TTL | Served from `inventory.db`; the output notes `(local inventory)`. |
| Set is missing or expired | Fetched from the platform, stored, then served. |
| `--refresh` | Always fetched and stored. |
| `--offline` | Always served from the cache, even if expired. A set that was never synced is an error (exit code 4); any command that must write to a platform fails with exit code 6. |

TTLs are per resource type (`ttl:` in `config.yaml`; the defaults are listed under [`config.yaml`](#configyaml)). DNS records are tracked per zone, so listing one zone never forces a fetch of every zone in the account.

The inventory knows these resource types (the values of `--type`); each platform syncs the ones it supports, listed with its commands below:

| Type | Holds |
| --- | --- |
| `domain` | registered domains |
| `zone` | DNS zones |
| `dns_record` | DNS records |
| `instance` | compute instances |
| `security_group` | security groups and firewalls |
| `load_balancer` | load balancers |
| `certificate` | certificates held by a platform |
| `volume` | block storage volumes |
| `db_instance` | managed database instances |
| `eip` | elastic / static public IP addresses |
| `key_pair` | SSH key pairs |

```text
polyctl sync [--platform cloudflare,aws] [--profile <name>] [--type domain,zone,dns_record,instance,...]
polyctl inventory stats
polyctl inventory list [--platform cloudflare,aws] [--type domain,zone,dns_record,instance,...] [--name <exact name>] [--profile <name>]
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
- **`ensure`** converges a group of related resources to a desired state, where `create` makes one new resource (and fails when it exists) and `set` / `upsert` set one object (a DNS record, a record set) to the given value. An `ensure` command is idempotent: it first reads what exists, changes only what differs, reports `unchanged` for what already matches, and never deletes resources it was not told about. Any command that implicitly creates resources the caller did not name one by one (dependencies such as a VPC, a security group, a certificate, a listener) is an `ensure` command; `set` and `upsert` never create anything but their target. `ensure` waits until the resources are usable (`--no-wait` returns at once, `--timeout` bounds the wait) and prints a change report (see [Dry runs and change reports](#dry-runs-and-change-reports)). Exit code 0 includes "everything was unchanged".
- **Asynchronous changes** take `--wait` (wait until the change has completed; the default of `ensure` commands only) and `--timeout <duration>` (the upper bound of the wait, default `10m`). A wait that runs out of time fails with exit code 1 and names the resource and its last status.

### Cloudflare (`polyctl cloudflare`, alias `polyctl cf`)

```text
cloudflare whoami                 # verifies the API token (id, status, expiry) or the browser authorization (granted scopes)
cloudflare zone list              cloudflare zone get <zone|id>
cloudflare dns list <zone> [--type] [--name]
cloudflare dns create <zone> --type A --name www --value 203.0.113.10 [--ttl 1] [--proxied[=false]] [--priority] [--comment]
cloudflare dns update <zone> <record-id> [--type] [--name] [--value ...] [--ttl ...] [--priority] [--proxied[=false]] [--comment]
cloudflare dns delete <zone> <record-id>
cloudflare cache purge <zone> (--everything | --url <url>... | --host <h>... | --tag <t>... | --prefix <p>...)   # host/tag/prefix need Enterprise
cloudflare dev-mode <zone> [on|off]       # Development Mode (bypass cache for 3 hours)
cloudflare ssl-mode <zone> [off|flexible|full|strict]
cloudflare account list
cloudflare r2 bucket list [--wide]
cloudflare r2 domain list   <bucket>
cloudflare r2 domain get    <bucket> <domain>
cloudflare r2 domain attach <bucket> <domain> [--zone <zone>] [--disabled] [--min-tls 1.0|1.1|1.2|1.3]
cloudflare r2 domain update <bucket> <domain> [--enabled[=false]] [--min-tls <v>]
cloudflare r2 domain detach <bucket> <domain> [-y]
cloudflare r2 domain ensure <bucket> <domain> [--zone <zone>] [--disabled] [--min-tls <v>]
```

Every command above can be written with `cf` in place of `cloudflare` (`polyctl cf zone list`). Inventory types: `zone`, `dns_record`. Record ids are the Cloudflare record ids; `proxied` is the orange cloud, a boolean flag: `--proxied` switches it on, `--proxied=false` off, and without the flag `dns update` keeps the current setting.

`cloudflare r2` manages the custom domains of R2 buckets (the objects in a bucket, and creating or deleting buckets, are not covered). R2 is addressed per account, and buckets are not cached in the inventory: every `r2` command reads the platform, so `--offline` is refused (exit code 6) and `--refresh` changes nothing.

- **Accounts.** The account of a profile is the one it is pinned to (`account_id`), or the only account its credentials see; several are ambiguous (exit code 5). `r2 bucket list` without `--profile` lists the buckets of every Cloudflare profile (an account that has not enabled R2 is skipped silently, one that fails is a warning, and the command fails only when no account could be read); with `--profile`, an account without R2 is exit code 7. The `r2 domain` commands without `--profile` find the account that holds `<bucket>` among all Cloudflare profiles: accounts without R2, or whose credentials are refused, are skipped (and named when the bucket is found nowhere, exit code 4), and a bucket name held by several accounts is ambiguous (exit code 5, pass `--profile`). `--jurisdiction <j>` (`eu`, `fedramp`) addresses the buckets of that R2 jurisdiction instead of the default one.
- **`bucket list`** shows each bucket's profile, name and creation date; `--wide` also reads each bucket (one request per bucket) for its location, storage class and jurisdiction. JSON: `[{"profile", "account_id", "name", "creation_date"}]`.
- **`domain list` / `get`** show each custom domain with its enabled state, zone, minimum TLS version (`-`, `null` in JSON, when it was never set: Cloudflare then applies its own default) and the ownership and SSL status Cloudflare reports (`pending` and `initializing` right after a binding are normal). A domain that is not bound to the bucket is not found (exit code 4).
- **`domain attach`** binds `<domain>` (lower-cased, without a trailing dot; wildcards are refused) to the bucket. The zone is `--zone` (a name or an id) or else the longest zone name the domain ends in (`cdn.example.co.uk` finds `example.co.uk`, a delegated `a.example.com` beats `example.com`), always among the zones of the bucket's account; it must be active, and the domain must be in it (a usage error otherwise). Cloudflare then creates the proxied CNAME record `<domain> -> public.r2.dev` in the zone; it is reported as `r2/<bucket>/domain/<domain>/dns-record` once it could be read, and stored in the inventory. A domain that is bound already (to this bucket or another) is an error (exit code 1), and so is an A, AAAA or CNAME record of that name in the zone, which Cloudflare would refuse (a TXT record is fine). `--disabled` creates the binding disabled; `--min-tls` sets the minimum TLS version (`1.0`, `1.1`, `1.2` or `1.3`; not set by default).
- **`domain update`** changes what is given (`--enabled` / `--enabled=false`, `--min-tls`; at least one is required) and leaves the rest. **`domain detach`** unbinds the domain, and Cloudflare deletes its CNAME record; it asks for confirmation (default no) in the interactive flow and needs `--yes` in the non-interactive one. Both read the domain first, because the API reports success for a domain that is not bound: such a domain is not found (exit code 4).
- **`domain ensure`** is the idempotent form: a binding that is enabled as wanted (disabled with `--disabled`) and, when `--min-tls` is given, with that version, is `unchanged` and nothing is written; a differing one is updated; a missing one is created as `attach` does. A binding with another zone than `--zone` is an error: it is never unbound automatically. A domain bound to another bucket is not looked for beforehand; the creation then fails.
- The writes print a change report and honour `--dry-run`; a browser login (`method=oauth`) does not cover R2, so these commands need an API token with R2 read and write permission (binding a domain also needs DNS edit permission on its zone).

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
aws ec2 instance list [--region <r>] [--state <s>[,<s>...]] [--type <t>[,<t>...]] [--name <substring|pattern>]
aws ec2 instance get <name|id> [--field <name>] [--include-terminated] [--region <r>]
aws ec2 instance create <name> [--type <t>] [--ami <ami-id> | --os al2023] [--arch x86_64|arm64] [--subnet <id>] [--sg <sg-id>]...
                        [--key-pair <name>] [--ssh-key <public key> | --ssh-key-file <path>] [--disk <GB> [--disk-device /dev/sdb]
                        [--disk-type gp3] [--disk-iops 3000] [--disk-throughput 125]] [--public-ip[=false]] [--tag k=v]...
                        [--region <r>] [--wait [--timeout 5m]]
aws ec2 instance delete <name|id> [--yes] [--wait [--timeout 5m]] [--region <r>]       # alias: terminate
aws ec2 instance reboot <name|id> [--wait [--timeout 5m]] [--region <r>]               # starts a stopped instance
aws ec2 instance resize <name|id> --type <t> [--start[=false]] [--yes] [--timeout 5m] [--wait-port <n>] [--region <r>]
aws ec2 instance start <instance-id> [--region] [--wait [--timeout 5m]]
aws ec2 instance stop <instance-id> [--region] [--force] [--wait [--timeout 5m]]
aws ec2 key-pair list [--region <r>]
aws ec2 key-pair import <name> (--ssh-key <public key> | --ssh-key-file <path>) [--region <r>]
aws ec2 key-pair ensure [<name>] [--ssh-key <public key> | --ssh-key-file <path>] [--region <r>]
aws ec2 security-group list [--vpc <vpc-id>] [--name <name|pattern>] [--instance <name|id>] [--region <r>]
aws ec2 security-group get <sg-id|name> [--vpc <vpc-id>] [--region <r>]
aws ec2 security-group create <name> [--vpc <vpc-id>] [--description <text>] [--rule <rule>]... [--rule-description <text>] [--region <r>]
aws ec2 security-group delete <sg-id|name> [--vpc <vpc-id>] [--yes] [--region <r>]
aws ec2 security-group ensure <name> [--instance <name|id>] [--vpc <vpc-id>] [--rule <rule>]... [--description <text>]
                              [--rule-description <text>] [--region <r>]
aws ec2 security-group rule add <sg-id|name> --rule <rule>... [--rule-description <text>] [--vpc <vpc-id>] [--region <r>]
aws ec2 security-group rule remove <sg-id|name> --rule <rule>... [--vpc <vpc-id>] [--yes] [--region <r>]
```

Inventory types: `zone`, `dns_record`, `domain`, `instance`, `key_pair`, `security_group`. `route53domains` is this tree's registrar group, the counterpart of `domain` in the other trees.

EC2 instances:

- `get`, `delete`, `reboot` and `resize` take the instance's Name tag or its id and find the account themselves, the way domains are routed: the inventory tells which AWS accounts hold an instance of that name or id (the stale instance lists are synced once when none does), and those accounts are asked live; when none of them holds a live one, the other selected accounts are asked too. Terminated instances, which AWS keeps listing for a while with their Name tag, are never picked. Several live instances of one name are ambiguous (exit code 5): pass `--profile`, or the instance id when they are in one account. Nothing found is exit code 4. The inventory holds the profile's region; `--region` asks the selected profile's account in another region directly.
- `list` filters ask AWS directly, bypassing the inventory: `--state` (`running`, `stopped`, `stopping`, `pending`, `terminated`, `shutting-down`) and `--type` take comma-separated values, `--name` matches Name tags that contain the value (a value holding `*` or `?` is used as the EC2 wildcard pattern it is). Several filters must all match. Without filters every state is listed, as before. No match is an empty list, a note on stderr and exit code 0.
- `get` shows the instance in any state but terminated (`--include-terminated` finds a terminated one too), with its addresses, network, key pair and volumes. In JSON: `{"instance_id", "instance_name", "profile", "region", "availability_zone", "instance_type", "state", "platform", "architecture", "private_ip", "public_ip", "vpc_id", "subnet_id", "security_groups", "key_name", "launch_time", "root_device", "volumes": [{"volume_id", "size", "device", "state", "volume_type", "delete_on_termination"}]}`. `--field <name>` prints the raw value of one of those scalar fields for scripts; an empty value (a stopped instance has no public IP) is exit code 1 with an explanation. A failed volume listing is a warning and an empty `volumes`.
- `create <name>` refuses a name that a non-terminated instance already has in the region (exit code 1, nothing written). `--type`, `--subnet`, `--sg` and `--key-pair` default to `defaults.aws.instance_type`, `subnet_id`, `security_group_ids` and `key_name`; a missing type or subnet is a usage error (exit code 2), no security group means the VPC's default one, and no key pair means an instance without an SSH key. The image is `--ami`, or the latest Amazon Linux 2023 image for the type's architecture (`--arch`; arm64 for Graviton types): the SSM public parameter `al2023-ami-kernel-default-<arch>` first, and, when it cannot be read (no `ssm:GetParameter` permission), the newest Amazon image named `al2023-ami-2023.*-kernel-6.1-<arch>` (the two can use different kernels). The network is one interface in the subnet with the security groups and, unless `--public-ip=false`, a public IP. `--ssh-key` / `--ssh-key-file` bind the key pair that holds that public key, importing it under `--key-pair` when none does (the rules of `key-pair ensure`). `--disk <GB>` adds a data disk (`/dev/sdb`, gp3 with 3000 IOPS and 125 MiB/s by default; IOPS and throughput are sent for gp3 only, io1 and io2 need `--disk-iops`) that is **kept** when the instance is deleted; its encryption follows the account's EBS default. The Name tag, the tags of `defaults.aws.tags` and `--tag k=v` go on the instance and its volumes. `--wait` waits until the instance runs (5 second polls) and reports its public and private IP. `--dry-run` resolves the image and checks the name and the type, then reports `would create` with the type, image, subnet, security groups and disk.
- `delete` (alias `terminate`) shows the instance, its addresses and its volumes, says which volumes go with it (the root volume) and which stay (data volumes, which keep costing money), and asks for a confirmation (default no; `--yes` skips it, the non-interactive flow needs `--yes`, exit code 2). A declined confirmation is exit code 0. Termination protection is exit code 1 with the command that switches it off; polyctl never switches it off. A terminated instance is `unchanged`. Elastic IPs and snapshots are not deleted. `--wait` waits until it is terminated.
- `reboot` reboots a running instance and starts a stopped one; any other state is exit code 1. A reboot keeps the instance running, so `--wait` only applies to the start of a stopped instance (which gets a new public IP unless it has an Elastic IP).
- `resize --type <t>` checks the new type first (unknown: exit code 2; another architecture, x86_64 against arm64, or not offered in the instance's availability zone: exit code 1, nothing written), then stops a running instance (after a confirmation, as for `delete`), changes the type and starts it again, waiting for each state (5 second polls, `--timeout` each). The instance ends in the power state it had: a stopped instance stays stopped unless `--start`, and `--start=false` leaves a running one stopped. The same type is `unchanged`. A failed type change leaves the instance stopped with its old type; running the command again continues from there. Without an Elastic IP the public IP changes: the report and stderr show `public ip <old> -> <new>`. `--wait-port <n>` then waits until the TCP port accepts connections (22 for SSH, 3389 for RDP). The report has one row per step (`stop`, `modify-type <old> -> <new>`, `start`).
- `start` and `stop` take an instance id; `--wait` waits until the instance is running (and prints its addresses) or stopped.
- Errors: denied calls are exit code 3 and name the IAM action (`ec2:RunInstances`, ...); missing capacity (`InsufficientInstanceCapacity`) and exhausted quotas (`VcpuLimitExceeded`, `InstanceLimitExceeded`) are exit code 1 with what to do; a wait that runs out of time is exit code 1 with the last state.

EC2 key pairs belong to one region: `--region` picks it, the profile's region by default (the region the inventory caches; `key-pair list --region` reads another one live). AWS imports RSA and ED25519 public keys only; any other algorithm (ECDSA, DSA) is refused before anything is sent (exit code 2).

- `--ssh-key` takes the public key itself (one line, `ssh-ed25519 AAAA... comment`); `--ssh-key-file` a file holding it (`~` is expanded, the first public key line is used). A file path given to `--ssh-key`, both flags together, a private key, or text that is not a public key are usage errors (exit code 2). The public key is never printed: reports show its algorithm, the start of its SHA256 fingerprint and the first 20 characters of its comment.
- `key-pair list` shows `NAME`, `TYPE`, `FINGERPRINT` and `CREATED`. In JSON each key pair is `{"name", "key_pair_id", "type", "fingerprint", "created", "region"}` and `fingerprint` is exactly what AWS reports: unprefixed padded base64 SHA-256 for ED25519, colon-separated hexadecimal for RSA (the MD5 of the key for an imported key, a SHA-1 of the private key for a key pair AWS generated). The table prefixes ED25519 fingerprints with `SHA256:`. No key pairs is an empty list (`[]` with `-o json`), a note on stderr and exit code 0.
- `key-pair import <name>` imports the key under `<name>` and prints a change report (`key-pair/<name>  created`). A name that is taken is a usage error (exit code 2) whatever key it holds: an existing key pair is never replaced. `--dry-run` checks the key and reports `would create` without sending any request. The tags of `defaults.aws.tags` are set on the new key pair.
- `key-pair ensure [<name>]` reuses an existing key pair first. With a public key, the region's key pairs are compared with it by their public key (which matches imported key pairs and the ones AWS generated alike; a key pair listed without its public key is compared by fingerprint), and a key pair that holds it is reported `unchanged` (`matched by public key`) under its own name; a `<name>` that does not exist is then ignored, with a note. The same key can be imported under several names: `<name>` picks one of them, otherwise a terminal asks and the non-interactive flow fails with exit code 5, listing the names. When no key pair holds the key, it is imported as `<name>`; without `<name>` a terminal asks for the name (an empty answer creates nothing, exit code 0) and the non-interactive flow is a usage error (exit code 2): no name is ever chosen for you. With `<name>` alone, an existing key pair is used as it is; a missing one needs a public key (a terminal asks for the file, offering `~/.ssh/*.pub`; otherwise exit code 2). A `<name>` that exists with another key, or that AWS lists without its public key so it cannot be compared, is a usage error (exit code 2) and is never replaced. `--dry-run` reports `unchanged` or `would create` without writing.
- There is no `key-pair delete`: a key pair may still be bound to instances, and polyctl does not remove it.

EC2 security groups belong to one region and one VPC; names are unique within a VPC only.

- A group is named by its id (`sg-...`) or its name. A name is looked up in `--vpc`, else in `defaults.aws.vpc_id`, else in every VPC of the region, where a name that several VPCs use is ambiguous (exit code 5: pass `--vpc` or the id). A missing group is exit code 4, a malformed id (`sg-bogus`) exit code 2. Without `--profile` and `--region`, an id is looked up in the account whose inventory holds it when exactly one does.
- Rules are `<protocol>:<port|from-to|alias|all>:<source>`, the format every platform's firewall commands share: `tcp`, `udp`, `icmp` or `all`; a port, a range (`8000-8999`, aliases allowed on both ends: `ssh-http`) or an alias (`ssh`, `telnet`, `smtp`, `dns`, `http`, `pop3`, `imap`, `https`, `smb`, `mssql`, `mysql`, `rdp`, `postgresql`/`postgres`, `redis`, `elasticsearch`/`elastic`, `mongodb`/`mongo`); `icmp:all`, `all:all`, and `tcp:all` / `udp:all` for ports 1-65535; the source is an IPv4 or IPv6 CIDR (host bits are masked, a bare address gets `/32` or `/128`) or a security group id of the same account. ICMP from an IPv6 source is ICMPv6 (protocol 58). A malformed rule is exit code 2. Repeated rules in one command count once.
- Rules are compared by protocol, ports and source, never by description, the way AWS compares them. Egress rules are not managed: a new group keeps the AWS default that allows all outbound traffic.
- `list` shows `ID`, `NAME`, `VPC`, `RULES` (ingress rules, one per source) and `DESCRIPTION`; without filters the profile's region comes from the local inventory, while `--region`, `--vpc`, `--name` (`*` is a wildcard) and `--instance` (the groups attached to an instance, found like `instance get` finds it) ask AWS. No groups is `[]`, a note on stderr and exit code 0.
- `get` shows the group, its ingress rules and the instances it is attached to. In JSON: `{"id", "name", "vpc_id", "description", "profile", "region", "tags", "ingress": [{"protocol", "from_port", "to_port", "source", "source_type", "description"}], "instances"}`; `protocol` is `tcp`, `udp`, `icmp`, `icmpv6` or `all`, ports are -1 when the protocol has none, and `source_type` is `ipv4`, `ipv6`, `sg` or `prefix-list`.
- `create <name>` creates the group in `--vpc` (default `defaults.aws.vpc_id`; neither is exit code 2) with the description `auto created <name>` unless `--description` (AWS cannot change it later), then adds the `--rule` rules in one call, each with `--rule-description`. A group of that name in the VPC is exit code 1 (use `ensure`). Names may not start with `sg-`; names and descriptions take ASCII letters, digits, spaces and `._-:/()#,@[]+=&;{}!$*`, at most 255 characters (anything else is exit code 2 before anything is sent). New groups are tagged `Name=<name>`, `polyctl:managed=true` and the tags of `defaults.aws.tags` (which may override `polyctl:managed`).
- `ensure <name>` makes sure the group exists, holds the rules and, with `--instance`, is attached to that instance; a second run changes nothing. The VPC is `--vpc`, else the instance's VPC, else `defaults.aws.vpc_id` (none is exit code 2; a `--vpc` other than the instance's is exit code 2). A missing group is created as by `create`; an existing one is used as it is (`unchanged`). Rules present are `unchanged`; the missing ones are added in one call (AWS refuses a whole batch that holds a rule present already, so when another writer added one meanwhile, the rules are added one by one and the duplicate is `unchanged`). Rules are never removed. The instance (Name tag or id, found in every selected account like `instance get`) keeps every group it has: the new group is added to the set (`attached sg-... (kept N existing)`), and an attached group is `unchanged`. An instance that already has 5 groups (the default quota per network interface) is exit code 1, and one with several network interfaces exit code 7, before anything is written. `--dry-run` reports `would create` (the new group's id is `(pending)`, and all its rules would be created) and `instance/<name>  would update  attach <sg-id|(pending)> (keep: ...)`. Report rows: `security-group/<name>`, `security-group/<name>/rule` (detail `tcp 443 0.0.0.0/0`), `instance/<name>`.
- `rule add <sg-id|name>` adds the rules to an existing group (exit code 4 when it is missing), like `ensure` without creating or attaching anything. `rule remove` removes the rules that are present (a rule that is not there is `unchanged`) after showing them and asking for a confirmation (default no; `--yes` skips it, the non-interactive flow needs `--yes`, exit code 2); nothing to remove asks nothing.
- `delete` shows the group's name, VPC and instances and asks for a confirmation (as for `rule remove`). A group still attached to an instance or network interface, or used as the source of another group's rule, is exit code 1 (`DependencyViolation`: detach it or remove the reference first). The default group of a VPC is refused (exit code 1). A group that is gone by the time it is deleted is `unchanged`.
- Errors: denied calls are exit code 3 and name the IAM action (`ec2:AuthorizeSecurityGroupIngress`, ...); quotas (`RulesPerSecurityGroupLimitExceeded`: 60 ingress rules per group by default, IPv4 and IPv6 counted apart; `SecurityGroupsPerInstanceLimitExceeded`) are exit code 1 with the AWS message.

Route 53 stores a *record set* (name + type) with several values. polyctl exposes **one record per value** both in the inventory and in `dns list`, with a synthetic id of the form `<zone-id>|<TYPE>|<name>|<set-identifier>|<value>` (each part URL-encoded); updating or deleting one of them rewrites the whole record set with that value changed or removed. `record upsert` with several `--value` flags writes the set in one call.

### GCP (`polyctl gcp`)

```text
gcp whoami                        # the profile's project, account and login method
gcp project list                  gcp project current
gcp dns zone list                 gcp dns zone get <managed-zone>
gcp dns record list <zone> [--type] [--name]
gcp dns record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300]
gcp dns record delete <zone> (--type A --name www [--value <v>] [--priority] | --id <zone|TYPE|name|value>)
gcp compute instance list                         gcp compute instance start <instance> [--zone <z>] [--wait [--timeout 10m]]     gcp compute instance stop <instance> [--zone <z>] [--wait [--timeout 10m]]
gcp compute instance get <name|id> [--zone <z>] [--field external-ip|internal-ip|status|zone|machine-type]
gcp compute instance create <name> [--machine-type <t>] [--zone <z>] [--disk <GB>] [--boot-disk-size <GB>] [--disk-type pd-balanced] [--data-disk-type <t>]
                            [--os debian] [--os-version <v>] [--image <path>] [--ssh-key <key>]... [--ssh-key-file <path>]... [--ssh-user <name>]
                            [--ssh-key-instance-only] [--tag <tag>]... [--network <n>] [--subnet <s>] [--spot] [--ip-forward[=false]]
                            [--static-ip[=false]] [--service-account <email>] [--no-wait] [--timeout 10m]
gcp compute instance delete <name|id> [--zone <z>] [--release-ips] [--yes] [--wait [--timeout 10m]]
gcp compute instance resize <name|id> --machine-type <t> [--zone <z>] [--yes] [--wait-ssh] [--timeout 10m]
gcp compute instance reboot <name|id|ip> [--zone <z>] [--yes] [--wait [--timeout 3m]]
gcp compute instance update <name|id> --ip-forward[=false] [--zone <z>]
gcp compute firewall list [--network <n>]          gcp compute firewall get <name>
gcp compute firewall create <name> --allow <proto[:ports]>... [--network <n>] [--source-range <cidr>]... [--destination-range <cidr>]...
                            [--target-tag <tag>]... [--direction ingress|egress] [--priority 1000] [--description <text>] [--no-wait] [--timeout 10m]
gcp compute firewall update <name> [--allow ...] [--source-range ... | --add-source-range <cidr>...] [--destination-range ...]
                            [--target-tag ...] [--description ...] [--priority ...] [--no-wait] [--timeout 10m]
gcp compute firewall delete <name> [--yes] [--no-wait] [--timeout 10m]
gcp compute firewall ensure [<name>] --preset lb-health-check [--network <n>] [--region <r>] [--instance <i> [--zone <z>]] [--target-tag <tag>]
                            [--allow ...] [--description ...] [--no-wait] [--timeout 10m]
gcp compute firewall ensure <name> --allow ... --source-range ... [--target-tag ...] [--network <n>] [--direction ...] [--priority ...]
gcp compute network list                          gcp compute network get <name>
gcp compute subnet list [--network <n>] [--region <r>] [--proxy-only]
```

Inventory types: `zone`, `dns_record`, `instance`. Cloud DNS record sets are split one record per value exactly like Route 53 (see above); writes are applied as a single atomic change.

Compute Engine instances:

- `get`, `delete`, `resize`, `reboot` and `update` take the instance's name or numeric id and find the account themselves: the inventory of every selected GCP account (instances in every status, `TERMINATED` included) tells which project and zone hold it, and when none does the instance lists are synced once (always with `--refresh`). The instance is then read live, so these commands need the network (`--offline` is exit code 6). An instance of one name in several zones or projects is ambiguous (exit code 5): pass `--zone`, `--profile` or the id. `--zone` also finds an instance the inventory does not know when the sync failed; a `--zone` that differs from the zone of the only match is noted on stderr and the real zone is used. Nothing found is exit code 4. The inventory rows hold the internal and external IP and the network tags of each instance.
- `get` shows the instance with its addresses, network, tags, ip forwarding, deletion protection and disks (their type is read from each disk). In JSON: `{"name", "id", "zone", "status", "machine_type", "internal_ip", "external_ip", "network", "subnetwork", "tags", "can_ip_forward", "deletion_protection", "disks": [{"name", "boot", "size_gb", "type", "auto_delete"}], "creation_timestamp", "profile", "project"}`. `--field` prints one raw value for scripts (`external-ip`, `internal-ip`, `status`, `zone`, `machine-type`). An instance without an external IP gets a warning with the reason (a stopped instance released its ephemeral IP; a running one has no external access configured); with `--field external-ip` it is exit code 1 with nothing on stdout. A static external address stays bound to a stopped instance, which then still reports it.
- `create <name>` creates the instance in `--zone` of the selected profile's project; it is not an ensure command: an instance of that name in the zone is exit code 1. The name must follow the Compute Engine rule (a lower-case letter first, then lower-case letters, digits and hyphens, at most 63 characters; a leading digit is exit code 2 with a hint to add a prefix). `--machine-type` and `--zone` default to `defaults.gcp.machine_type` and `defaults.gcp.zone`; neither is exit code 2. The machine type is checked in the zone first (exit code 4). The image is `--image` (`projects/<p>/global/images/<name>` or `.../family/<family>`; its minimum disk size is read when possible, 10 GB is assumed otherwise), or the latest current x86_64 image of `--os` (`debian` by default; `ubuntu`, `centos`, `rocky`, `almalinux`/`alma`, `rhel`, `windows`, `suse`, `opensuse`, `cos`) in the OS's public image project, every page listed and deprecated, obsolete and ARM images left out: Debian without `--os-version` picks the highest release number, Ubuntu the newest LTS (an even year with month 04; minimal images excluded), Rocky, AlmaLinux and RHEL their standard images (no optimized, EUS, LVM or SAP variants) of the highest major version, Windows the Server Datacenter image without Core, and the others the newest image. No matching image is exit code 4; there is no fallback to another system. The boot disk `{name}-boot` (`--disk-type`, `pd-balanced` by default) has the image's minimum size unless `--boot-disk-size` (smaller than the minimum: exit code 2); `--disk <GB>` adds an empty data disk `{name}-data` (`--data-disk-type`). Both disks are deleted with the instance.
  - Network: `--network` (default `defaults.gcp.network`, else `default`); subnetwork: `--subnet` (default `defaults.gcp.subnet`; it must exist, exit code 4, and belong to the network, exit code 2), else the only subnetwork of the network in the zone's region (matched by exact network name; several are exit code 2, none is fine on an auto-mode network and exit code 1 on a custom-mode one).
  - `--static-ip` (default) reserves the external address `{name}-external-ip` (premium tier) and the internal address `{name}-internal-ip` (always in the instance's subnetwork) and binds them; existing ones are reused (`unchanged`), an internal one reserved in another subnetwork is re-reserved in the right one, and one that another resource uses stops create before anything is written (exit code 1). The names come from `naming.gcp_instance_external_ip` and `naming.gcp_instance_internal_ip`. `--static-ip=false` uses ephemeral addresses.
  - SSH keys go into the instance's `ssh-keys` metadata as `user:key` lines: `--ssh-key` takes the public key itself (a file path is refused with a hint to use `--ssh-key-file`), `--ssh-key-file` every key line of a file (`~` is expanded), and `defaults.gcp.ssh_keys` adds configured ones; both flags repeat. The user is a `user:` prefix of the key, else `--ssh-user`, else the name before the `@` of the e-mail address that ends the key's comment; none of them is exit code 2. Keys are parsed locally (Compute Engine does not check them). A key the project metadata already holds for that user is reported `ssh-key/<user> unchanged present in project metadata` and not repeated, unless `--ssh-key-instance-only`. A project whose metadata sets `block-project-ssh-keys=TRUE` (inherited by the instance) gets every key in the instance metadata. A project with `enable-oslogin=TRUE` gets a warning: OS Login ignores `ssh-keys`. Without any key nothing is written to the metadata.
  - `--tag` and `defaults.gcp.tags` are the network tags (both are used, without repeats). The instance gets the service account `--service-account` (default `default`, the default compute service account, with the devstorage read-only, logging, monitoring, service management, service control and trace scopes), Shielded VM with vTPM and integrity monitoring (secure boot off), on-host maintenance `MIGRATE` with automatic restart, or with `--spot` a Spot instance (`TERMINATE`, no automatic restart), no deletion protection, and ip forwarding only with `--ip-forward`.
  - By default create waits for the operation and then until the instance is `RUNNING` (5 second polls, `--timeout`, 10m by default, for each wait; running out of time is exit code 1) and prints its addresses; `--no-wait` returns once the creation was accepted (`instance/<name> created ... (provisioning)`). The report rows are `image/<os>`, `ssh-key/<user>`, `address/<name>`, `instance/<name>` and `instance/<name>/status`. Nothing is rolled back on failure: reserved addresses are kept, and the next create of the name reuses them. `--dry-run` runs every read (instance, machine type, image, subnetworks, addresses, project metadata) and reports `would create`, with `(pending)` for the IDs of addresses still to reserve.
- `delete` shows the instance, its disks (which go with it, which stay) and the static addresses it keeps, and asks for a confirmation (default no; `--yes` skips it, the non-interactive flow needs `--yes`, exit code 2; a declined confirmation is exit code 0). An instance with deletion protection is exit code 1; polyctl never switches it off. `--release-ips` then deletes `{name}-external-ip` and `{name}-internal-ip` when they are `RESERVED` (Compute Engine itself would delete an address in use; polyctl skips one that another resource uses) and implies `--wait`. `--wait` waits until the instance is deleted (`--timeout`, 10m: deleting an instance with a data disk can take minutes). The instance leaves the inventory.
- `resize --machine-type <t>` checks the type in the instance's zone first (exit code 4, nothing written); the same type is `unchanged`. A `RUNNING` instance is stopped after a confirmation (as for `delete`). Before that, its ephemeral IPs are made static, since a stopped instance loses its ephemeral external IP: an address that already holds the IP is `unchanged`, otherwise the IP is reserved as `{name}-external-ip` / `{name}-internal-ip`; a failed external promotion stops the command before the instance is stopped (exit code 1), a failed internal one is a warning. Then the instance is stopped (polled until `TERMINATED`), the type is changed and the instance started again (polled until `RUNNING`), each wait bounded by `--timeout`. A `TERMINATED` instance is changed and stays stopped: the instance ends in the power state it had. A failed type change leaves the instance stopped with its old type. Report rows: `address/<name>`, `instance/<name>/stop`, `instance/<name>/machine-type` (`<old> -> <new>`), `instance/<name>/start`; an address that changed anyway is a warning `IP changed: <old> -> <new>`. `--wait-ssh` then waits up to 5 minutes until port 22 accepts connections on the internal IP, or the external one (exit code 1 otherwise).
- `reboot` is a hard reset (`instances.reset`, like `gcloud compute instances reset`): the virtual machine restarts at once without a graceful shutdown of the operating system, keeps its addresses and stays `RUNNING`; it is never emulated by a stop and a start. It also takes an internal or external IP, looked up in the inventory; an IP that instances of several projects share is ambiguous (exit code 5), and the interactive flow lets you choose. The status is read live: an instance that is not `RUNNING` is exit code 1. The project, zone, addresses and status are shown and a confirmation is asked (as for `delete`). `--wait` waits for the reset (`--timeout`, 3m); a failed operation is exit code 1 with its error code.
- `update --ip-forward[=false]` switches ip forwarding in place, on a running or a stopped instance: the instance is sent back whole with its fingerprint and only `canIpForward` changed, allowing at most a refresh (never a restart), and read again to check the value. A value that is already set is `unchanged`; a stale fingerprint (the instance changed in between) is re-read and retried once. `update` without a setting is exit code 2.
- Errors: a disabled Compute Engine API and a missing permission (`compute.instances.*`, `compute.addresses.*`, ...) are exit code 3 and say which; quota and capacity errors (`QUOTA_EXCEEDED`, `ZONE_RESOURCE_POOL_EXHAUSTED`) are exit code 1 with a hint to try another zone or machine type, whatever HTTP status carries them; an operation that finishes with an error (`IP_IN_USE_BY_ANOTHER_RESOURCE`, ...) is exit code 1 with its code.

VPC firewall rules (read live, never kept in the inventory; `--profile` picks the project, and several GCP profiles without a default one are exit code 5). A rule name is unique in the project, so `get`, `update` and `delete` need no network:

- `list` lists the rules of every network, or of `--network` (matched by its exact name: `net-a` never lists the rules of `net-a-2`), sorted by priority (lower numbers win; at the same priority a deny rule wins over an allow rule). Columns `NAME NETWORK DIR PRI ALLOW SOURCES TARGET-TAGS` (`SOURCES` counts the source ranges, or the destination ranges of an egress rule; a deny rule shows `deny <protocols>`). No rule is exit code 0 with `[]` and a note.
- `get <name>`: JSON `{"name", "network", "direction", "priority", "allowed": [{"protocol", "ports"}], "denied", "source_ranges", "destination_ranges", "source_tags", "target_tags", "disabled", "description", "creation_timestamp"}` (`denied`, `destination_ranges` and `source_tags` only when set). A missing rule is exit code 4.
- `create <name>` is not an ensure: a rule of that name is exit code 1 (use `firewall ensure` to converge one). `--allow` (required, repeatable) is `<protocol>` or `<protocol>:<ports>`, the protocol `tcp`, `udp`, `icmp` or `all`, and only `tcp` and `udp` take ports: numbers, `from-to` ranges and the port aliases (`ssh`, `http`, `https`, `mysql`, ...), separated by commas (`tcp:80,443,8000-8100`); ports on another protocol are exit code 2. Without ports a protocol covers every port. An ingress rule (the default `--direction`) needs `--source-range`: Compute Engine silently opens a rule without one to `0.0.0.0/0`, so polyctl refuses it (exit code 2; pass `--source-range 0.0.0.0/0` to mean that). `--direction egress` takes `--destination-range` instead (required for the same reason) and refuses `--source-range`. CIDRs are normalized (a bare address gets `/32` or `/128`). Without `--target-tag` the rule applies to every instance of the network. `--network` defaults to `defaults.gcp.network`, else `default`; a missing network is exit code 4. `--priority` is 0-65535 (default 1000). The name must follow the Compute Engine rule (exit code 2).
- `update <name>` patches only the fields it is given: `--allow`, `--source-range`, `--destination-range` and `--target-tag` replace that list as a whole, `--add-source-range` adds ranges to the existing ones (a union; it never removes one), `--description` and `--priority` set those fields. Values already set are `unchanged` and nothing is sent; no field at all is exit code 2. The network and the direction are never changed (exit code 2: delete the rule and create it again), source ranges on an egress rule and destination ranges on an ingress rule are exit code 2, and a list cannot be emptied, except `--target-tag ""`, which makes the rule apply to every instance of the network: Compute Engine ignores an empty list in a patch, so the rule is then read and sent back whole (a warning is printed).
- `delete <name>` shows the rule and asks for a confirmation (default no; `--yes` skips it, the non-interactive flow needs `--yes`, exit code 2; a declined confirmation is exit code 0). A missing rule is exit code 4.
- `ensure` creates a missing rule, and adds to an existing one the ranges, target tags and allowed protocols or ports it lacks (a union: nothing is ever removed, so a range of a deleted subnetwork stays until `update --source-range` replaces the list); `--priority` and `--description` change an existing rule only when given. A rule without target tags already applies to every instance of the network, so it gets no tag (that would narrow it). A rule of that name on another network, with the other direction, disabled, a deny rule, or one that targets service accounts is exit code 1 with nothing written: polyctl does not move, turn, re-enable or retarget a rule. Without `--preset` it takes `<name>`, `--allow` and the ranges as `create` does.
  - `--preset lb-health-check` makes the rule load balancer health checks and proxies need. The name is `allow-lb-health-check-{network}` (`naming.gcp_lb_firewall`, which can use `{network}` and `{region}`; `<name>` overrides it; a name longer than 63 characters is cut and ends with a 6-character hash, the same for the same network). The source ranges are Google's health check ranges `35.191.0.0/16` and `130.211.0.0/22`, plus the primary and secondary ranges of every subnetwork of the network in `--region`, proxy-only subnetworks included (purpose `REGIONAL_MANAGED_PROXY`, `GLOBAL_MANAGED_PROXY`, `INTERNAL_HTTPS_LOAD_BALANCER`), sorted and without repeats. Subnetworks are regional: run it again for each region whose load balancers use the network, and the rule widens to those regions only. The target tag is `defaults.gcp.lb_network_tag` (`lb-health-check`) or `--target-tag`; the rule is an ingress rule at priority 1000 that allows every tcp port (an existing rule that allows tcp on some ports is kept as it is; `--allow` asks for other protocols or ports, which are then added as needed). `--source-range`, `--destination-range`, `--direction` and `--priority` are exit code 2 with the preset.
  - `--instance` (name or id, found like `instance get` finds it; `--zone` narrows it) also adds the target tag to that instance, in any status: the tags are replaced as a whole, so the instance's other tags are sent along with the fingerprint of the tags as read, and a stale fingerprint is read again and retried once. The account that holds the instance is used for the rule as well (a note on stderr when it is not the default profile), and the instance's network and region are the defaults of `--network` and `--region`; an instance that is not on `--network` is exit code 2. Without `--instance`, `--network` defaults to `defaults.gcp.network`, else `default`, and `--region` to the region of `defaults.gcp.zone`; no region at all is exit code 2.
  - Report rows: `firewall/<name>` (`created` with `tcp, 7 source ranges, tag lb-health-check`, `updated` with the added items such as `+10.20.0.0/24 (now 6 ranges)`, or `unchanged`) and `instance/<name>/tag`. In JSON the `attrs` of the rule carry `source_ranges`, the final list. `--dry-run` reads everything and reports `would create` / `would update`. A missing permission is exit code 3; failures also go to `hooks.on_failure` as `gcp.compute.firewall.ensure.failed`.
- Every write waits for its operation (`--timeout`, 10m; running out of time is exit code 1), since the operation is where Compute Engine reports most errors; `--no-wait` only submits it (writes to the same rule then fail until the operation is done). The writes print a change report (`firewall/<name>` `created`, `updated` with the changed fields, `deleted`); `--dry-run` runs the reads and reports `would create`, `would update` or `would delete`. A missing `compute.firewalls.*` permission and a disabled API are exit code 3 and say which; the firewall rule quota is exit code 1.

VPC networks and subnetworks (read-only, always read live, never kept in the inventory; `--profile` picks the project, and several GCP profiles without a default one are exit code 5):

- `network list` shows each network's mode (`auto`, `custom`, or `legacy` for a network with a single IPv4 range), routing mode, MTU (a network that never set one reads back 0 and is shown as `1460(default)`) and number of subnetworks. JSON: `[{"name", "mode", "routing_mode", "mtu", "ipv4_range", "subnetworks": ["<region>/<name>", ...], "description", "creation_timestamp"}]`.
- `network get <name>` adds the subnetworks of every region with their ranges (`subnets`, shaped like the rows of `subnet list`). A missing network is exit code 4.
- `subnet list` lists every region (`--region` one), optionally the subnetworks of one `--network`: the network is matched by its exact name, so `net-a` never lists the subnetworks of `net-a-2`. Columns `NAME REGION NETWORK RANGE SECONDARY-RANGES PURPOSE ROLE`; JSON `[{"name", "region", "network", "ip_cidr_range", "secondary_ranges": [{"range_name", "ip_cidr_range"}], "purpose", "role"}]`. `--proxy-only` keeps the proxy-only subnetworks (purpose `REGIONAL_MANAGED_PROXY`, `GLOBAL_MANAGED_PROXY` or the older `INTERNAL_HTTPS_LOAD_BALANCER`). No match is exit code 0 with `[]` and a note on stderr.
- A `--profile` that exists but holds no GCP account is exit code 7.

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
aliyun ecs instance list [--region]
aliyun ecs instance get <name|id> [--region <r>]
aliyun ecs instance create <name> --type <type> --security-group <name|id> [--vswitch <id|name>] [--image <id> | --os alibaba-cloud-linux] [--disk 20] [--disk-category cloud_essd_entry] [--key-pair <name>] [--ssh-key <public key> | --ssh-key-file <path>] [--eip] [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance delete <name|id> [--force] [--yes] [--timeout 10m] [--region <r>]
aliyun ecs instance reboot <name|id> [--force] [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance resize <name|id> --type <type> [--yes] [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance ensure <name> [--type <type>] [--disk 20] [--disk-category <c>] [--image <id> | --os alibaba-cloud-linux] [--vswitch <id|name>] [--security-group <name>] [--rule <rule>]... [--key-pair <name>] [--ssh-key <public key> | --ssh-key-file <path>] [--eip[=false]] [--no-wait] [--timeout 10m] [--region <r>]
aliyun ecs instance start <instance-id> [--wait] [--timeout 10m] [--region]
aliyun ecs instance stop <instance-id> [--force] [--wait] [--timeout 10m] [--region]
aliyun ecs security-group list [--vpc <vpc-id>] [--region <r>]
aliyun ecs security-group get <name|id> [--vpc <id|name>] [--region <r>]
aliyun ecs security-group create <name> --vpc <id|name> [--description <text>] [--region <r>]
aliyun ecs security-group delete <name|id> [--vpc <id|name>] [--yes] [--region <r>]
aliyun ecs security-group ensure <name> [--vpc <id|name>] [--description <text>] [--instance <name|id>] [--rule <rule>]... [--priority 1-100] [--region <r>]
aliyun ecs security-group rule add <sg> --rule <rule>... [--description <text>] [--priority 1-100] [--vpc <id|name>] [--region <r>]
aliyun ecs security-group rule remove <sg> (--rule <rule>... | --rule-id <sgr-id>...) [--yes] [--vpc <id|name>] [--region <r>]
aliyun ecs key-pair list [--region <r>]
aliyun ecs key-pair import <name> (--ssh-key <public key> | --ssh-key-file <path>) [--region <r>]
aliyun ecs key-pair ensure [<name>] [--ssh-key <public key> | --ssh-key-file <path>] [--region <r>]
aliyun ecs image latest [--os alibaba-cloud-linux] [--arch x86_64|arm64] [--region <r>]
aliyun vpc vpc list [--all] [--region <r>]
aliyun vpc vpc get <name|id> [--region <r>]
aliyun vpc vpc create <name> [--cidr 172.16.0.0/12] [--wait] [--timeout 60s] [--region <r>]
aliyun vpc vpc ensure [<name>] [--cidr 172.16.0.0/12] [--zones b,c] [--netmask 22] [--no-wait] [--timeout 60s] [--region <r>]
aliyun vpc vswitch list [--vpc <id|name>] [--region <r>]
aliyun vpc vswitch get <name|id> [--vpc <id|name>] [--region <r>]
aliyun vpc vswitch create <name> --vpc <id|name> --zone <zone-id|suffix> [--cidr <cidr>] [--region <r>]
aliyun vpc vswitch ensure [--vpc <id|name>] [--zones b,c] [--prefix <name-prefix>] [--netmask 22] [--region <r>]
aliyun eip address list [--unused | --bound] [--region <r>]
aliyun eip address allocate [--bandwidth 200] [--isp BGP_PRO] [--resource-group default] [--region <r>]
aliyun eip address associate <allocation-id|ip> --instance <name|id> [--region <r>]
aliyun eip address ensure [--count 1] [--instance <name|id>] [--exclude <allocation-id>]... [--bandwidth 200] [--isp BGP_PRO] [--resource-group default] [--region <r>]
```

`aliyun ecs instance stop` asks for confirmation on a terminal (default No; declining is a `nothing to do` note and exit code 0) unless `--yes` is given. In the non-interactive flow it never asks: without `--yes` it is a usage error (exit code 2) raised before the account is opened. `start --wait` waits until the instance is `Running`, `stop --wait` until it is `Stopped` (polled every 2 seconds, bounded by `--timeout`, 10m by default).

ECS instances are named by their id (`i-...`) or their name. Alibaba Cloud does not keep names unique and its name filter ignores case, so polyctl compares names case-sensitively and treats a name held by several instances as ambiguous (exit code 5: pass the id). Without `--region`, `get`, `delete`, `reboot` and `resize` find the instance through the local inventory of every selected account (synced once when it does not know the instance; an instance outside the profile's region needs `--region`) and then read it live; with `--region` the selected profile is asked in that region. A missing instance is exit code 4.

- `get <name|id>` shows `NAME`, `ID`, `REGION`, `TYPE`, `STATUS`, `PUBLIC_IP`, `PRIVATE_IP` and `EIP` (`yes`/`no`). JSON: `{"name", "id", "profile", "region", "zone", "type", "status", "public_ip", "private_ip", "eip": {"allocation_id", "ip"} | null, "vpc_id", "vswitch_id", "security_group_ids", "key_pair", "created_at", "cached"}`. The public address is the instance's own one, else its EIP's; the private address is the classic network address, else the primary address of the primary network interface. `created_at` is RFC 3339 (Alibaba Cloud keeps minutes only). With `--offline` the inventory is shown as it is (exit code 6 when it does not hold the instance).
- `create <name>` creates one instance from existing network resources: pay as you go, pay by traffic, no public address of its own (outbound bandwidth 0; the public address is an EIP). `--type` is required (or `defaults.aliyun.ecs_instance_type`). `--vswitch` (id or name) places it and decides its zone; by default it is the vSwitch `naming.aliyun_vswitch` names for zone `b` in the VPC `naming.aliyun_vpc` names, which has to exist (otherwise exit code 2). `--security-group` (name or id, required) is looked up in that vSwitch's VPC; a group of another VPC is exit code 1. The key pair is resolved like `key-pair ensure`, existing first: `--key-pair`, or the key pair holding `--ssh-key` / `--ssh-key-file`; a missing one is imported under `--key-pair` (a terminal asks for the name; the non-interactive flow never chooses one: exit code 2). The image is `--image`, else the newest image of `--os` (see `image latest`); the system disk is `--disk` GiB (20 by default; at least the image's size) of `--disk-category` (`cloud_essd_entry` by default). The host name is the name with every character other than letters, digits, hyphens and dots replaced by a hyphen (`site_a` becomes `site-a`), cut to 64 characters and trimmed of leading and trailing hyphens and dots; a name that leaves fewer than 2 characters is exit code 2. Instance names hold 2 to 128 characters, no `*`, and may not start with `i-`. An instance of the name in the region is exit code 1 (use `ensure`). The request carries a `ClientToken` derived from its content, so a retried request never creates a second instance; when the token answers an instance of an earlier identical request that was deleted since, the request is sent once more under a new token. `--wait` waits until it is `Running`; `--eip` waits too, then binds an EIP like `ensure` does. A zone without stock of the type is exit code 1 with a hint to pass `--vswitch` in another zone or another `--type`.
- `delete <name|id>` shows the instance and its addresses and asks for a confirmation (default no; `--yes` skips it; the non-interactive flow without `--yes` is exit code 2 before the account is opened). A `Running` instance is stopped and deleted once `Stopped`; `--force` deletes it at once. A `Pending`, `Starting` or `Stopping` instance is waited for until it is `Running` or `Stopped` (`--timeout` bounds each wait). A new instance cannot be deleted for about 45 seconds after its creation (`IncorrectInstanceStatus.Initializing`): the delete is retried every 3 to 5 seconds for up to 2 minutes. Deletion protection is exit code 1 (polyctl never switches it off). An EIP bound to the instance is not released: it becomes idle, stays billed (a note says so) and is reused by the next `ensure`.
- `reboot <name|id>` reboots a `Running` instance (`--force` is `ForceStop`); any other status is exit code 1. `--wait` waits until it is `Running` again, counting a `Running` read only after the instance was seen leaving `Running` (or 30 seconds after the reboot); a `Stopped` read on the way is accepted for 30 seconds.
- `resize <name|id> --type <type>` changes the type. ECS changes the type of a `Stopped` instance only, so a `Running` one is stopped (after a confirmation, default no; `--yes` skips it, the non-interactive flow needs it: exit code 2), changed and started again; a `Stopped` one stays `Stopped` and needs no confirmation. The stop is always waited for; `--wait` also waits until it is `Running` again. The same type is `unchanged`. A failed change leaves the instance `Stopped` with its old type (exit code 1, with the Alibaba Cloud message).
- `ensure <name>` makes sure the instance exists, is `Running` and holds an EIP; a second run changes nothing. An instance of the name (several are exit code 5) is used as it is: what it depends on is neither checked nor repaired, and a `--type` or `--disk` given that differs is reported `skipped` (`type differs: current X, want Y; use resize`), never changed; a `Stopped` instance is `skipped` (start it), a `Pending` or `Starting` one is waited for. Otherwise the whole chain is created as needed, in this order: the key pair (as for `create`), the VPC (`naming.aliyun_vpc`, `172.16.0.0/12`, waited for until `Available`), its vSwitches in zones `b` and `c` (`naming.aliyun_vswitch`, the first free `/22` blocks), the security group (`--security-group`, else `naming.aliyun_ecs_security_group`, `sg-common`) in that VPC with the `--rule` rules (else `defaults.aliyun.ecs_security_group_rules`, else `icmp:all:0.0.0.0/0`, `tcp:80:0.0.0.0/0` and `tcp:443:0.0.0.0/0`; missing rules are added, none removed), then the instance in the zone `b` vSwitch (with `--vswitch`, in that existing vSwitch instead, and the VPC and vSwitches are not ensured). The instance is `--type` (`defaults.aliyun.ecs_instance_type`, else `ecs.u1-c1m1.large`) with the image and disk of `create`. It is waited for until `Running` (polled every 2 seconds, `--timeout` 10m; a `Stopped` read right after the creation is normal and accepted for 30 seconds, a `Stopped` after `Running` is a failure); `--no-wait` returns at once and skips the EIP. Then (`--eip`, the default; `--eip=false` skips it) an instance without an EIP gets an idle EIP of the region, else a new one (see the EIPs below), bound and waited for until `InUse`; a binding refused because the EIP or the instance is not ready is retried every 3 seconds, 10 times. Nothing created is rolled back when a later step fails: run `ensure` again to go on. Rows: `key-pair/<name>`, `vpc/<name>`, `vswitch/<name>`, `security-group/<name>`, `security-group/<name>/rule`, `instance/<name>`, `instance/<name> status`, `eip/<name>`. An instance of the name that the inventory knows in another account or region is a note on stderr. `-o json` adds `"result": {"instance_id", "public_ip"}` (`(pending)` for an instance a dry run would create). `--dry-run` reads everything (the VPC, vSwitches, group and rules, the image, the idle EIPs) and reports what a real run would do, with `(pending)` for ids that do not exist yet. The default group name `sg-common` starts like a security group id: the `aliyun ecs security-group` commands read `sg-...` as an id, so address that group there by its id.

ECS security groups belong to one region (`--region`, the profile's region by default) and one VPC. polyctl creates VPC security groups only (type `normal`), and never sends a create without a VPC: Alibaba Cloud would then create a default VPC on its own.

- A group is named by its id (`sg-...`) or its name. Alibaba Cloud does not keep names unique, not even within one VPC: a name held by several groups is ambiguous (exit code 5: pass the id, or `--vpc`), a missing group is exit code 4. `--vpc` takes a VPC id or name (a name several VPCs share is ambiguous; a missing VPC is exit code 4).
- Rules use the format of every platform's firewall commands (see the AWS security groups below): `<protocol>:<port|from-to|alias|all>:<source>`, e.g. `icmp:all:0.0.0.0/0`, `tcp:http:0.0.0.0/0`, `tcp:8000-8999:10.0.0.0/8`, `tcp:1-65535:203.0.113.7`. They are written as ECS port ranges (`80/80`, `8000/8999`, `-1/-1` for `icmp` and `all`) with the policy `accept`, the NIC type `intranet` and `--priority` (1-100, default 1); ICMP from an IPv6 source is `ICMPv6`. A single IPv4 address is always sent as `/32`, because ECS keeps `203.0.113.7` and `203.0.113.7/32` as two rules. Malformed rules and priorities are exit code 2 before anything is sent (ECS answers some of them with misleading error codes).
- Rules are compared by protocol, ports, source (normalized: a bare IPv4 address equals its `/32`, host bits are masked, IPv6 is compressed) and policy; priority and description never count. Only ingress rules are read (`Direction=ingress`, every page) and managed.
- `list` shows `NAME`, `ID`, `VPC`, `RULES` (rules of both directions, as ECS counts them) and `DESCRIPTION`, from the local inventory per region; `--vpc <vpc-id>` keeps one VPC's groups (a VPC name is exit code 2). No groups is `[]`, a note on stderr and exit code 0.
- `get` shows the group and its ingress rules. In JSON: `{"name", "id", "vpc_id", "region", "type", "description", "profile", "rules": [{"id", "direction", "protocol", "port", "source", "policy", "priority", "description"}]}`; `protocol` and `policy` are lower case, `port` is the ECS port range and `source` is shown as ECS stores it.
- `create <name>` creates the group in `--vpc` (required; nothing is sent without it, exit code 2). A group of that name in the VPC is exit code 1 (use `ensure`). Names may not start with `sg-` and hold at most 128 characters.
- `ensure <name>` makes sure the group exists, holds the `--rule` rules and, with `--instance`, holds the instance; a second run changes nothing. The VPC is the instance's with `--instance` (another `--vpc` is exit code 2), else `--vpc`, else the VPC named by `naming.aliyun_vpc` (`{region}-vpc`), which has to exist (otherwise exit code 2 naming it); a group given by id (`sg-...`) without `--vpc` or `--instance` keeps its own VPC. The group is looked up by name in that VPC: a missing one is created (`security-group/<name>  created  sg-... vpc-...`), an existing one is used as it is (its description is kept), several are ambiguous. A group given by id that is in another VPC is exit code 1: a group cannot change VPCs. Rules present are `unchanged`; the missing ones are added in one call (ECS applies a batch as a whole). A group that is not found right after being created is retried a few times, 2 seconds apart. Rules are never removed, and without `--rule` only the group is ensured. `--instance` (name or id, found through the inventory in every selected account; several of one name are exit code 5) joins the instance to the group, keeping its other groups (`instance/<name>  updated  joined sg-... to i-...`; an instance already in it is `unchanged`); a group and an instance in different VPCs are exit code 1. `--dry-run` reads everything and reports `would create` (a new group's id is `(pending)` and all its rules would be created) and `would update  join <sg-id|(pending)> to <instance-id>`.
- `rule add <sg>` adds the rules to an existing group, like `ensure` without creating or joining anything, with `--description` on every rule added. `rule remove <sg>` removes rules given as `--rule` (every stored rule equal to it, `203.0.113.7` and `203.0.113.7/32` alike) or as `--rule-id <sgr-...>` (the ids `get` shows), not both; a rule that is not there is `unchanged`. The rules to remove are shown and confirmed (default no; `--yes` skips it, the non-interactive flow needs `--yes`, exit code 2); nothing to remove asks nothing. A rule removed meanwhile by someone else is `unchanged`.
- `delete` shows the group (name, id, VPC, rule count) and asks for a confirmation (default no; `--yes` skips it; the non-interactive flow without `--yes` is exit code 2 before the account is opened). A group that instances are still in, or that another group's rule references, is exit code 1 (`DependencyViolation`, with a hint saying which); polyctl never removes the instances or the reference for you. A group that is gone by the time it is deleted is `unchanged`.
- Errors carry the Alibaba Cloud code and message; RAM denials (`Forbidden.RAM`) are exit code 3.

ECS key pairs belong to one region (`--region`, the profile's region by default): a key used in several regions is imported in each. ECS imports RSA, ECDSA and ED25519 public keys and never returns them; it reports a fingerprint, the MD5 of the key in lower-case hexadecimal without colons, and that is what key pairs are compared by.

- `--ssh-key` takes the public key itself (one line); `--ssh-key-file` a file holding it (`~` is expanded, the first public key line is used). Alibaba Cloud accepts almost any text as a public key, so the key is checked locally: a file path given to `--ssh-key`, both flags together, a private key, text that is not a public key or a DSA key are usage errors (exit code 2) before anything is sent. The public key is never printed (reports show its algorithm, the start of its SHA256 fingerprint and of its comment), and only the key, not its comment, is sent.
- Names hold 2 to 128 characters and no `*` (which Alibaba Cloud reads as a wildcard); anything else is exit code 2.
- `key-pair list` shows `NAME`, `FINGERPRINT` and `CREATED`, every page of the region (cached in the local inventory per region). In JSON each key pair is `{"name", "fingerprint", "created", "region"}`; `created` is RFC 3339 (Alibaba Cloud keeps minutes only). No key pairs is `[]`, a note on stderr and exit code 0.
- `key-pair import <name>` imports the key and prints a change report (`key-pair/<name>  created`, with the fingerprint in `attrs`). A name that is taken is exit code 1 whatever key it holds (an existing key pair is never replaced; use `ensure`). `--dry-run` checks the key and the name and reports `would create`.
- `key-pair ensure [<name>]` reuses an existing key pair first. With a public key, the key pairs holding it are looked up by fingerprint (one filtered request, then the whole listing when none matches), and one that holds it is `unchanged` (`matched by fingerprint`) under its own name. The same key can be imported under several names: `<name>` picks one of them, otherwise a terminal asks and the non-interactive flow fails with exit code 5, listing the names. When no key pair holds the key, it is imported as `<name>`; without `<name>` a terminal asks for the name (an empty answer creates nothing, exit code 0) and the non-interactive flow is a usage error (exit code 2): no name is ever chosen for you. With `<name>` alone, an existing key pair is used as it is; a missing one needs a public key (a terminal asks for the file, offering `~/.ssh/*.pub`; otherwise exit code 2). A `<name>` that exists with another key is exit code 2 and is never replaced. `--dry-run` reports `unchanged` or `would create  import from ...` without writing.
- There is no `key-pair delete`: a key pair may still be bound to instances.

`aliyun ecs image latest` prints the id of the newest plain Alibaba Cloud Linux system image of the region (`--region`, else the profile's) for `--arch` (`x86_64` by default, or `arm64`). It asks for the image families `acs:alibaba_cloud_linux_4_lts_<arch>`, then `..._3_2104_lts_...`, then `..._2_1903_lts_...` (x86_64 only), and takes the first family that answers: a family returns its newest image only, and every variant (pro, container optimized, agentic, GPU, ...) has a family of its own, so a newer variant is never picked instead of the plain image. When none of these families answers, every page of the region's available Linux system images is read and the image whose family is a plain one (`acs:alibaba_cloud_linux_<version>[_<release>]_lts_<arch>`) with the highest version, then the newest, is taken; image names and OS names are never used to tell versions apart. The table output is the image id alone (`$(polyctl aliyun ecs image latest)`); `-o json` gives `{"image_id", "image_name", "os_name", "architecture", "creation_time", "region"}`. Image ids are regional. Only `--os alibaba-cloud-linux` is supported (any other value, or another `--arch`, is exit code 2); no matching image is exit code 1. It is read-only: `--dry-run` changes nothing in it, and `--offline` is exit code 6.

VPCs and vSwitches belong to one region (`--region`, the profile's region by default) and are always read from the API (`--offline` is exit code 6; `--dry-run` changes nothing in the read-only commands). Alibaba Cloud keeps the names of neither unique: several VPCs may share a name, and vSwitches may share one within a VPC (in other zones) and across VPCs. A name held by several is ambiguous (exit code 5: pass the id, `vpc-...` / `vsw-...`), a missing one is exit code 4. Names may not start with `vpc-` / `vsw-`, `http://` or `https://`, and hold at most 128 characters.

- `vpc list` shows `NAME`, `ID`, `CIDR`, `STATUS` and `DEFAULT`, every page of the region; the default VPC (the one Alibaba Cloud creates on its own) is left out unless `--all` is given. JSON: `[{"id", "name", "cidr", "region", "is_default", "status"}]`. No VPCs is `[]`, a note on stderr and exit code 0. `vpc get` adds the VPC's vSwitches (`"vswitches"`, shaped like the rows of `vswitch list`) and the profile.
- `vpc create <name>` creates the VPC with `--cidr` (`172.16.0.0/12` by default; an IPv4 block aligned to its mask, which cannot be changed later). A VPC of that name in the region is exit code 1 (use `ensure`). `--wait` returns once it is `Available` (about 3 seconds), bounded by `--timeout` (60s).
- `vpc ensure [<name>]` makes sure the VPC (default `naming.aliyun_vpc`, `{region}-vpc`) exists and holds a vSwitch in each of `--zones`, like `vswitch ensure`; a second run changes nothing. A missing VPC is created and waited for until it is `Available` (polled by id every 2 seconds, bounded by `--timeout`, 60s by default; running out of time is exit code 1 with the last status), because a `Pending` VPC refuses vSwitches. An existing VPC is used as it is (`unchanged`; its CIDR block is not compared, a note says when `--cidr` differs), and one still `Pending` is waited for, never created again. `--no-wait` returns once the creation was requested; the vSwitches of a VPC that is not `Available` yet are then `skipped` (run `ensure` again). `--dry-run` reports `vpc/<name>  would create  172.16.0.0/12` with the id `(pending)`, and the vSwitches of a VPC still to be created with the blocks of an empty VPC (`... (vpc pending)`).
- `vswitch list` shows `NAME`, `ID`, `VPC`, `ZONE`, `CIDR`, `STATUS` and `AVAILABLE IPS`, of the region or of `--vpc` (id or name). JSON: `[{"id", "name", "vpc_id", "zone", "cidr", "status", "available_ips", "region"}]`. No vSwitches is `[]` and exit code 0. `vswitch get` looks a name up in `--vpc` when given, else in the whole region.
- `vswitch create <name>` needs `--vpc` and `--zone` (a suffix such as `b`, or a zone id of the region such as `cn-hongkong-b`; nothing is sent without them, exit code 2). `--cidr` gives its block; without it the first free `/22` of the VPC's block is taken. A vSwitch of that name in the same zone of the VPC is exit code 1 (use `ensure`).
- `vswitch ensure` makes sure the VPC `--vpc` (default `naming.aliyun_vpc`, which has to exist: otherwise exit code 2 naming it) holds a vSwitch in each of `--zones` (`b,c` by default: `{region}-b` and `{region}-c`; suffixes or zone ids of the region, each once). They are named `<prefix>-<suffix>` with `--prefix` (no extra hyphen when the prefix ends with one), else by `naming.aliyun_vswitch` (`{region}-switch-{zone}`, `{zone}` being the suffix), and looked up by name in that VPC only: a vSwitch of the name in another VPC never counts. An existing one is `unchanged` whatever its zone or block (a warning in the detail says when its zone differs; vSwitches cannot be changed). The missing ones get the first free `/--netmask` blocks (22 by default, 16 to 29) of the VPC's block, scanned from its start and never overlapping the VPC's other vSwitches, so `--dry-run` shows the blocks a real run creates (`vswitch/<name>  created  vsw-... <zone> <cidr>`). A new vSwitch is waited for up to 30 seconds; running out of time is only a warning.
- vSwitch creation errors carry the Alibaba Cloud code with a hint: an overlapping block (`InvalidCidrBlock.Overlapped`), a block outside the VPC's (`InvalidParameter`) or not aligned (`IllegalParam.CidrBlock`) are exit code 1; a zone the region does not have (`ResourceNotAvailable`) is exit code 7, with a hint to pass `--zones`.

Elastic IP addresses (EIPs) belong to one region (`--region`, the profile's region by default) and are named by their allocation id (`eip-...`) or their address. An EIP is billed as long as it exists, bound or not; polyctl has no command that releases one (`list --unused` shows the idle ones).

- New EIPs are allocated with `AllocateEipAddress`: `--bandwidth` Mbps (`defaults.aliyun.eip.bandwidth`, else 200), `--isp` (`defaults.aliyun.eip.isp`, else `BGP_PRO`), pay by traffic, pay as you go, public, paid automatically, in the resource group `--resource-group` (a name, looked up with ResourceManager, or an `rg-...` id taken as it is; default `defaults.aliyun.resource_group`, else the group named `default`). A resource group that does not exist is exit code 4. An ISP the region does not offer is exit code 7 (which code Alibaba Cloud answers with is not verified: an invalid component, or a code naming the ISP, is mapped to it). An allocated EIP is read back (the answer of the allocation lacks most fields) and waited for until it is `Available` (up to 30 seconds).
- `list` shows `ALLOCATION_ID`, `IP`, `STATUS`, `BOUND_TO` (the instance, network interface or load balancer and its type), `NAME / DESC`, `BANDWIDTH` and `ISP`, every page of the region, cached in the local inventory per region. `--unused` keeps the EIPs bound to nothing, `--bound` the others (both together are exit code 2). JSON: `[{"allocation_id", "ip", "status", "instance_id", "instance_type", "name", "description", "bandwidth", "isp", "charge_type", "internet_charge_type", "service_managed", "resource_group_id", "region"}]`. No EIPs is `[]`, a note on stderr and exit code 0.
- `allocate` allocates one EIP and prints a change report (`eip/1  created  allocated 203.0.113.20 BGP_PRO 200Mbps PayByTraffic`); `--dry-run` resolves the resource group and reports `would create`.
- `associate <allocation-id|ip> --instance <name|id>` binds the EIP to an ECS instance (found through the inventory in every selected account; `--instance` is required). The EIP is looked up in the instance's region: a `--region` that differs from it is exit code 2, a missing EIP exit code 4. An EIP bound to the instance already is `unchanged`; an EIP bound elsewhere or not `Available`, an instance that holds an EIP already or is not in a VPC are exit code 1. After the binding the EIP is waited for until it is `InUse` by the instance (up to 30 seconds).
- `ensure` makes sure `--count` EIPs (1 by default; 2 for a dual-zone load balancer) are there to use, and with `--instance` that the instance holds one; a second run changes nothing. An idle EIP of the account in the region is reused first (`eip/1  unchanged  reuse idle 203.0.113.10`): bound to nothing, `Available`, not managed by a cloud product (`ServiceManaged` 0: a load balancer keeps the EIPs it used managed for up to a minute after letting them go) and of the ISP asked for. Any idle EIP of the account qualifies, whoever allocated it. The EIPs picked by one run are never picked twice, and `--exclude` leaves allocation ids out. The rest are allocated (`created`). `--instance` (with `--count 1` only) binds the EIP to the instance (`instance/<name>  updated  associated eip-... with i-...`); an instance that holds an EIP already is `unchanged` and nothing is reused, allocated or bound. `-o json` adds the EIPs to the report: `"result": {"eips": [{"allocation_id", "ip"}]}` (`(pending)` for one a dry run would allocate). `--dry-run` reads everything, so its `reuse idle` rows are those a real run reports.

Inventory types: `zone` (Alidns domains), `dns_record`, `domain` (registered domains), `instance`, `security_group`, `key_pair`, `eip`. Alidns stores the relative record name as `RR`; both the native `aliyun dns record` commands and the neutral `dns` commands expose it as `--name`. Records also carry a resolution line (`--line`), shown in the `LINE` column.

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

### Dry runs and change reports

`ensure` commands, and every write command run with `--dry-run`, print a change report: one row per resource, with what happened to it (or would happen).

```text
RESOURCE                    ACTION        DETAIL
security-group/web          unchanged     sg-0abc
security-group/web/rule     created       tcp 443 0.0.0.0/0
record/www.example.com/A    would update  203.0.113.10 -> 203.0.113.20
```

The actions are `created`, `updated`, `unchanged`, `skipped`, `deleted` and `failed`, and in a dry run `would create`, `would update` and `would delete` (`would_create`, `would_update`, `would_delete` in JSON and YAML). With `-o json` / `-o yaml` the report is

```json
{
  "target": { "platform": "aws", "profile": "acme", "region": "ap-east-1" },
  "dry_run": false,
  "changes": [
    { "resource": "security-group/web", "action": "unchanged", "id": "sg-0abc" },
    { "resource": "security-group/web/rule", "action": "created", "detail": "tcp 443 0.0.0.0/0" }
  ]
}
```

A report with nothing in it still prints its header (`"changes": []`). When a step fails, the report is printed all the same, with the failed step as `failed` and the error as its detail, and the command exits with the code of the error. Commands that work through a batch (several records, several accounts) go on after a failed item, report every item and exit with code 1 at the end when any failed.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, including an `ensure` that found everything unchanged and any `--dry-run`. Also every status `domain ns check` reports (`mismatch`, `no-zone`, ... included): it is a report, not an assertion. Also a menu or selection prompt left with Esc or Ctrl-C, a question of a login flow left with Ctrl-C or Ctrl-D, and a command that had nothing to do: no account to `sync` or `domain index` (none configured, none matching `--profile` / `--platform`, none supporting `--type`), no profile or account to pick from in `auth use` / `auth logout` / `auth manage`, a declined or left confirmation of `dns delete` (also `--all`), `aliyun ecs instance stop`, `delete` or `resize`, `aliyun ecs security-group delete` or `rule remove`, or `cloudflare r2 domain detach`, and the terms of service of the CA declined in `cert ensure`. The prompts in this row exist in the interactive flow only. |
| `1` | Generic error (API failure, I/O error, a login that was not approved in time, `config.yaml` changed by another process while the command ran, a failed certificate issuance or a certificate lock that did not come free, ...). |
| `2` | Usage error: bad flag combination, unknown flag or command (also below a command group: `polyctl dns nosuch`), unknown platform or resource type, missing required flag or argument, an unknown value of a login option (`--set env=`, `--set method=`), an invalid or already used name for `auth rename`, invalid config, an invalid `POLYCTL_NON_INTERACTIVE` value, `auth login` without `--profile` for a platform that only other profiles have. Also everything the non-interactive flow cannot ask for: `auth manage`, a missing argument (`auth login` without a platform, `auth use` without a profile, `auth logout` without `--profile`), a confirmation without `--yes` (`dns delete` of several records, `dns delete --all`, `aliyun ecs instance stop`, `delete` and the `resize` of a running instance, `aliyun ecs security-group delete` and `rule remove`, `cloudflare r2 domain detach`), and a login value or choice that was not passed (the message names the `--set` key or environment variable). Also `cert ensure` without an ACME account address or the agreement to the terms of service when it has to register an account. |
| `3` | Authentication: missing credentials, no account on the platform in the selected profile, rejected token, expired SSO session, `auth status` with a failing account. Also a request valid credentials were not allowed to make: a RAM / IAM policy denial (the platform's error code is kept in the message), or an account the platform refuses to serve until something is done in its console (Alibaba Cloud basic information not completed, real-name verification missing). Such a denial does not ask for a new login, and `sync` goes on with the account's other resource types. |
| `4` | Not found: unknown domain / zone / record / profile, a `--profile` / `--platform` selection that names no account able to hold the requested domain (`dns list`, `domain info`, ...), `auth logout <platform>` for a platform the profile has no account on, a set that was never synced in `--offline` mode, a domain no DNS account hosts in `cert ensure`, or a domain without a certificate in `cert get`. |
| `5` | Ambiguous: the domain has more than one candidate account (pass `--profile` and/or `--platform`, as the message says), or the platform more than one candidate profile (pass `--profile`). Also a `dns ensure` record whose name and type has several records, none of them as desired (pass `--prune-duplicates`). |
| `6` | Offline: the command needs the network but `--offline` was given. |
| `7` | Not supported: the platform (or the profile's client) cannot perform the operation. |

A non-zero code means the request could not be carried out. Having nothing to do is success: the command exits with code 0 and says why on stderr as a note, `nothing to do: <reason>`, without the `error:` prefix, and a command that prints a report still prints it, empty (`[]` with `-o json`), so scripts can test the exit code and parse stdout either way.

Errors are printed to stderr as `error: <message>`.

## Project layout

```text
cmd/polyctl/                 main(): calls internal/cli.Main and exits with its code
internal/cli/                Cobra command tree (root, auth, dns, domain, sync/inventory, platform mounts), exit-code mapping
internal/app/                Runtime shared by all commands: config, credential store, inventory, profile selection,
                             domain routing (ResolveDomain), resource routing (ResolveResource), cache policy
                             (EnsureSet / NeedsRefresh), SyncAccount, --dry-run and change reports, --wait flags,
                             per-platform defaults and naming, hooks.on_failure, the NS check of domain ns check
internal/platform/           Provider-neutral contracts: Provider, Client, DNSService, RegistrarService, Zone/Record/Domain,
                             resource types, sentinel errors, provider registry, DNS name helpers, live NS lookups and
                             the provider guess; the change plan of ensure commands (Plan / Step / Change / Report),
                             waits and retries, the shared parsers of ingress rules, listeners and DNS record specs,
                             the planner of dns ensure, SSH public keys and key pair resolution
internal/providers/
  cloudflare/  namecom/  godaddy/  aws/  gcp/  aliyun/
                             One package per platform: provider.go (login, client, sync) and commands.go (native commands)
internal/cert/               The certificate store, the ACME account and issuance (lego), the DNS-01 challenge records
                             written through a DNSService, the propagation check and the cert ensure flow
internal/config/             config.yaml loading/saving (profiles and their accounts), TTL defaults, defaults / naming /
                             hooks / cert / dns settings
internal/creds/              Keyring store, 0600 file store, Multi (read from any, write to primary)
internal/inventory/          SQLite schema, Replace/Upsert/Delete, Purge/RenameProfile, domain lookup, stats
internal/output/             table / json / yaml rendering
internal/dnstest/            Fake DNS resolvers on 127.0.0.1 for tests
internal/httpx/              Small JSON REST client with retries (Cloudflare, name.com, GoDaddy)
internal/prompt/             Line / secret / confirm prompts in the flow handed to them (they refuse in the
                             non-interactive one); Picker (arrow-key select, multi-select, confirm, input) drawn on stderr
internal/browser/            Open a URL in the default browser (macOS, Windows, Linux)
internal/loopback/           The 127.0.0.1 listener that takes the redirect of a browser login (GCP, Cloudflare)
```

Adding a platform means implementing `platform.Provider` (and `DNSService` / `RegistrarService` as applicable) in a new `internal/providers/<name>` package, registering it in `init()`, and mounting its Cobra subtree in `internal/cli/platforms.go`. The neutral commands, routing, caching and output need no changes.

## Security notes

- Secrets never enter `config.yaml`, the inventory or command output. `auth list` shows metadata only.
- Keyring entries are created under the service name `polyctl`; on macOS you may be asked once to allow `polyctl` access to the Keychain item.
- When the keyring is unavailable, `credentials.json` is written with mode `0600` inside a `0700` directory. Treat that file like `~/.aws/credentials`. Set `credential_store: keyring` if you would rather fail than fall back.
- `inventory.db` contains the full record data of every zone you synced (including TXT verification strings and the public IPs of instances). It is not encrypted; keep the config directory private or point `POLYCTL_INVENTORY_DB` at a protected location.
- Secrets are read from the terminal without echo. Passing them on the command line with `--set token=...` is convenient for scripts but leaves them in shell history and in the process list; prefer the interactive prompt, or `--set key=-` with the value piped on stdin by a secrets manager.
- AWS SSO role credentials and GCP OAuth access tokens are short-lived and minted on demand; polyctl stores the Identity Center access/refresh tokens (plus the registered OIDC client) and the Google refresh token, and refreshes them when possible.
- A Cloudflare browser login (`method=oauth`) stores the OAuth access token, the refresh token, the expiry and the granted scopes in the credential store, never in `config.yaml` (which records the method, the account and the list of granted scopes) and never in output, `-v` included. The client is a public one without a secret: each login is bound to a fresh PKCE verifier and a random `state`, the redirect is taken by a listener on `127.0.0.1` only, on a random port, for one request on one path, and the page it shows contains nothing of the request. The authorization covers a whole account, so prefer an API token where single zones are enough. `auth logout` revokes the refresh token and the access token at Cloudflare, best effort: when Cloudflare cannot be reached, or with `--offline`, a note says that the authorization could not be revoked, the account is removed all the same, and the authorization stays valid until you withdraw it in the Cloudflare dashboard.
- Create least-privilege tokens: Cloudflare tokens scoped to the zones you manage, GoDaddy/name.com tokens per machine, AWS roles limited to Route 53 / EC2, GCP service accounts with the DNS Administrator and Compute Instance Admin roles only.
- Network access goes directly to each platform's public API over HTTPS with a `polyctl/<version>` User-Agent; there is no telemetry and no intermediary service.

## Roadmap

- Cloud resources beyond DNS are skeletons: for Alibaba Cloud the ECS instance lifecycle (list, get, create, delete, reboot, resize, start, stop, ensure), ECS security groups, key pairs and the latest system image are implemented (`aliyun ecs`); AWS has the EC2 instance lifecycle (list, get, create, delete, reboot, resize, start, stop) and EC2 key pairs; GCP has the Compute Engine instance lifecycle (list, get, create, delete, resize, reboot, update, start, stop), VPC firewall rules (including the load balancer health check rule) and read-only VPC networks and subnetworks. Storage, networking, IAM and the rest of each cloud's surface are deliberately out of scope for now.
- GoDaddy and name.com registrar features beyond nameservers, lock, auto-renew and availability (transfers, contacts, purchases) are not planned for the first releases.
- Cloudflare coverage is limited to zones, DNS, cache purge, development mode, SSL mode and the custom domains of R2 buckets; Workers, Pages, Access and the contents of R2 buckets are not exposed.
- Planned: record import/export (zone-file and bulk JSON), `polyctl domain expiring` across registrars, encrypted file fallback for the credential store, and a `--watch` mode for `inventory stats`.

## License

[MIT](LICENSE)
