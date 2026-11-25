# Configuration

Where polyctl keeps its state, and the settings, flags and output conventions every command shares.

- [Files](#files)
- [Environment variables and global flags](#environment-variables-and-global-flags)
- [config.yaml](#configyaml)
- [Defaults, naming, hooks and certificates](#defaults-naming-hooks-and-certificates)
- [Credential storage](#credential-storage)
- [Caching](#caching)
- [Output formats](#output-formats)
- [Dry runs and change reports](#dry-runs-and-change-reports)
- [Exit codes](#exit-codes)
- [Security notes](#security-notes)

## Files

All state lives in one directory, `~/.config/polyctl/` by default (created with mode `0700`):

| File | Purpose |
| --- | --- |
| `config.yaml` | Profiles and settings. Metadata only, never secrets. Mode `0600`. |
| `inventory.db` | SQLite cache of platform resources and the domain index, plus the encrypted login credentials of Windows instances polyctl creates (see [Instances](instances.md)). Schema: [Development](development.md). |
| `credentials.json` | Secrets, **only** when the OS keyring is unavailable or `credential_store: file` is set. Mode `0600`. |
| `credentials.lock` | Lock file used while stored secrets change. Safe to delete when no polyctl is running. |
| `config.lock` | Lock file used while `config.yaml` is saved: of two processes saving at once, the later one sees the other's change and is refused ("run the command again") instead of overwriting it. Safe to delete when no polyctl is running. |
| `keyring-service` | Only in a config directory other than the default one: records that its keyring entries were copied from the shared service (see [Credential storage](#credential-storage)). |

## Environment variables and global flags

| Variable | Effect |
| --- | --- |
| `POLYCTL_CONFIG_DIR` | Configuration directory (holds `config.yaml`, `credentials.json`, `inventory.db`). |
| `POLYCTL_OUTPUT` | Output format: `table`, `json`, `yaml`. |
| `POLYCTL_CREDENTIAL_STORE` | `auto`, `keyring` or `file`; overrides `credential_store`. |
| `POLYCTL_INVENTORY_DB` | Path of the inventory file (default `<config dir>/inventory.db`). |
| `POLYCTL_NON_INTERACTIVE` | `1`, `true`, `yes`: never ask anything, like `--non-interactive`. `0`, `false`, `no` or empty: off. Any other value is a usage error (exit code 2). |

| Global flag | Effect |
| --- | --- |
| `--config-dir <dir>` | Configuration directory; overrides `POLYCTL_CONFIG_DIR`. Created with mode `0700` when missing. |
| `-p, --profile <name>` | Use this profile. Restricts routing, `sync`, `domain index` and `auth status` to its accounts. For `auth login`, the profile the account is added to. |
| `--refresh` | Ignore the cache: fetch from the platform and update the inventory. |
| `--offline` | Never touch the network; serve from the inventory only. Cannot be combined with `--refresh`. |
| `-o, --output <fmt>` | `table` (default), `json` or `yaml`. |
| `-v, --verbose` | Extra diagnostics on stderr. |
| `-y, --yes` | Confirm the commands listed in [Confirmations](interactive.md#confirmations), the interactive `auth logout` and the removal in `auth manage`. Required for them in the non-interactive flow (otherwise exit code 2). It confirms, it does not fill in missing arguments. |
| `--dry-run` | Write commands print a change report (`would create` / `would update` / `would delete`), write nothing and exit 0. Reads still happen; nothing is asked and `--yes` is not needed. Read-only commands ignore it. `auth login`, `auth use`, `auth logout`, `auth rename` and `auth manage` refuse it (exit code 2). |
| `--non-interactive` | Never ask, choose or confirm, also on a terminal. Missing arguments and unconfirmed actions are usage errors (exit code 2) naming what to pass. Overrides `POLYCTL_NON_INTERACTIVE`; `--non-interactive=false` keeps a terminal interactive. With `--yes`, destructive actions proceed without a question. See [Interactive use](interactive.md). |
| `--version` | Print the build version. |

Precedence for every setting: **flag > environment variable > `config.yaml` > built-in default**. A command is only interactive when stdin and stderr are terminals.

`--help`, `polyctl help <command>`, bare `polyctl` and a bare command group (`polyctl dns`) print help and exit 0 without reading the configuration. `polyctl help <unknown>` is a usage error (exit code 2).

Flags local to some commands:

- `auth login`, `auth manage`: `--no-browser` prints login URLs instead of opening a browser (implied in the non-interactive flow).
- `dns`, `domain`, `cert ensure`, `cert deploy`: `--platform <platform>` routes to the account on that platform; see [Routing rules](commands.md#routing-rules).
- `sync`, `inventory list`, `find`: `--platform` is a filter taking a comma-separated list of platforms.

## config.yaml

```yaml
current_profile: acme             # default profile of platform commands and `auth login`
credential_store: auto            # auto (default) | keyring | file
output: table                     # table | json | yaml

ttl:                              # freshness per resource type (Go durations)
  default: 24h
  dns_record: 1h
  instance: 15m

profiles:
  acme:                           # one account per platform
    platforms:
      cloudflare:
        metadata:
          account_id: 0123456789abcdef0123456789abcdef
          email: ops@example.com
        credential_backend: keyring
        created_at: 2026-11-01T10:00:00Z
        updated_at: 2026-11-01T10:00:00Z
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
        metadata: { method: keys, region: us-east-1 }
        credential_backend: keyring
```

| Key | Meaning |
| --- | --- |
| `current_profile` | Profile used without `--profile`, if it has an account on the platform. Otherwise polyctl uses the only profile with an account there, or errors listing the candidates. Also where `auth login` adds accounts. Set by `auth use`, and by `auth login` when none is current. A value naming no profile counts as unset. |
| `credential_store` | `auto` tries the keyring and falls back to the file (with a warning); `keyring` fails without a keyring; `file` always uses `credentials.json`. |
| `ttl.<type>` | How long a synced set stays fresh. Built-in defaults: `dns_record: 1h`, `zone: 24h`, `domain: 24h`, `instance: 15m`, `security_group: 1h`, `load_balancer: 1h`, `certificate: 24h`, `volume: 1h`, `db_instance: 15m`, `eip: 1h`, `key_pair: 24h`, `r2_bucket: 1h`, `default: 24h` (used for unset types). |
| `output` | Default output format. |
| `profiles.<name>.platforms.<platform>` | The profile's account on one platform: `cloudflare`, `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. |
| `….metadata` | Non-secret values the provider needs (account id, region, project, login method). Written by `auth login`; editable by hand. |
| `….credential_backend` | Where the secret is stored (`keyring` or `file`). Written by polyctl. |
| `….created_at` / `updated_at` | First added / last logged in. |
| `….legacy_secret`, `….legacy_backend` | Written by polyctl only, for accounts converted from 0.1.x whose secret has not moved yet. See [Upgrading from 0.1.x](accounts.md#upgrading-from-01x). |
| `profiles.<name>.defaults.<platform>.<key>` | Per-profile override of `defaults.<platform>.<key>`. |

Profile names must not contain spaces or slashes.

0.1.x files (`profiles.<name>.platform: cloudflare` with `metadata` next to it) are still read; each becomes a profile with that one platform. A profile mixing both layouts (`platform:` and `platforms:`, an empty `platform:`, or `metadata` / `credential_backend` / `created_at` / `updated_at` on the profile without `platform:`) is rejected (exit code 2): keep only `platforms:`.

If `config.yaml` changes while a command runs (another polyctl process or a hand edit), the command does not overwrite it: it fails with "the config file was changed since it was read" and can simply be rerun. `auth login` rereads the file after its login flow, so it is not affected.

## Defaults, naming, hooks and certificates

These keys configure commands that create resources. None holds a secret. Values with no neutral default (account names, keys, VPC or security group ids) must be configured here or passed as a flag; otherwise the command is a usage error (exit code 2) naming the flag and the key.

```yaml
defaults:                         # defaults.<platform>.<key>
  aws:
    region: eu-west-1
    vpc_id: vpc-0123456789abcdef0
    subnet_id: subnet-0123456789abcdef0
    security_group_ids: [sg-0123456789abcdef0]
    key_name: ops
    instance_type: t3.small       # aws ec2 instance create --type (type or size such as 2H4G)
    elb_security_group_ids: [sg-0fedcba9876543210]   # aws elbv2 load-balancer ensure --sg
    tags: { team: ops }
    rds:                          # aws rds instance create
      default_class: db.t3.micro  # --class (built-in db.m5.large)
      default_major: "8.0"        # --major (built-in 8.0)
      default_storage_type: gp3   # --storage-type (built-in gp3)
      subnet_group: default       # --subnet-group
      security_group_ids: [sg-0123456789abcdef0]   # --security-group
      parameter_group: default.mysql8.0            # --parameter-group
      default_tags: { backup: daily }              # added to Name=<id> and defaults.aws.tags
    acm:
      default_key_algorithm: EC_prime256v1         # aws acm certificate request --key-algorithm
      default_key_types: [EC_prime256v1, RSA_2048] # aws acm certificate list / get --key-type
      wildcard: true                               # aws acm certificate request --wildcard
  gcp:
    network: default
    subnet: default
    zone: europe-west1-b
    machine_type: e2-small        # gcp compute instance create --machine-type
    tags: [web]
    lb_network_tag: lb-health-check   # built-in default
    ssh_keys: []
  aliyun:
    region: cn-hongkong
    resource_group: rg-0123456789 # name or rg- id (aliyun eip, aliyun alb)
    eip:
      bandwidth: 200              # Mbps
      isp: BGP_PRO
    ecs_instance_type: ecs.u1-c1m1.large   # aliyun ecs instance create / ensure --type
    ecs_key_pair: ops             # key pair used without a key flag (if it exists in the region)
    ecs_security_group_rules: ["icmp:all:0.0.0.0/0", "tcp:80:0.0.0.0/0", "tcp:443:0.0.0.0/0"]   # aliyun ecs instance ensure --rule
    cas_region: ap-southeast-1    # default: ap-southeast-1 for a cn-hongkong profile, the central store otherwise
    cas_endpoint: cas.ap-southeast-1.aliyuncs.com   # default: the endpoint of cas_region
  cloudflare:
    ssl: strict                   # flexible | full | strict (built-in strict)

profiles:
  acme:
    defaults:                     # per-profile overrides
      aws:
        instance_type: t3.large

naming:                           # names of resources ensure commands create
  aws_elbv2_load_balancer: "{name}-lb"
  aws_elbv2_target_group: "{name}-{port}-target"
  aws_windows_key_pair: "{name}-win"   # aws ec2 instance create --os windows
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
  gcp_instance_external_ip: "{name}-external-ip"
  gcp_instance_internal_ip: "{name}-internal-ip"
  gcp_lb_firewall: "allow-lb-health-check-{network}"
  gcp_ssl_certificate: "{slug}-cert-{date}"

hooks:
  on_failure: https://hooks.example.com/polyctl   # or a shell command

cert:
  email: you@your-domain.tld      # ACME account address (CAs refuse example.com)
  agree_tos: false                # must be set to true explicitly
  dir: ""                         # default <config dir>/certs; ~ is expanded
  acme_directory: https://acme-v02.api.letsencrypt.org/directory
  key_type: ec256                 # ec256 | ec384 | rsa2048 | rsa4096
  reuse_key: false                # keep the private key on renewal
  renew_days: 30                  # default of --days
  name_template: "upload_{name}_{not_after}"
  skip_accounts: []               # profiles (name) or deployers (name:aliyun-alb) cert deploy skips
  dns_accounts: {}                # root domain -> DNS account (profile or platform/profile) when several host its zone
  dns:
    resolvers: ["1.1.1.1:53", "8.8.8.8:53", "223.5.5.5:53", "114.114.114.114:53"]
    min_resolvers: 2
    propagation_timeout: 5m
    poll_interval: 10s
    settle_delay: 20s
  aws:
    regions: [us-east-1]          # default: the account's region
  aliyun:
    regions: [cn-hongkong]

dns:                              # domain ns check
  resolvers: [1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4]
  timeout: 5s

find:
  concurrency: 8                  # accounts find --refresh syncs at once
  detail_timeout: 10s             # live lookup per match with --detail
```

- **`defaults`**: used when the flag is not given. Platform ids only (no aliases); keys may be nested. Order: flag, then `profiles.<name>.defaults`, then top-level `defaults`, then built-in default. Only `defaults.gcp.lb_network_tag` and `defaults.cloudflare.ssl` have built-in defaults; an invalid `ssl` value is rejected at load (exit code 2).
- **`naming`**: name templates for resources that `ensure` commands (and `aws ec2 instance create --os windows`) create unless a flag names them. Variables: `{name}`, `{service}`, `{protocol}`, `{port}`, `{region}`, `{zone}`, `{network}`, `{slug}`, `{date}`; which ones apply is documented with each command. Unknown keys or variables and unbalanced braces are rejected at load (exit code 2). The values shown are the defaults.
- **`hooks.on_failure`**: called when an `ensure`-style command fails (not for usage errors, dry runs or `--offline` runs, which never touch the network), typically from cron. An `http(s)://` value receives a `POST` with JSON `{"event": "<command>.failed", "platform", "profile", "target", "domain", "error", "time", "changes"}` (`cert deploy` adds `"deployer"`, one event per failed target). Any other value runs as a shell command (`/bin/sh -c`; on Windows `cmd /S /C "<value>"`, the value passed as written, so quoted paths with spaces work) with the JSON on stdin and `POLYCTL_EVENT`, `POLYCTL_PLATFORM`, `POLYCTL_PROFILE`, `POLYCTL_DEPLOYER`, `POLYCTL_TARGET`, `POLYCTL_DOMAIN`, `POLYCTL_ERROR` set. Timeout 15 s; a failing hook is a warning and never changes the exit code. After Ctrl-C or SIGTERM a run stops and sends at most one more notification; a second Ctrl-C ends the process at once, without waiting for the hook. Empty (default): no notification.
- **`cert`**: certificate command settings (see [Certificates](commands.md#certificates)). `email` and `agree_tos` are used only to register the ACME account on first issuance. `name_template` names certificates uploaded to Alibaba Cloud CAS (`{name}` = root domain, `{not_after}` = expiry date). `cert.dns.*` tune the DNS-01 check: resolvers asked, how many must see the TXT record (`min_resolvers`, at most the number of resolvers), longest wait, poll interval, and pause before the CA validates.
- **`dns.resolvers` / `dns.timeout`**: resolvers (IP or IP:port) `domain ns check` asks in order and per-query timeout; `--resolver` / `--timeout` override them. Invalid values are rejected at load (exit code 2).
- **`find.concurrency` / `find.detail_timeout`**: see [Finding resources](commands.md#finding-resources-by-ip-or-dns-name). Negative values are rejected at load (exit code 2).

## Credential storage

Each account's secret is one keyring entry: account `<profile>/<platform>` (for example `acme/cloudflare`), under a service that depends on the config directory:

- the default directory (`~/.config/polyctl`): service `polyctl`;
- any other directory (`--config-dir`, `POLYCTL_CONFIG_DIR`): service `polyctl:<16 hex digits>`, from the SHA-256 of the directory's absolute path. Two directories with a profile of the same name therefore never overwrite or delete each other's secrets. The directory's `keyring-service` file records its service and path, and the recorded service stays in use when the directory is moved or renamed, or reached by another spelling of its path (another letter case on a case-insensitive file system such as the macOS default, or a symbolic link), so its accounts and the data key of its instance passwords stay readable. A copy of a directory that still exists at the recorded path gets a service of its own on its first run, starting with copies of the original's entries. A `keyring-service` file written by an earlier release records the service only, and those releases used the service of whatever path the directory was reached by. When that service differs from the one the file records (the directory was moved, spelled another way or copied), the path's service stays in use, as it holds what those releases stored since (a login again after a move, the entries of a copy), the entries it lacks are copied from the recorded service, and the recorded service is kept in the file as a former one: a data key it holds still opens the instance passwords sealed with it. The default directory spelled in another case is still the default directory; if an earlier release gave it a service of its own that way (its `keyring-service` file says so), the entries the shared service lacks are copied from that service, and a data key there still opens the instance passwords sealed with it.

Releases before this layout stored the entries of every directory under `polyctl`. On its first run with a reachable keyring, a non-default directory copies the entries of its own accounts and `/instance-secrets` (wherever `POLYCTL_INVENTORY_DB` puts the inventory, and even when `credentials.json` holds a data key too) from `polyctl` to its own service, then writes the `keyring-service` marker file and stops looking at `polyctl` for account entries. The data key is also copied later, when it is needed and still missing from the directory's own service (a directory marked by an earlier release that did not copy it), and a different data key left under `polyctl` still opens the instance passwords sealed with it, so no new key is created while the old one exists. The entries under `polyctl` stay, as they may belong to the default directory; remove leftovers with your keyring tool if no default directory uses them.

- macOS: Keychain
- Windows: Credential Manager
- Linux / BSD: Secret Service (GNOME Keyring, KWallet)

A secret too big for one keyring entry (Windows Credential Manager takes at most 2560 bytes, which an AWS SSO login can exceed; the macOS keychain tool about 4 KB) is stored as several entries: `<profile>/<platform>` names the parts, stored as `<profile>/<platform>/part/<id>/<n>`. They are read, replaced and removed together. Releases before this one failed to store such a secret, so no existing entry changes.

Without a reachable keyring (headless servers, containers, no D-Bus session) polyctl falls back to `<config dir>/credentials.json` (mode `0600`) with a one-line warning. Reads check both backends, so accounts keep working when a keyring appears or disappears. `auth logout` removes the secret from every backend.

Force a backend with `credential_store: file|keyring` or `POLYCTL_CREDENTIAL_STORE`.

`credentials.json` and `config.yaml` are rewritten through a temporary file renamed over the original. On Windows, where that rename fails while another program has the file open (another polyctl reading it, an antivirus or indexing service), it is retried for about a second before the write fails.

The store also holds `/instance-secrets`, the data key that encrypts Windows instance passwords in `inventory.db`. `auth logout` leaves it alone. Unlike account secrets, it is never created anew while instance passwords are stored and a backend is out of reach (see [Instances](instances.md)).

## Caching

Every read goes through the inventory:

| Situation | Behaviour |
| --- | --- |
| Cached and younger than its TTL | Served from `inventory.db`; output notes `(local inventory)`. |
| Missing or expired | Fetched, stored, served. |
| `--refresh` | Always fetched and stored. |
| `--offline` | Always served from cache, even expired. Never synced: exit code 4. Any write to a platform: exit code 6. |

`polyctl find` always reads the inventory as is and syncs only with `--refresh`. DNS records are cached per zone.

Resource types (values of `--type`; each platform syncs the ones it supports):

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
| `eip` | elastic / static public IPs |
| `key_pair` | SSH key pairs |
| `r2_bucket` | Cloudflare R2 buckets (default jurisdiction) |

```text
polyctl sync [--platform cloudflare,aws] [--profile <name>] [--type domain,zone,...]
polyctl inventory stats
polyctl inventory list [--platform ...] [--type ...] [--name <exact name>] [--profile <name>]
polyctl inventory path
```

- `sync` fetches the selected types (default: all) for the selected accounts (default: every account of every profile) and replaces them in the inventory, one set at a time, printing a report per set. An authentication failure stops that account's sync. On AWS and Alibaba Cloud, `instance`, `load_balancer`, `eip`, `db_instance` (and `volume` on AWS) cover every enabled region; a failed region keeps its old data, is reported, and makes the exit code non-zero. A region whose resources were listed but whose details could not all be read (on Alibaba Cloud, network interfaces without `ecs:DescribeNetworkInterfaces`) is replaced with what was listed, so new instances appear and deleted ones go; the missing details are reported the same way. A set that keeps the old data of a failed region is not marked fresh: the next command that reads it syncs it again, and `find` reports the cached results as stale until a sync reads every region. Unknown `--profile`: exit code 4; unknown platform or type: exit code 2. Nothing to sync (no matching account or type) is success: empty report on stdout, `nothing to do: ...` on stderr, exit code 0.
- `inventory stats`: row counts and sync/expiry time per set. `inventory list`: cached rows; `--platform` / `--type` take lists as on `sync`. `inventory path`: the database path, bare in the table output (for `$(polyctl inventory path)`), as `{"path": "..."}` with `-o json` / `-o yaml`.

## Output formats

```sh
polyctl dns list example.com            # table (default)
polyctl dns list example.com -o json
polyctl dns list example.com -o yaml
POLYCTL_OUTPUT=json polyctl auth list
```

Precedence: `--output` > `POLYCTL_OUTPUT` > `output:` > `table`.

Tables show the most useful columns. JSON and YAML contain the full result, including routing:

```json
{
  "target": { "platform": "cloudflare", "profile": "acme", "resource_type": "zone", "resource_id": "9a1...", "domain": "example.com" },
  "cached": true,
  "records": [
    { "id": "f3c...", "zone_id": "9a1...", "name": "www.example.com", "type": "A", "value": "203.0.113.10", "ttl": 1, "proxied": true }
  ]
}
```

A list in the result is `[]` when empty, never `null`, at any depth (`"records": []` when a `dns list` filter matches nothing, `"nameservers": []` for a domain without nameservers).

Progress and notes go to stderr, so stdout is safe to pipe.

## Dry runs and change reports

`ensure` commands, most write commands, and every write command run with `--dry-run` print a change report:

```text
RESOURCE                    ACTION        DETAIL
security-group/web          unchanged     sg-0abc
security-group/web/rule     created       tcp 443 0.0.0.0/0
record/www.example.com/A    would update  203.0.113.10 -> 203.0.113.20
```

Actions: `created`, `updated`, `unchanged`, `skipped`, `deleted`, `failed`; in a dry run `would create`, `would update`, `would delete` (`would_create` etc. in JSON/YAML). JSON form:

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

An empty report still prints its header (`"changes": []`). A failed step is reported as `failed` with the error as detail, and the command exits with that error's code. Batch commands continue after a failed item and exit 1 at the end if any failed.

These writes print the written object instead of a report when run for real (a report only with `--dry-run`):

- `dns add`, `dns set`, `dns delete`, `domain ns set`;
- platform DNS record writes: `cloudflare dns create|update|delete`, `namecom dns create|update|delete`, `godaddy dns add|upsert|delete`, `aws route53 record upsert|delete`, `gcp dns record upsert|delete`, `aliyun dns record create|update|delete`;
- registrar writes: `ns set` of `aws route53domains`, `namecom domain`, `godaddy domain`, `aliyun domain`; `lock` / `unlock` / `autorenew` of `namecom domain` and `godaddy domain`;
- `cloudflare cache purge`, `cloudflare dev-mode` / `ssl-mode` with a value, `aws rds instance create`.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. Includes: an `ensure` with nothing changed, any `--dry-run`, every `domain ns check` status (it reports, it does not assert; except when every requested side failed, see 1), a prompt left with Esc / Ctrl-C (or Ctrl-D in a login), a declined [confirmation](interactive.md#confirmations) or declined CA terms or e-mail prompt in `cert ensure` / `cert deploy` (`cert deploy` reports the targets of that domain as skipped; a run with other failed targets still exits 1), and nothing to do (no account for `sync` / `domain index`, nothing to pick in `auth use` / `auth logout` / `auth manage`, no certificate target for `cert deploy`). |
| `1` | Generic error: API or I/O failure (including a config directory or `config.yaml` that cannot be created or read), `find --refresh` that could sync no account and found nothing, `domain ns check` when every requested side failed (registrar, zone and live lookup; the report is still printed, and the code is 3 when a side failed for credentials or permissions), a domain not found after the index was built or refreshed while no candidate account could be synced ([routing rule 5](commands.md#routing-rules)), `domain list --refresh` with an account that could not be synced, login not approved in time, `config.yaml` changed during the run, failed certificate issuance or busy certificate lock, failed `cert deploy` target (including a root domain that needs the ACME account registered while `cert deploy` runs non-interactively without `--email` / `--agree-tos` or `cert.email` / `cert.agree_tos`). |
| `2` | Usage error: bad or unknown flag, command, platform or resource type; missing argument; unknown login option value (`--set env=`, `--set method=`); invalid or taken name for `auth rename`; invalid config (a `config.yaml` that does not parse or holds an invalid value) or `POLYCTL_NON_INTERACTIVE`; `auth login` without `--profile` for a platform only other profiles have. In the non-interactive flow: `auth manage`, any missing argument, a confirmation without `--yes`, a login value not passed. `cert ensure` without ACME email or `agree_tos` when registering; `cert deploy` with both a domain and `--all` or neither, an unknown `--deployer`, or a `cert.skip_accounts` entry naming an unknown deployer. |
| `3` | Authentication: missing credentials, no account on the platform in the profile, rejected token, expired SSO session, `auth status` when every failing account failed for one of these reasons (otherwise 1). Also a permission denial (RAM / IAM, error code kept in the message) or an account the platform refuses to serve until fixed in its console (Alibaba Cloud basic information or real-name verification). `sync` continues with the account's other types. Also `cert deploy` when every failure was one of these, and the indexing failures listed under 1 when every account failed for one of these reasons. |
| `4` | Not found: unknown domain, zone, record or profile; a `--profile` / `--platform` selection with no account that can hold the domain; `auth logout <platform>` without such account; never-synced set with `--offline`; no DNS account for the domain in `cert ensure`; no certificate in `cert get`; domain unknown to `cert deploy`; `find` without a match or with never-synced sets. |
| `5` | Ambiguous: several candidate accounts for the domain (pass `--profile` / `--platform`) or profiles for the platform (pass `--profile`); `dns ensure` with several records of that name and type, none with the desired value (pass `--prune-duplicates`). |
| `6` | Offline: the command needs the network but `--offline` was given. |
| `7` | Not supported by the platform or client; `cert deploy --platform` for a platform without a deployer; `ssh-key` commands on a Windows instance. |

Having nothing to do is success: exit 0, a `nothing to do: <reason>` note on stderr, and an empty report on stdout (`[]` with `-o json`). Errors go to stderr as `error: <message>`.

## Security notes

- Secrets never enter `config.yaml`, the inventory or output; `auth list` shows metadata only. Exception: the password of a Windows instance polyctl created, stored encrypted in the inventory and printed only by an interactive create and by the instance group's `password` command.
- On macOS you may be asked once to allow `polyctl` access to its Keychain items.
- Treat `credentials.json` like `~/.aws/credentials`. Set `credential_store: keyring` to fail instead of falling back to the file.
- `inventory.db` is not encrypted (except Windows passwords) and holds full record data, including TXT verification strings and instance IPs. Keep the config directory private or point `POLYCTL_INVENTORY_DB` at a protected location.
- Secrets are read from the terminal without echo. `--set token=...` leaves the value in shell history and the process list; prefer the prompt, or `--set key=-` with the value on stdin.
- AWS SSO and GCP access tokens are short-lived and minted on demand from the stored refresh tokens.
- A Cloudflare browser login (`method=oauth`) authorizes a whole account; prefer an API token when single zones are enough. `auth logout` revokes the tokens at Cloudflare when reachable; otherwise (or with `--offline`) the account is removed locally and the authorization stays valid until you withdraw it in the Cloudflare dashboard.
- Use least-privilege credentials: Cloudflare tokens scoped to your zones, GoDaddy / name.com tokens per machine, AWS roles limited to Route 53 / EC2, GCP service accounts with DNS Administrator and Compute Instance Admin only.
- `ssh-key` commands use only the local key of the instance's key pair (or `--identity-file`), never store or print private keys, never use password authentication, run `sudo -n` only, and refuse a changed host key. Without a local key they use the platform's temporary access: a one-time in-memory key (EC2 Instance Connect, valid 60 s) or a root command (SSM Run Command, Cloud Assistant). See [Instances](instances.md).
- polyctl talks directly to each platform's HTTPS API with a `polyctl/<version>` User-Agent. No telemetry.
