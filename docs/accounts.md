# Accounts and profiles

How to log in to each platform and organise accounts into profiles.

- [Profiles](#profiles)
- [Commands](#commands)
- [Interactive management](#interactive-management)
- [Login flows per platform](#login-flows-per-platform)
  - [Cloudflare](#cloudflare)
  - [name.com](#namecom)
  - [GoDaddy](#godaddy)
  - [AWS](#aws)
  - [GCP](#gcp)
  - [Alibaba Cloud](#alibaba-cloud)
- [Upgrading from 0.1.x](#upgrading-from-01x)

## Profiles

A **profile** is a named set of accounts, at most one per platform. It usually stands for one project or customer: the profile `acme` holds acme's Cloudflare, name.com and AWS accounts, so `--profile acme` selects all of them. Two accounts on the same platform (production and test, two AWS organisations) go into two profiles.

```sh
polyctl auth login cloudflare --profile acme     # creates acme (current if no profile was)
polyctl auth login namecom    --profile acme     # adds a second platform
polyctl auth use acme                            # later commands default to acme
polyctl auth login aws                           # added to acme, unless another profile has AWS
polyctl auth rename acme acme-prod               # same accounts, secrets and cache
polyctl auth logout namecom --profile acme-prod  # drop one account
polyctl auth logout --profile acme-prod          # drop the whole profile
```

Secrets go to the system keyring, or a 0600 file when no keyring is available; see [Configuration](configuration.md) for credential storage and exit codes.

## Commands

```text
polyctl auth login <platform> [--profile <name>] [--set key=value ...] [--no-browser]
polyctl auth list
polyctl auth use <profile>
polyctl auth status [--profile <name>]
polyctl auth rename <old> <new>
polyctl auth logout [platform] --profile <name> [--keep-inventory]
polyctl auth manage [--no-browser]
```

### auth login

Runs the platform's login flow, verifies the credentials, stores the secret and writes the account's metadata to `config.yaml`.

- **Target profile:** `--profile`, else the current profile, else `default`. A missing profile is created; it becomes current if no profile was. A new name that differs from an existing profile's only in letter case (`Prod` next to `prod`) is a usage error (exit code 2): Windows Credential Manager matches entry names regardless of case, so the two profiles would share one secret. Profiles that already differ only in case keep working where the keyring is case-sensitive; rename one of them before using them on Windows.
- Logging in to a platform the profile already has re-authenticates that account; its other accounts are untouched.
- Without `--profile`, if the target profile has no account on the platform but another profile does, the interactive flow asks whether to re-authenticate there, add a second account, or use a new profile. The non-interactive flow fails with exit code 2 listing those profiles: pass `--profile <name>`.
- `--set key=value` (repeatable) passes platform options; `--set key=-` reads that value from stdin, one line per key in the order given. Use it for secrets, so they stay out of shell history and the process list. An unknown key is a usage error listing the valid ones.
- In the interactive flow anything missing is asked. In the non-interactive flow nothing is asked, no browser opens, and a missing value is a usage error (exit code 2) naming the `--set` key. See [Interactive use](interactive.md).
- `--no-browser` prints the URL of a browser-based flow instead of opening it (useful over SSH).
- `--offline` makes `auth login` fail with exit code 6 before anything is asked.
- Platform aliases are accepted: `cf`, `name.com`, `gd`, `google`, `alibaba`, ...
- Ctrl-C, or Ctrl-D on an empty line, at a login question ends with `cancelled`, exit code 0, nothing stored.

### auth list

One row per account: profile, platform, current marker (`*`), credential backend, metadata summary. A profile without accounts shows as `(no accounts)` (in JSON/YAML: `name` and `current` only).

### auth use

Sets `current_profile`. An unknown profile exits with code 4. Interactively, without a name, it asks which profile (with no profiles: `nothing to do`, exit 0). In the non-interactive flow the name is required.

### auth status

Verifies the stored credentials of every account (or of `--profile`) against the platform and prints the resolved identity (account, user, email, ARN, project...). Exits with code 3 when every failing account failed for its credentials or permissions, and with code 1 when one failed for another reason (network, timeout, platform outage); each row keeps its own error. Ctrl-C stops it before the accounts left. With `--offline` it only checks that credentials are present.

### auth rename

Renames a profile with its accounts, secrets and cached resources; `current_profile` follows. Unknown `<old>`: exit code 4. A `<new>` that exists, differs from another profile's name only in letter case, is empty or contains spaces or slashes: exit code 2. A rename that changes only the letter case (`prod` to `Prod`) is allowed and keeps the secrets, also in a keyring that matches entry names regardless of case. If it fails part way, the profile keeps its old name.

It is refused, with nothing changed, when an account's secret cannot be moved: its `credential_backend` is not available in this run (e.g. `keyring` while only the file store is in use), or it is still marked `legacy_secret` from 0.1.x and the old backend is unreachable. The message says which backend is needed, or to log in again.

### auth logout

- `auth logout --profile <name>` removes the whole profile: all accounts, their secrets from every backend, and their cached resources (keep those with `--keep-inventory`; kept rows no longer take part in domain routing, the domain pickers, `domain which`, `domain list` or completion; `inventory list` still shows them).
- `auth logout <platform> --profile <name>` removes one account; the profile goes with its last account. A platform the profile has no account on: exit code 4.
- Stored Windows instance passwords are kept but detached from the profile, so a different account logged in later under the same name does not inherit them; see [Instances](instances.md).
- Interactively, without `--profile`, it opens a list of accounts to tick, then confirms; `--yes` skips the confirmations (inventory removed unless `--keep-inventory`). Nothing to offer: `nothing to do`, exit 0.
- A Cloudflare browser login is revoked at Cloudflare first; if that is not possible (offline, unreachable), a note says so and the account is removed anyway.
- If the account's backend is not available in this run, the account is removed from `config.yaml` with a warning that its secret was left in that backend.
- Removing the current profile leaves none current until the next `auth use` or `auth login`.

## Interactive management

`polyctl auth manage` opens a menu (interactive flow only; otherwise it is a usage error naming the commands to use). It shows the `auth list` table and offers:

| Menu entry | What it does |
| --- | --- |
| View account details | Profile, platform, credential store, whether credentials are present, created/updated times, all metadata, cached resource counts. Nothing is fetched. |
| Switch current profile | `auth use` from a list. |
| Add an account (log in) | Pick a platform, then a profile or "New profile...", then the `auth login` flow. |
| Verify credentials | Tick accounts (Ctrl-A ticks all), get the `auth status` table. |
| Rename a profile | `auth rename` from a list. |
| Remove accounts or profiles | Tick accounts across profiles, review, confirm (default No), choose whether to keep the cached inventory (default No). With `auth manage --yes` both questions are skipped and the inventory is removed. |
| Quit | Leave the menu (`q` too). |

Keys: arrows or `j`/`k` move, space ticks, `/` filters, enter confirms. In yes/no questions `y`/`n` select and enter confirms. Esc or Ctrl-C returns to the menu; at the top level Esc, Ctrl-C or `q` exits with code 0. The menu re-reads `config.yaml` before every action, so changes made by other polyctl commands meanwhile are kept.

`auth use`, `auth login` and `auth logout [platform]` without their argument ask for it the same way on a terminal. Leaving such a prompt prints `cancelled` and exits 0.

## Login flows per platform

Each platform lists its `--set` keys. Required values for the non-interactive flow are under "Non-interactive".

### Cloudflare

Keys: `method`, `token`, `account_id`.

| `method` | Flow |
| --- | --- |
| `token` (default) | API token. polyctl opens <https://dash.cloudflare.com/profile/api-tokens> and asks for the token. |
| `oauth` | Approve in the browser (OAuth with PKCE); polyctl waits up to 5 minutes on a `127.0.0.1` listener. Interactive only. With `--no-browser`, open the URL in a browser on the same machine (or forward the port). |

**API token permissions:** required `Zone:Read` and `DNS:Edit` (the "Edit zone DNS" template is a good start). Optional: `Account:Read` (list accounts), `Zone:Edit` (cache purge, development mode, SSL mode, `cloudflare zone` create/delete/configure), R2 read and write (`cloudflare r2`), Cache Rules and Single Redirects (`cloudflare cache rule` / `redirect rule`), `User:Read` (show your email).

**Token or browser:**

- Browser: one approval, covers a whole account (cannot be limited to zones). Required scopes `zone.read`, `dns.read`, `dns.write`, `offline_access`; optional `cache.purge`, `zone-settings.read`, `zone-settings.write`, `account-settings.read`, `user-details.read` (a command that needs a declined scope says so; log in again to grant it). polyctl refreshes the access token itself and revokes it on `auth logout`. If the refresh token is refused, the command exits with code 3: log in again. `--offline` never refreshes. Accounts whose admin disabled third-party OAuth apps are not offered: use a token.
- Token: for scripts, CI and least privilege (can be limited to zones and exact permissions). You create and delete it in the dashboard; `auth logout` only forgets it.

> The browser login is not available to everybody yet: polyctl's OAuth client is not published, so `method=oauth` only works for members of the publisher's Cloudflare account. Everyone else should use an API token.

Without `--set method`, a token given with `--set token` or `CLOUDFLARE_API_TOKEN` selects `token`, and a re-login keeps the stored method. `method=oauth` with `--set token` is a usage error; `CLOUDFLARE_API_TOKEN` is ignored (with a note) for `method=oauth`.

`account_id` is optional: polyctl lists the accounts the credentials can see and asks if there are several. In the non-interactive flow several accounts are a usage error listing them.

**Non-interactive:** export `CLOUDFLARE_API_TOKEN`, or `--set token=-` with the token on stdin (`--set token` wins). A token piped without `--set token=-` is ignored.

```sh
polyctl auth login cloudflare
polyctl auth login cloudflare --set method=oauth
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile acme --set account_id=...
echo "$TOKEN" | polyctl auth login cloudflare --profile acme --set token=-
```

### name.com

Keys: `username`, `token`, `env`.

Username plus API token from <https://www.name.com/account/settings/api>. API access must be enabled there, and name.com may require your IP to be whitelisted.

`env` is `production` (default) or `test` (`api.dev.name.com`). The test environment needs a token created for it and your username with `-test` appended (added automatically).

**Non-interactive:** `--set username=<user> --set token=-`.

```sh
polyctl auth login namecom --profile acme
printf '%s\n' "$NAMECOM_TOKEN" | polyctl auth login namecom --profile acme --set username=acme --set token=-
polyctl auth login namecom --profile acme-test --set username=acme --set token=- --set env=test
```

### GoDaddy

Keys: `method`, `token`, `api_key`, `api_secret`, `env`, `base_url`.

Personal Access Token from <https://developer.godaddy.com/personal-access-token> (`method=pat`, default). The legacy API key + secret (`method=api_key`, selected automatically by `--set api_key` / `api_secret`) still works but is deprecated by GoDaddy for the Domains API. A method that contradicts the credential, or a token together with the key pair, is a usage error.

`env` is `production` (default) or `ote` (`api.ote-godaddy.com`). `base_url` overrides the API endpoint.

Production API access requires the account to hold at least one domain or be on a plan with API access; paid operations need a billing method. Otherwise requests fail with `403 ACCESS_DENIED` (exit code 3); use an OTE credential for development.

**Non-interactive:** `--set token=-`, or `--set api_key=<key> --set api_secret=-`.

```sh
polyctl auth login godaddy --profile acme
printf '%s\n' "$GODADDY_TOKEN" | polyctl auth login godaddy --profile acme --set token=-
polyctl auth login godaddy --profile acme-ote --set token=- --set env=ote
polyctl auth login godaddy --profile legacy --set api_key=... --set api_secret=-
```

### AWS

Keys: `method`, `region`, `start_url`, `sso_region`, `account_id`, `role_name`, `aws_profile`, `access_key_id`, `secret_access_key`, `session_token`.

| `method` | Flow |
| --- | --- |
| `sso` (default) | IAM Identity Center device-code login. Asks for `start_url`, `sso_region`, `account_id`, `role_name` when not given, opens the verification URL and waits for approval. Role credentials are exchanged again before they expire, also during a long wait in one command (the access token is refreshed with the refresh token when it has expired); when the SSO session itself expires, log in again. |
| `keys` | Static access key id, secret access key and optional session token: asked, passed with `--set`, or taken from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` when neither key is given with `--set`. |
| `profile` | References a profile in `~/.aws/config` / `~/.aws/credentials` (`aws_profile`). Nothing is copied; the AWS SDK resolves it. |

`region` is the default region for EC2 and other regional services; Route 53 and Route 53 Domains are global.

**Non-interactive:** `--set method=` is required (a re-login keeps its method).

- `sso`: `start_url` required (`sso_region` defaults to `us-east-1`); the URL and code are printed and polyctl waits until the code expires. `account_id` and `role_name` are required when several are accessible.
- `keys`: `--set` keys or the environment variables; the session token is never asked.
- `profile`: without `aws_profile`, the previous login's profile, else `default`.

```sh
polyctl auth login aws --profile acme --set method=sso --set start_url=https://acme.awsapps.com/start \
  --set sso_region=us-east-1 --set account_id=123456789012 --set role_name=AdministratorAccess --set region=eu-west-1
polyctl auth login aws --profile lab --set method=keys
printf '%s\n' "$SECRET" | polyctl auth login aws --profile ci --set method=keys --set access_key_id=AKIA... --set secret_access_key=-
polyctl auth login aws --profile legacy --set method=profile --set aws_profile=default
```

### GCP

Keys: `method`, `project`, `key_file`, `client_id`, `client_secret`.

`polyctl auth login gcp` on a terminal opens the browser and signs in with your Google account. gcloud is not needed.

| `method` | Flow |
| --- | --- |
| `oauth` (default on a terminal) | Browser login. Opens Google's consent screen, receives the code on a loopback listener on `127.0.0.1` (authorization code with PKCE; waits up to 5 minutes without a terminal) and stores the refresh token. Uses the OAuth client built into polyctl, or your own Desktop-app client with `client_id` and `client_secret`. |
| `service_account` | `key_file=<path>`: the JSON key's contents are stored. A leading `~`, `~/` or `~\` is the home directory, also in the interactive prompt. `project` defaults to the key's `project_id`. |
| `adc` (default without a terminal) | Application Default Credentials, as written by `gcloud auth application-default login`. Nothing is stored. If none exist, polyctl prints that command (and says so when gcloud is not installed), names the other methods and exits with code 3. |

Which method a login uses:

- `--set method=` when given.
- Else the method of the account when it is logged in again. An account of your own OAuth client keeps to such a client and needs `client_id` and `client_secret` again; to move it to the built-in client, remove it with `polyctl auth logout gcp --profile <name>` and log in again.
- Else, on a terminal, the browser login with the built-in client; no question is asked about the method.
- Else (non-interactive) `adc`.

The built-in client:

- Until Google has verified it, the consent screen may show **"Google hasn't verified this app"**. Choose **Advanced**, then the **Go to ... (unsafe)** link, to continue. If you would rather not, `method=adc`, `method=service_account` and `method=oauth` with your own client remain available.
- Its id and secret are part of the program (Google does not treat the secret of a desktop client as confidential) and are never stored: the account records `oauth_client: builtin` in `config.yaml` and its refresh token in the credential store, and takes the client from the polyctl binary in use.
- A polyctl build without a built-in client (none is set while the client is being registered) behaves as follows instead: on a terminal, `adc` when Application Default Credentials exist, else polyctl asks which way to log in (a service account key file, your own OAuth client, or instructions for creating the credentials with gcloud; the last one adds no account and exits with code 0). `method=oauth` then needs `client_id` and `client_secret`, and an account of the built-in client cannot be used (exit code 3) until you log in again.

`project` sets the default project; without it polyctl lists visible projects and asks.

**Non-interactive:** nothing is asked, no browser is opened, and the default method is `adc`. `service_account` needs `key_file` (and `project` if the key names none). `oauth` needs `project` (and `client_id`, `client_secret=-` for your own client, or in a build without a built-in one); it prints the consent URL and waits up to 5 minutes for the browser to return. The project otherwise falls back to the previous login's, the ADC project, or the only visible one; several and no default is a usage error.

`--no-browser` prints the consent URL instead of opening a browser; open it in a browser on the same machine, as the code returns to `127.0.0.1`.

```sh
polyctl auth login gcp --profile acme                                          # browser login
polyctl auth login gcp --profile acme --set method=adc --set project=acme-prod
polyctl auth login gcp --profile acme-ci --set method=service_account --set key_file=./sa.json --set project=acme-ci
printf '%s\n' "$CLIENT_SECRET" | polyctl auth login gcp --profile me --set method=oauth --set client_id=<id> --set client_secret=- --set project=acme-prod
```

### Alibaba Cloud

Keys: `site`, `access_key_id`, `access_key_secret`, `region`, `aliyun_profile`.

RAM AccessKey pair from <https://ram.console.aliyun.com/manage/ak>. polyctl asks for the site, then the key id and secret, then the region. The key can also come from `--set` or, when neither key is given with `--set`, from `ALIBABA_CLOUD_ACCESS_KEY_ID` / `ALIBABA_CLOUD_ACCESS_KEY_SECRET`.

- **`site`** (`cn` = aliyun.com, `intl` = alibabacloud.com) is required when adding an account; there is no default. It selects the registrar API and console links. It cannot change later: a different `--set site` is a usage error; remove and re-add the account instead. For main accounts polyctl cross-checks the site with the billing API and warns if it looks wrong (skipped for RAM users without billing permission). Accounts added before the site was required derive it from the region; log in again with `--set site=` to record it.
- **`region`**: default region for ECS (default `cn-hangzhou`). Alidns is region-independent.
- **`aliyun_profile=<name>`** imports the AccessKey of an Alibaba Cloud CLI profile (`~/.aliyun/config.json` or `ALIBABA_CLOUD_CLI_CONFIG`; `current` = the CLI's current profile; AK-mode profiles only). The key is copied, so later CLI changes need a new login.

**RAM permissions** (grant as needed):

| Commands | Policy |
| --- | --- |
| DNS, domains, ECS reads | `AliyunDNSFullAccess`, `AliyunDomainFullAccess`, `AliyunECSReadOnlyAccess` |
| ECS writes (instances, security groups, key pairs, `ecs instance ssh-key`) | `AliyunECSFullAccess` |
| Security group VPC lookups, `aliyun vpc` listings | `AliyunVPCReadOnlyAccess` |
| `aliyun vpc` and `aliyun eip` writes | `AliyunVPCFullAccess` (plus `AliyunResourceManagerReadOnlyAccess` to find a resource group by name) |
| `aliyun cas` | `yundun-cert:*` actions |
| `aliyun alb` | `AliyunSLBFullAccess` or `alb:*`; `ensure` also `AliyunVPCFullAccess`, `AliyunECSReadOnlyAccess`, `yundun-cert:ListUserCertificateOrder`, `AliyunResourceManagerReadOnlyAccess` |
| Listener check of `aliyun cas certificate delete` | `alb:ListLoadBalancers`, `alb:ListListeners`, `alb:GetListenerAttribute`, `alb:ListListenerCertificates`, `ecs:DescribeRegions` |

**Non-interactive:** `--set site=cn|intl` plus the key (`--set` or environment) or `aliyun_profile`. The region is never asked: `--set region`, else the CLI profile's, else the previous login's, else `cn-hangzhou`.

```sh
polyctl auth login aliyun --profile acme --set region=cn-hangzhou
printf '%s\n' "$AK_SECRET" | polyctl auth login aliyun --profile ci --set site=intl --set access_key_id=LTAI... --set access_key_secret=-
polyctl auth login aliyun --profile acme --set site=cn --set aliyun_profile=default
```

## Upgrading from 0.1.x

In 0.1.x a profile was one account on one platform; now it is a set of accounts, one per platform.

**Automatic:**

- `config.yaml` is converted: each old profile becomes a profile of the same name with that one platform. Names, `current_profile`, metadata and inventory are kept.
- Secrets move from the bare profile name to `<profile>/<platform>` on the first command that opens the credential store. If the old backend is unreachable, the account stays marked `legacy_secret: true`, keeps working from the old entry, and the move is retried later (`-v` shows errors).
- Cached DNS records are converted when `inventory.db` is opened.

**What changes for you:**

- `auth login <platform>` targets the current profile (or `default`), not a profile named after the platform. Re-authenticate a converted profile with its old name: `polyctl auth login cloudflare --profile cloudflare`.
- `auth logout` takes an optional platform: `auth logout <platform> --profile <name>` removes one account.
- To merge one-platform profiles, log in again under a common `--profile` and remove the old ones. To just rename, use `polyctl auth rename cloudflare acme`.
- Without a terminal, nothing is read from stdin unless a flag says so. Pass secrets with `--set token=-` and confirmations with `--yes`: `echo "$TOKEN" | polyctl auth login cloudflare --set token=-`; `auth login aws` needs `--set method=`.

**Renamed flags, variables and commands** (no aliases except `cf`; old spellings exit with code 2):

- `--config <file>` is now `--config-dir <dir>` (the directory holding `config.yaml`).
- `--non-interactive` / `POLYCTL_NON_INTERACTIVE=1` are new (`--no-input` / `POLYCTL_NO_INPUT` from pre-0.2 `main` builds are gone).
- `POLYCTL_OUTPUT` now overrides `output:` in `config.yaml` (flag > environment > config > default).
- `--no-browser` is a flag of `auth login` and `auth manage` only.
- An unknown subcommand (`polyctl dns nosuch`, `polyctl help dns nosuch`) is a usage error (exit 2), not help with exit 0.
- `dns update` is now `dns set`; `dns update --add` is now `dns add`.
- `ns set <domain> --ns a,b` is now `ns set <domain> a b` (all trees).
- `--proxied true|false` is now `--proxied` / `--proxied=false`.
- `inventory list --platform` / `--type` take lists.
- `domain which` now honours `--profile` / `--platform`.
- Record data is `value` everywhere: table column `VALUE`, JSON/YAML field `value` (was `content`).

| 0.1.x | now |
| --- | --- |
| `cf ...` | `cloudflare ...` (`cf` remains an alias) |
| `cf token verify` | `cloudflare whoami` |
| `namecom hello` | `namecom whoami` |
| `aws sts whoami` / `aliyun sts whoami` | `aws whoami` / `aliyun whoami` |
| (none) | `gcp whoami`, `godaddy whoami` |
| `cf dns update\|delete <zone> --id <id>` | `cloudflare dns update\|delete <zone> <id>` |
| `namecom dns update\|delete <domain> --id <id>` | `namecom dns update\|delete <domain> <id>` |
| `aliyun dns record update\|delete <domain> --id <id>` | `aliyun dns record update\|delete <domain> <id>` |
| `aliyun dns record add` | `aliyun dns record create` |
| `godaddy dns replace` | `godaddy dns upsert` |
| `godaddy domain available` | `godaddy domain check` |
| `aws route53domains domain list\|get` | `aws route53domains list\|get` |
| `aws ec2 list\|start\|stop` | `aws ec2 instance list\|start\|stop` |
| `gcp compute list\|start\|stop` | `gcp compute instance list\|start\|stop` |
| `aliyun ecs list\|start\|stop` | `aliyun ecs instance list\|start\|stop` |

`--id` remains an optional flag on `dns delete`, `godaddy dns delete` and `gcp dns record delete`. All `whoami` commands now print `profile`, `platform`, `identity`.

**Login options:**

- Unknown `--set` keys are a usage error (0.1.x ignored them).
- Alibaba Cloud: `from_cli=` is now `aliyun_profile=`; `site=cn|intl` is required when adding an account.
- GoDaddy: `key=` / `secret=` are now `api_key=` / `api_secret=`.
- Option values have one spelling: GCP `method=adc|service_account|oauth`, GoDaddy `method=pat|api_key` and `env=production|ote`, name.com `env=production|test`. Stored accounts keep working.
