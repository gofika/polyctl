# Accounts and profiles

How to log in to each platform and organise accounts into profiles.

- [Profiles](#profiles)
- [Enabled, disabled and default](#enabled-disabled-and-default)
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

## Enabled, disabled and default

One GCP account reaches several Google Cloud projects, and one Cloudflare login several Cloudflare accounts. polyctl treats both in the same way, with three words:

- **Enabled.** Every project (account) the credentials see is enabled, the ones created or shared later included. Nothing has to be added. A sync, the inventory, the lists, the name lookups and the platform-neutral commands that route by domain or address (`dns`, `domain`, `find`, `cert deploy`, ...) cover every enabled one, not only the default.
- **Disabled.** A disabled project (account) is kept out of every sync, list, lookup and routing, and what the inventory cached of it is dropped: disable the ones that are certainly not used. `polyctl gcp project enable` and `polyctl cloudflare account enable` manage which ones are enabled: on a terminal, without arguments, they open one list of everything visible with the enabled ones ticked, and what is ticked at the end is enabled and the rest disabled. `enable <id>...` and `disable <id>...` change the ones named, for scripts; `disable` always needs them (exit code 2 without). Only the disabled ones are stored (`disabled_projects`, `disabled_accounts` in `config.yaml`).
- **Default.** The default project (account) is only what a command works on when nothing names one: where a new instance, firewall rule, certificate or zone is created. It is always enabled. A login chooses it, and `polyctl gcp project use <id>` / `polyctl cloudflare account use <account>` change it.

`--project <id>` on the `gcp` commands and `--account <id or name>` on the `cloudflare` commands name one for a single call. A disabled one can be named too: it is read live and nothing of it is cached.

```sh
polyctl gcp project list                 # every visible project, ENABLED yes or no, * the default
polyctl gcp project enable               # on a terminal: tick the projects that stay enabled
polyctl gcp project disable acme-lab     # the shortcut: never synced or searched again, until enabled
polyctl cf account enable                # the same list for the Cloudflare accounts
polyctl cf account disable "Acme Lab"
polyctl sync                             # every enabled project and account of every profile
```

Because everything visible is enabled, a sync touches every project and account the credentials reach: disable what is not used to keep it short. Details, exit codes and what credentials that cannot list their projects or accounts cover are in [GCP: Projects](platforms/gcp.md#projects) and [Cloudflare: Accounts](platforms/cloudflare.md#accounts).

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

One row per account: profile, platform, current marker (`*`), credential backend, metadata summary. A GCP account shows its default project and a Cloudflare login its default account, each with the number of disabled ones when there are any (`project=acme-prod (2 disabled)`, `account_id=0123456789abcdef0123456789abcdef (1 disabled)`). A Cloudflare login without a default account shows `no default account (2 disabled)` when it holds disabled accounts. The enabled ones are not counted: that needs the platform, and `auth list` reads the local configuration only. A profile without accounts shows as `(no accounts)` (in JSON/YAML: `name` and `current` only).

### auth use

Sets `current_profile`. An unknown profile exits with code 4. Interactively, without a name, it asks which profile (with no profiles: `nothing to do`, exit 0). In the non-interactive flow the name is required.

### auth status

Verifies the stored credentials of every account (or of `--profile`) against the platform and prints the resolved identity (account, user, email, ARN, project...; for GCP the default project and for Cloudflare the default account, with `(N disabled)` when projects or accounts are disabled; a Cloudflare login without a default account says `no default account (N disabled)`). Exits with code 3 when every failing account failed for its credentials or permissions, and with code 1 when one failed for another reason (network, timeout, platform outage); each row keeps its own error. Ctrl-C stops it before the accounts left. With `--offline` it only checks that credentials are present.

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

Keys: `method`, `token`, `account_id`, `disabled_accounts`.

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

A login works on every account its credentials see ([Enabled, disabled and default](#enabled-disabled-and-default)). It chooses the default account only, where new zones are created. Credentials that see one account use it and nothing is asked.

- When the credentials see several accounts, a first login in the interactive flow asks which one is the default; in the non-interactive flow it is a usage error listing them (pass `--set account_id=<id>`). No list is ticked at a login.
- `account_id=<id>` names the default account. It must be visible to the credentials, when they can list their accounts.
- A later login keeps the default account stored before (said on stderr when several are visible). One the credentials no longer see: a token fails until `--set account_id` names another; a browser login says so and asks again.
- `disabled_accounts=<id>,<id>,...` sets the disabled accounts; given empty, none is disabled. Without it a later login keeps the stored list. The ids are not checked against what the credentials see (an account may become visible later); naming the default account is a usage error.
- `accounts=...` is not an option (it existed only in unreleased builds): it is answered by the usage error for an unknown login option.
- A token that cannot list accounts (no `Account:Read`) takes `account_id` as given, and without it the login has no default account: it works on every zone it sees, and a new zone or R2 needs `--account`. An account-owned token sees its own account only.
- Stored as the metadata `account_id`, `account_name` (the default account) and `disabled_accounts` (absent when none is disabled).
- A login that disables more accounts drops their cached zones, records and R2 buckets at once; one that enables accounts again makes the cached sets of the login due: the next online command that reads a set syncs it, and the commands that route by domain sync the zone set before their lookup ([routing rule 5](commands.md#routing-rules)).
- When several accounts are enabled the login says so and names `polyctl cloudflare account enable`, which chooses the ones that stay enabled. `polyctl cloudflare account use`, `enable` and `disable` change the default and the disabled accounts without a new login; `account current` shows them. See [Cloudflare: Accounts](platforms/cloudflare.md#accounts).

**Non-interactive:** export `CLOUDFLARE_API_TOKEN`, or `--set token=-` with the token on stdin (`--set token` wins). A token piped without `--set token=-` is ignored.

```sh
polyctl auth login cloudflare
polyctl auth login cloudflare --set method=oauth
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile acme --set account_id=<id>                    # the default account, when the token sees several
CLOUDFLARE_API_TOKEN=... polyctl auth login cloudflare --profile acme --set account_id=<id> --set disabled_accounts=<id>,<id>   # and accounts kept out of every sync
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
| `sso` (default) | IAM Identity Center device-code login. Asks for `start_url`, `sso_region`, `account_id`, `role_name` when not given, opens the verification URL and waits for approval. Role credentials are exchanged again before they expire, also during a long wait in one command (the access token is refreshed with the refresh token when it has expired); when the SSO session itself expires (after 8 hours by default; IAM Identity Center sets the duration, see the [FAQ](faq.md#aws-why-does-the-iam-identity-center-login-expire-and-how-long-does-it-last)), log in again. |
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

Keys: `method`, `project`, `disabled_projects`, `key_file`, `client_id`, `client_secret`, and `projects` (deprecated, no longer used).

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

- It is the OAuth client of the Google Cloud SDK's application-default login, so the consent screen names **Google Auth Library** and asks for access to your Google Cloud data and your e-mail address. gcloud itself is not needed. The screen lets you grant each permission separately: tick both, as a login without the Google Cloud permission is refused (exit code 3) and adds no account. Should Google stop accepting it, `method=adc`, `method=service_account` and `method=oauth` with your own client remain available.
- Its id and secret are part of the program (Google does not treat the secret of a desktop client as confidential) and are never stored: the account records `oauth_client: builtin` in `config.yaml` and its refresh token in the credential store, and takes the client from the polyctl binary in use.
- A polyctl build without a built-in client behaves as follows instead: on a terminal, `adc` when Application Default Credentials exist, else polyctl asks which way to log in (a service account key file, your own OAuth client, or instructions for creating the credentials with gcloud; the last one adds no account and exits with code 0). `method=oauth` then needs `client_id` and `client_secret`, and an account of the built-in client cannot be used (exit code 3) until you log in again.

Projects. One account works on every project its credentials see ([Enabled, disabled and default](#enabled-disabled-and-default)). A login chooses the default project only, where new resources are created. See [GCP: Projects](platforms/gcp.md#projects).

- `project=<id>` sets the default project without a question.
- On a terminal, without it: a re-login keeps the default project it had (said on stderr), unless the credentials list projects and it is not among them; then, and at a first login, the only visible project is used, several are offered in a list (the project of the Application Default Credentials proposed), and when the projects cannot be listed the id of one project is asked. No list is ticked at a login. A service account login asks nothing: its default project is the previous login's, else the key's `project_id`, and it is asked only when the key names none.
- `disabled_projects=<id>,<id>,...` sets the disabled projects; given empty, none is disabled. Without it a re-login keeps the stored list (without the new default). Naming the default project is a usage error.
- `projects=<id>,<id>,...`, which chose the projects of an account in 0.4.0, is accepted and no longer used: a note on stderr says so. Without `project` it still names the default project (the stored one when it is listed, else its first id), so a 0.4.0 command line keeps working.
- The default project must be reachable (exit code 3 otherwise). The other projects are not probed at a login: a sync skips the ones that hold nothing ([GCP: Projects](platforms/gcp.md#projects)).
- Stored in `config.yaml` as `project` (the default) and `disabled_projects` (comma-separated; absent when none is disabled).
- When the credentials list more than one enabled project the login says how many and names `polyctl gcp project enable`, which chooses the ones that stay enabled. `polyctl gcp project use`, `enable` and `disable` change the default and the disabled projects without a new login.
- A login that disables more projects drops what the inventory cached of them (stored instance passwords stay); one that changes the default or enables projects again makes the cached inventory of the account due: the next online command that reads a set syncs it, and the commands that route by domain sync the zone set before their lookup ([routing rule 5](commands.md#routing-rules)).

**Non-interactive:** nothing is asked, no browser is opened, and the default method is `adc`. `service_account` needs `key_file` (and `project` if the key names none). `oauth` needs `project` (and `client_id`, `client_secret=-` for your own client, or in a build without a built-in one); it prints the consent URL and waits up to 5 minutes for the browser to return. The default project otherwise falls back to the previous login's, the ADC project, or the only visible one; several and no default is a usage error. The disabled projects of the previous login are kept.

`--no-browser` prints the consent URL instead of opening a browser; open it in a browser on the same machine, as the code returns to `127.0.0.1`.

```sh
polyctl auth login gcp --profile acme                                          # browser login
polyctl auth login gcp --profile acme --set method=adc --set project=acme-prod
polyctl auth login gcp --profile acme --set project=acme-prod --set disabled_projects=acme-lab,acme-old
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
| `cf dns update\|delete <zone> --id <id>` | `cloudflare dns update\|delete <zone> <name> [<type> [<value>]]`, or `--id <id>` (`<zone> <id>` still works) |
| `namecom dns update\|delete <domain> --id <id>` | `namecom dns update\|delete <domain> <name> [<type> [<value>]]`, or `--id <id>` (`<domain> <id>` still works) |
| `aliyun dns record update\|delete <domain> --id <id>` | `aliyun dns record update\|delete <domain> <name> [<type> [<value>]]`, or `--id <id>` (`<domain> <id>` still works) |
| `aliyun dns record add` | `aliyun dns record create` |
| `godaddy dns replace` | `godaddy dns upsert` |
| `godaddy domain available` | `godaddy domain check` |
| `aws route53domains domain list\|get` | `aws route53domains list\|get` |
| `aws ec2 list\|start\|stop` | `aws ec2 instance list\|start\|stop` |
| `gcp compute list\|start\|stop` | `gcp compute instance list\|start\|stop` |
| `aliyun ecs list\|start\|stop` | `aliyun ecs instance list\|start\|stop` |

`--id` is an optional flag on `dns delete`, `cloudflare dns update|delete`, `namecom dns update|delete`, `aliyun dns record update|delete`, `godaddy dns delete` and `gcp dns record delete`. All `whoami` commands now print `profile`, `platform`, `identity`.

**Login options:**

- Unknown `--set` keys are a usage error (0.1.x ignored them).
- Alibaba Cloud: `from_cli=` is now `aliyun_profile=`; `site=cn|intl` is required when adding an account.
- GoDaddy: `key=` / `secret=` are now `api_key=` / `api_secret=`.
- Option values have one spelling: GCP `method=adc|service_account|oauth`, GoDaddy `method=pat|api_key` and `env=production|ote`, name.com `env=production|test`. Stored accounts keep working.
