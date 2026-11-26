# Interactive and non-interactive use

How polyctl decides whether it may ask questions, what it asks on a terminal, and what scripts must pass instead.

- [Choosing the flow](#choosing-the-flow)
- [Missing input on a terminal](#missing-input-on-a-terminal)
- [Scripts, CI and stdin](#scripts-ci-and-stdin)
- [What to pass instead of answering](#what-to-pass-instead-of-answering)
  - [Browser logins without a terminal](#browser-logins-without-a-terminal)
  - [Confirmations](#confirmations)

## Choosing the flow

| Situation | Flow |
| --- | --- |
| stdin **and** stderr are terminals | interactive |
| stdin or stderr is not a terminal (pipe, redirect, `</dev/null`, CI, cron) | non-interactive |
| `--non-interactive`, or `POLYCTL_NON_INTERACTIVE` set to `1` / `true` / `yes` | non-interactive, also on a terminal |

`--non-interactive=false` keeps a terminal interactive when the environment variable is set.

- **Interactive**: missing arguments are picked from an arrow-key list, destructive actions ask for confirmation (default No), logins prompt for credentials and open a browser.
- **Non-interactive**: never shows a menu, asks, reads an answer or opens a browser. A missing input fails at once with a usage error (exit code 2) that names the argument, flag, `--set` key or environment variable to pass, before anything is written.

`--yes` / `-y` answers confirmations in both flows. On a terminal a missing argument is still asked for; `--non-interactive --yes` asks nothing at all and destructive actions proceed.

## Missing input on a terminal

- **Pick from a list.** A required argument with no default is offered as a list of candidates (from the platform, the local inventory or local files): type to filter, Enter to choose. Entries show what tells them apart (region or zone, status, fingerprint, expiry, account), and the sensible one is preselected (the current profile, the key pair holding your `~/.ssh` key, the opposite of a switch's current state).
- **Aligned columns.** The facts of an entry are columns that start at the same position in every row; `-` stands for a fact an entry does not have (a record without a TTL), and a column no entry has a value for is not shown. A terminal too narrow for the padding shows the entries unpadded.
- **Only usable candidates.** Only available or active items that fit the choices already made (region, zone, VPC, bucket). Deprecated or retired items and arm64 types or images are never listed.
- **Create a new one.** Where polyctl can create the resource, the list ends with "Create a new ..." or "Import a new ...". New names are checked as you type; key pairs get no default name.
- **Defaults are not asked.** Configured defaults (`defaults` in `config.yaml`, the profile's region or project, naming templates) and built-in defaults (disk size, instance type, image, TTL) are used silently.
- **Ambiguity is a choice.** A name matching several resources, a domain owned by several accounts, or a platform in several profiles (none current) is asked about instead of exit code 5.
- **Values that cannot be listed** (a record value, an address to find, a new hostname) are typed and checked as typed.
- **Nothing to choose.** An empty list is `nothing to do: ...` and exit code 0 for a command acting on an existing resource; for a create it is a usage error (exit code 2) naming the flag.
- **Leaving** with Esc, Ctrl-C or Ctrl-D prints `cancelled`, changes nothing and exits 0.
- `--dry-run` still asks for missing input. `--yes` answers confirmations only and never picks anything.

Commands without required input ask nothing in either flow, for example `auth list`, `auth status`, `sync`, `inventory`, `domain index`, `domain list` and every platform `list` without arguments.

## Scripts, CI and stdin

In the non-interactive flow stdin is data, not a conversation: a piped `y` confirms nothing. stdin is read only where a command says so:

- `--set key=-` on `auth login` reads that key's value, one line per such key in the order given.
- `aws rds instance create --password-stdin` reads the master password (one line).

No login reads a token from stdin on its own, so an open pipe without data never blocks. Notes and errors are plain lines on stderr; results go to stdout.

A re-authentication (`auth login` for an account the profile already has) reuses what the previous login recorded (username, start URL, account, role, project, region, method), so usually only the secret has to be passed again.

```sh
# scripts and CI: nothing is asked
printf '%s\n' "$NAMECOM_TOKEN" | polyctl auth login namecom --profile acme --set username=acme --set token=-
polyctl dns delete example.com www A --yes
polyctl aliyun ecs instance stop i-0123456789 --yes

# the same guarantees on your own terminal
polyctl --non-interactive auth use            # usage error: auth use: <profile> is required
POLYCTL_NON_INTERACTIVE=1 polyctl dns delete example.com www A
#   usage error: confirmation required: pass --yes to proceed (would delete 2 records in zone example.com)
```

## What to pass instead of answering

The usage error always names what is missing. The table covers accounts, the platform-neutral commands and the inputs that are not a simple resource argument.

### Accounts and logins

| Command | Interactive flow asks | Non-interactive flow requires |
| --- | --- | --- |
| `auth login` | the platform | `auth login <platform>` |
| `auth login <platform> --set key=-` | the value of `key` (hidden for secrets) | the value on stdin, one line per `key=-` |
| `auth login <platform>`, when only other profiles have the platform | re-authenticate one of them, add an account to the current profile, or a new profile | `--profile <name>` |
| `auth use` | the profile | `auth use <profile>` |
| `auth rename` | the profile, then the new name | `auth rename <old> <new>` |
| `auth logout [platform]` | the accounts to remove, "Remove N entries?" and "Keep cached inventory?" (`--yes` skips both questions) | `--profile <name>`; `--keep-inventory` keeps the cache |
| `auth manage` | everything, in a menu | not available: use `auth list`, `use`, `login`, `status`, `rename`, `logout --profile` |
| any platform command, several profiles hold the platform and none is current | the profile (once per run) | `--profile <name>` |
| `auth login cloudflare` | the API token; at a first login whose token sees several accounts, the default account (one list, one choice; every account the token sees is enabled, so no list is ticked) | `CLOUDFLARE_API_TOKEN` or `--set token=-`; `--set account_id=<id>` (the default account) when several accounts are visible and no login stored one; `--set disabled_accounts=<id>,<id>,...` to keep accounts out |
| `auth login cloudflare --set method=oauth` | browser approval (`--no-browser` prints the URL), up to 5 minutes, then the default account as above (`--set account_id` answers it) | not available: use `CLOUDFLARE_API_TOKEN` / `--set token=-` |
| `auth login namecom` | username and API token | `--set username=<user> --set token=-` |
| `auth login godaddy` | the Personal Access Token (or key and secret with `--set method=api_key`) | `--set token=-`, or `--set api_key=<key> --set api_secret=-` |
| `auth login aws` | the method | `--set method=sso\|keys\|profile` |
| `auth login aws --set method=keys` | access key id, secret, optional session token | `--set access_key_id=<id> --set secret_access_key=-` (`--set session_token=-`), or `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` (+ `AWS_SESSION_TOKEN`) |
| `auth login aws --set method=profile` | the profile from `~/.aws/config` / `~/.aws/credentials` | nothing: `--set aws_profile=<name>`, else the previous login's, else `default` |
| `auth login aws --set method=sso` | start URL, Identity Center region; after approval, account and role when several | `--set start_url=<url>` (`--set sso_region=`, default `us-east-1`); `--set account_id` and `--set role_name` when several are accessible |
| `auth login gcp` | browser approval with the built-in OAuth client (`--no-browser` prints the URL), then, at a first login that sees several projects, the default project (one list, one choice; every project the credentials see is enabled, so no list is ticked; a re-login keeps its default); a build without that client uses `adc` and, without Application Default Credentials, asks for the method | `adc`: Application Default Credentials must exist (exit code 3 otherwise); `--set project=<id>` unless unambiguous (previous login, ADC project, only visible project); `--set disabled_projects=<id>,<id>,...` to keep projects out (else the disabled projects of the previous login are kept) |
| `auth login gcp --set method=service_account` | the key file; the project when the key names none | `--set key_file=<path>` (`--set project=<id>` when needed) |
| `auth login gcp --set method=oauth` | browser approval, then the default project as above; client id and secret first for an OAuth client of your own | `--set project=<id>`; `--set client_id=<id> --set client_secret=-` for an OAuth client of your own (required in a build without a built-in one) |
| `auth login aliyun` | the site (`cn` / `intl`, no default), AccessKey ID and Secret, then the default region | `--set site=cn\|intl` (kept from the first login) and `--set access_key_id=<id> --set access_key_secret=-`, or `ALIBABA_CLOUD_ACCESS_KEY_ID` + `ALIBABA_CLOUD_ACCESS_KEY_SECRET`, or `--set aliyun_profile=<profile>`; region defaults to the previous login's, then `cn-hangzhou` |

### Platform-neutral commands

| Command | Interactive flow asks | Non-interactive flow requires |
| --- | --- | --- |
| any command whose name matches several owners or resources | which one | `--profile` / `--platform`, or the id (exit code 5 otherwise). When the candidates are of one login (zones of one name in several Cloudflare accounts of a login, or in several projects of a GCP account) neither flag chooses: use the platform's own command, `polyctl cloudflare ... --account <id or name>` or `polyctl gcp dns ... --project <id>`, or its zone id, as the error says |
| `dns list` / `set` / `add` / `ensure` / `delete` without `<domain>` | the zone, from the indexed zones | `<domain>` |
| `dns set` / `add` with only `<domain>` | the record type, then the value (the record is named `<domain>`) | `<name> <type> <value>` |
| `dns ensure` with only `<domain>` | nothing | `<name> <type> <value>...`, `--record` or `--file` |
| `dns delete` with only `<domain>` | the records to delete (multiple choice; SOA and apex NS not offered) | `<name> [<type> [<value>]]`, `--id` or `--all` |
| `dns delete <domain> <name>` when the name has records of several types | the records of the name to delete (multiple choice, none ticked; with their ids), after a line that names the types | `<type>` (exit code 5 otherwise, with or without `--yes`) |
| `cloudflare dns delete` with only `<zone>`, or with a `<name>` of several types | the records to delete, as `dns delete` lists them | `<name> [<type> [<value>]]` or `--id`; `<type>` for a name of several types (exit code 5 otherwise, with or without `--yes`) |
| `cloudflare dns update` with only `<zone>`, or when several records match | the one record to update; without a flag that changes something, the new value | `<name> [<type> [<value>]]` or `--id` (exit code 5 when several records match, with the candidates listed); a flag that changes something |
| `aws route53 record delete` / `gcp dns record delete` / `godaddy dns delete` with a `<name>` of several types | the record set of the name (GoDaddy: the record), after a line that names the types | `<type>` (exit code 5 otherwise, with or without `--yes`) |
| `domain info` / `which` / `ns check` / `ns get` / `ns set` without `<domain>` | the domain, from the index | `<domain>` |
| `domain ns set <domain>` without nameservers (also `namecom` / `godaddy` / `aliyun` / `aws route53domains`) | the nameservers of an indexed DNS zone of the domain, or typed | `<nameserver>...` |
| `find` without a query | the IP address or DNS name | `<ip\|dns-name>` |
| `cert ensure` / `cert get` without `<domain>` | the domain or certificate | `<domain>` |
| `cert deploy` without `<domain>` or `--all` | every due certificate, or one | `<domain>` or `--all` |
| `cert ensure` / `cert deploy`, first ACME registration | the e-mail address, then agreement to the CA's terms | `--email` (or `cert.email`) and `--agree-tos` (or `cert.agree_tos: true`) |
| every command in [Confirmations](#confirmations) | yes/no (default no) after showing what it affects | `--yes` |

### Platform commands

Platform commands follow the same rules: a missing resource argument (zone, instance, group, volume, certificate...) is picked from a list, and scripts pass the positional argument or flag the usage error names. A name several resources share is exit code 5 in scripts; pass the id. Inputs worth knowing in advance:

- **GCP resources of one name in several projects** (also zones, regions or accounts): on a terminal polyctl asks which one this call means, in a list that shows the project and the zone or region of each. Scripts get exit code 5 with the candidates listed and the flags that choose named: `--project <id>`, `--zone <zone>` (or `--region <r>` / `--global`), `--profile <name>`, whichever differ among the candidates, or the numeric id (the zone id `<project>/<managed zone>` for a managed zone). This holds for instances, load balancers and their components, firewall rules, SSL certificates, networks and managed zones. See [GCP: Projects](platforms/gcp.md#projects).
- **Cloudflare zones or R2 buckets of one name in several accounts**: on a terminal polyctl asks which one this call means, in a list that shows the account of each. Scripts get exit code 5 with the candidates listed and what chooses named: `--account <id or name>`, the zone id for a zone, and `--profile <name>` when the candidates are of different logins. See [Cloudflare: Accounts](platforms/cloudflare.md#accounts).
- **Cloudflare `zone create` / `zone ensure` on a login without a default account** (a token that could not list its accounts): the account of the new zone has to be named with `--account <id>`, or the default account set with `polyctl cloudflare account use <id>`. Without either the command fails while the credentials still cannot list accounts (exit code 3, on a terminal too). When they can by now and see several accounts, the account of the new zone is asked on a terminal, and scripts get exit code 2. Every other login creates the zone in its default account and asks nothing.
- **Cloudflare accounts.** `cloudflare account use` without an account offers the accounts the credentials see, for one choice. `cloudflare account enable` without accounts opens a list to tick: every account the credentials see, the enabled ones ticked; what is ticked on Enter is enabled and the rest is disabled. When the default account was unticked, a second question asks for the new default among the accounts that stay enabled (one left: taken without a question). Ticking nothing changes nothing (exit code 0). `cloudflare account disable` never opens the list: it takes the accounts to disable, and without one it is exit code 2 on a terminal too. Scripts pass the ids or names to either command (exit code 2 without them), and `--default <account>` when the default is disabled. See [Cloudflare: Accounts](platforms/cloudflare.md#accounts).
- **GCP projects.** `gcp project use` without a project id offers the visible projects, for one choice. `gcp project enable` without ids opens a list to tick: every project the credentials see, the enabled ones ticked; what is ticked on Enter is enabled and the rest is disabled. When the default project was unticked, a second question asks for the new default among the projects that stay enabled (one left: taken without a question). Ticking nothing changes nothing (exit code 0). `gcp project disable` never opens the list: it takes the projects to disable, and without one it is exit code 2 on a terminal too. Scripts pass the ids to either command (exit code 2 without them), and `--default <id>` when the default is disabled. See [GCP: Projects](platforms/gcp.md#projects).
- **Key pairs** (`aliyun ecs instance create` / `ensure`, `aliyun ecs key-pair ensure`, `aws ec2 key-pair ensure`, `aws ec2 instance create`) without `--ssh-key`, `--ssh-key-file`, `--key-pair` or a default (`defaults.aws.key_name`, `defaults.aliyun.ecs_key_pair`): on a terminal you pick an existing key pair or import one from `~/.ssh/*.pub`, another file or a pasted key. Scripts pass `--key-pair <existing>`, or `--ssh-key` / `--ssh-key-file` with `--key-pair` to import (exit code 5 when the key is registered under several names and `--key-pair` picks none).
- **Windows on AWS**: `aws ec2 instance create --os windows` (or a Windows `--ami`) with `--key-pair` needs `--key-file`, the RSA private key used to decrypt the password (never stored).
- **RDS password**: `aws rds instance create` takes `--password-stdin` or `--password-env <VAR>`; on a terminal without either it is typed twice (at least 8 characters).
- **Instance SSH keys** (`ssh-key list` / `add` / `remove` on AWS, GCP, Alibaba Cloud): scripts pass `<name|id>`, `--ssh-key` / `--ssh-key-file` / `--fingerprint`. On AWS and Alibaba Cloud an encrypted local key needs an SSH agent (`SSH_AUTH_SOCK`; on Windows the OpenSSH agent service is used without it), and an unknown host key needs `--accept-new-host-key`. See [instances](instances.md).
- **GCP instance create** of a Linux instance needs an SSH key (`--ssh-key`, `--ssh-key-file`, `defaults.gcp.ssh_keys`) unless the project metadata holds keys or enables OS Login; `--subnet` when the network has several ordinary subnetworks in the region.
- **Create never creates dependencies**: when a create has nothing to pick from (no VPC, subnet, vSwitch, idle EIP, target group, certificate), it is a usage error naming the flag; the `ensure` commands create what is missing.
- **Several choices typed at once** (`security-group rule add`, `alb acl entry add`): one rule or CIDR per line, an empty line ends the list.

Each platform page lists its commands and flags: [Cloudflare](platforms/cloudflare.md), [Name.com](platforms/namecom.md), [GoDaddy](platforms/godaddy.md), [AWS](platforms/aws.md), [GCP](platforms/gcp.md), [Alibaba Cloud](platforms/aliyun.md).

### Browser logins without a terminal

These logins need a person in a browser but nothing typed into polyctl, so they also work non-interactively: polyctl prints the URL, does not open a browser and waits a bounded time.

- `auth login aws --set method=sso` prints the verification URL and code and waits until the code expires (10 minutes when AWS names no lifetime). If several accounts or roles are accessible and `--set account_id` / `--set role_name` are missing, it fails listing them: pass both in scripts.
- `auth login gcp --set method=oauth` prints the consent URL and waits up to 5 minutes (on a terminal, until Ctrl-C).

`auth login cloudflare --set method=oauth` is interactive only.

### Confirmations

These commands ask one yes/no question (default no) before they delete, stop or overwrite something, after showing what is affected. `--yes` answers yes and nothing is asked, in both flows. In the non-interactive flow `--yes` is required: without it the command is a usage error (exit code 2) naming `--yes`. Declining, or leaving the question with Ctrl-C or Ctrl-D, changes nothing and is exit code 0 (`nothing to do`). A `--dry-run` asks nothing and needs no `--yes`. This is the one list of confirming commands; the other pages point here.

- Core: `dns delete` when the selector matches several records (they are listed first with their ids and the way to delete one of them only, `<value>` or `--id`, also with the refusal; a no repeats that hint), `dns delete --all` (refused before the zone is read), and `cert deploy --prune-expired` before it deletes expired certificates.
- Accounts: the interactive `auth logout` (its two confirmations) and the removal inside `auth manage`. In the non-interactive flow `auth logout` needs `--profile` instead, and `auth manage` is not available.
- AWS: `ec2 instance stop` (not asked for an instance stopped already; refused before any lookup), `ec2 instance delete` (alias `terminate`), `ec2 instance resize` of a running instance (a stopped one needs no confirmation), `ec2 security-group delete` and `rule remove`, `ec2 volume detach` (`--force` always needs `--yes`) and `delete`, `elbv2 load-balancer delete`, `target-group delete` and `listener delete`, `rds instance delete`, and `route53 record delete` (the values of the record set are listed first; `<name> <type>` is refused before anything is read, a `<name>` alone once it is known to mean one record set; a missing set is exit code 4 and asks nothing).
- GCP: `compute instance stop` (not asked for an instance stopped already; refused before any lookup), `delete` (alias `terminate`), `reboot` (a hard reset), `resize` of a running instance and `password --reset` (refused before any lookup), `compute firewall delete`, `compute ssl-certificate delete`, `compute load-balancer delete`, the `delete` of `compute backend-service`, `forwarding-rule`, `health-check` and `instance-group`, and `dns record delete` of a whole record set (its values are listed first with their ids and, for several, the way to delete one of them only; `<name> <type>` is refused before anything is read, a `<name>` alone once it is known to mean one record set; one value, `<value>` or `--id`, asks nothing).
- Alibaba Cloud: `ecs instance stop` (refused before the account is opened), `delete` (alias `terminate`), `reboot --force` (a forced stop; a plain reboot asks nothing) and `resize` of a running instance, `ecs security-group delete` and `rule remove` (nothing to remove asks nothing), `alb load-balancer delete`, `listener delete`, `server-group delete` and `acl delete`, and `cas certificate delete`.
- Instances: `ssh-key remove` of `aws ec2 instance`, `gcp compute instance` and `aliyun ecs instance` (refused before the instance is looked up; nothing to remove asks nothing).
- Cloudflare: `dns delete` when the selector matches several records (as the core `dns delete`: listed first with their ids and the way to delete one of them only, `<value>` or `--id`; one record is deleted at once), `r2 domain detach`, `zone delete`, and `cache rule set --replace` / `redirect rule set --replace` when they would delete rules.
- GoDaddy: `dns delete`, of a whole record set (`<name> [<type>]`) or of one record (`--id`, or picked from the records of the zone or of the name): the records are listed first with their ids and, for several, the way to delete one of them only (`--id`); `<name> <type>` and `--id` are refused before anything is read, a `<name>` alone once its records are known to have one type. `dns add` and `dns upsert` ask nothing.
