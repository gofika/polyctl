# Cloudflare

Commands of `polyctl cloudflare` (alias `polyctl cf`): zones and their settings, DNS records, cache, cache and redirect rules, R2 custom domains, and the Cloudflare accounts a login works on.

- [Commands](#commands)
- [Login and permissions](#login-and-permissions)
- [Accounts](#accounts)
- [Zones](#zones)
- [Zone settings](#zone-settings)
- [DNS records](#dns-records)
- [Cache and redirect rules](#cache-and-redirect-rules)
- [R2 custom domains](#r2-custom-domains)

Every command can be written with `cf` in place of `cloudflare` (`polyctl cf zone list`). Profile selection: `--profile` (must have a Cloudflare account, else exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5). One login works on every Cloudflare account its credentials see, unless an account was disabled: see [Accounts](#accounts). Inventory types: `zone`, `dns_record`, `r2_bucket`.

## Commands

```text
cloudflare whoami                 # verifies the API token (id, status, expiry) or the browser authorization (granted scopes)
cloudflare account list            # visible accounts; ENABLED says yes or no, * marks the default
cloudflare account current         # the default account and the disabled accounts (works offline)
cloudflare account use <account>   # <account> is an account id or name
cloudflare account enable [<account>...] [--default <account>] [--dry-run]   # without <account>, on a terminal: the list of enabled accounts
cloudflare account disable <account>... [--default <account>] [--dry-run]
# every command below: [--account <id|name>]
cloudflare zone list              cloudflare zone get <zone|id>
cloudflare zone create <domain> [--foundation-dns[=false]]
cloudflare zone ensure <domain> [--preset optimized] [--ssl flexible|strict] [--foundation-dns[=false]]
cloudflare zone delete <zone|id> [-y] [--downgrade-enterprise]
cloudflare zone setting list <zone|id>
cloudflare zone setting get <zone|id> <setting>
cloudflare zone setting set <zone|id> <setting> <value> [--timeout 1m]
cloudflare dns list <zone> [--type] [--name]
cloudflare dns create <zone> --type A --name www --value 203.0.113.10 [--ttl 1] [--proxied[=false]] [--priority] [--comment]
cloudflare dns update <zone> <record-id> [--type] [--name] [--value] [--ttl] [--priority] [--proxied[=false]] [--comment]
cloudflare dns delete <zone> <record-id>
cloudflare cache purge <zone> (--everything | --url <url>... | --host <h>... | --tag <t>... | --prefix <p>...)   # host/tag/prefix need Enterprise
cloudflare cache rule list <zone> [--wide]
cloudflare cache rule set  <zone> --file rules.yaml [--replace] [--first] [-y]
cloudflare redirect rule list <zone> [--wide]
cloudflare redirect rule set  <zone> --file rules.yaml [--replace] [--first] [-y]
cloudflare dev-mode <zone> [on|off]       # Development Mode (bypasses the cache for 3 hours)
cloudflare ssl-mode <zone> [off|flexible|full|strict]
cloudflare r2 bucket list [--wide] [--jurisdiction eu|fedramp]
cloudflare r2 domain list   <bucket>
cloudflare r2 domain get    <bucket> <domain>
cloudflare r2 domain attach <bucket> <domain> [--zone <zone>] [--disabled] [--min-tls 1.0|1.1|1.2|1.3]
cloudflare r2 domain update <bucket> <domain> [--enabled[=false]] [--min-tls <v>]
cloudflare r2 domain detach <bucket> <domain> [-y]
cloudflare r2 domain ensure <bucket> <domain> [--zone <zone>] [--disabled] [--min-tls <v>]
```

`whoami` prints `profile`, `platform` and `identity`; it needs the network (exit code 6 with `--offline`), and credentials that no longer work exit with code 3. List commands honour `--refresh` / `--offline`; writes always go to Cloudflare. Write commands print a change report and honour `--dry-run` (see [Dry runs and change reports](../configuration.md#dry-runs-and-change-reports)).

## Login and permissions

Log in with `polyctl auth login cloudflare` (an API token, or `--set method=oauth` for browser approval; details in [Accounts](../accounts.md)). Token permissions by command:

| Commands | Permission |
|---|---|
| everything | `Zone:Read`, `DNS:Edit` |
| `account list`; `account use` / `enable` / `disable` and `--account` to check an account or look its name up; R2 in other accounts than the default | `Account:Read` (without it `account list` fails with exit code 3, and `use` / `disable` / `--account` take an account id unchecked) |
| `whoami` showing your email | `User:Read` |
| `cache purge`, `dev-mode`, `ssl-mode`, `zone create` / `ensure` / `delete` | `Zone:Edit` (at the account level to create a zone) |
| `zone ensure`, `zone setting` | zone settings edit |
| `zone delete --downgrade-enterprise` | billing |
| `cache rule` / `redirect rule` | Cache Rules / Single Redirects (Dynamic URL Redirects) |
| `r2` | R2 read and write; `r2 domain attach` / `ensure` also DNS edit on the domain's zone |

A browser login (`method=oauth`) does not cover R2: the `r2` commands need an API token.

## Accounts

One Cloudflare login of a profile works on **every account its credentials see**, the ones they reach later included. An account is **enabled** unless you disabled it; one of the enabled accounts is the **default account**. The model is the same for GCP projects and is explained once in [Accounts: Enabled, disabled and default](../accounts.md#enabled-disabled-and-default).

| | Covers |
| --- | --- |
| Inventory sync (`polyctl sync`, automatic refreshes), `find`, `inventory list` | every enabled account |
| Looking a zone up by name or id (`zone get`, `dns`, `cache`, `redirect`, `dev-mode`, `ssl-mode`, `zone setting`, `zone delete`) | every enabled account |
| Domain routing of the platform-neutral `dns`, `domain` and `cert` commands (DNS-01 validation included) | every enabled account |
| `zone list`, `r2 bucket list` | every enabled account; an `ACCOUNT` column appears when the rows are of several |
| Finding the account of an R2 bucket (`r2 domain ...`) | every enabled account, of every Cloudflare profile unless `--profile` is given |
| Creating a zone (`zone create`, `zone ensure` of a zone that does not exist) | the default account |

```sh
polyctl cf account list                       # visible accounts; ENABLED says yes or no, * marks the default
polyctl cf account current                    # the default account and the disabled accounts (works offline)
polyctl cf account use "Acme Ltd"             # make it the default (enables it if it was disabled)
polyctl cf account enable                     # on a terminal: one list of every account, the enabled ones ticked
polyctl cf account enable "Acme Lab"          # take one back
polyctl cf account disable "Acme Lab" fedcba9876543210fedcba9876543210   # keep accounts that are not used out of every sync
polyctl cf account disable "Acme Ltd" --default "Acme Lab"   # disabling the default names its successor
polyctl cf account disable "Acme Lab" --dry-run -o json      # report only
polyctl cf zone list --account "Acme Lab"     # one account for this call
```

- **Enabled** is everything the credentials see minus what you disabled. Nothing has to be enabled: an account the credentials reach later is covered by the next sync of each set. **Disable** the accounts that are certainly not used.
- The **default account** is only what a command works on when nothing names an account, and where new zones go. It is always enabled.
- Only the disabled accounts are stored (`disabled_accounts` in `config.yaml`, next to `account_id` and `account_name`); `use`, `enable` and `disable` change them without a new login.
- An account is named by its id or its name (case-insensitive), in the `account` commands, in `--default` and in `--account`. A name two visible accounts carry is exit code 5: pass the id. `--account` takes an account the profile already knows (the default account by id or name, a disabled account by id, an account with a cached zone or R2 bucket) without asking the credentials; any other name is looked up among the visible accounts.
- `account list` needs the network and the permission to list accounts. Columns: `NAME` (the default marked ` *`), `TYPE`, `ID`, `ENABLED` (`yes` / `no`); stderr says `<n> account(s) via cloudflare/<profile>, <e> enabled, <d> disabled`. JSON is `{"profile", "accounts": [{"id", "name", "type", "enabled", "default"}]}`. The default account and the disabled accounts the credentials do not list are shown without a type, a disabled one with a note naming `polyctl cloudflare account enable <id>`, which forgets it.
- `account current` reads the local configuration only (works with `--offline`): `{"profile", "account_id", "account_name", "disabled_accounts", "method", "email"}`; `disabled_accounts` is always a list. A login without a default account shows `(none: every account the credentials see)`. The enabled accounts are not stored: read them with `polyctl cloudflare account list -o json`.
- `use <account>` sets the default account and checks that the credentials see it (exit code 4 otherwise). Nothing is checked, with a note, with `--offline` or when the credentials cannot list their accounts; a name can then only be one the profile already knows. A disabled account that becomes the default is enabled again, and only then are the cached sets of the login made due, as by `enable`. Nothing else changes: the login keeps working on every account it sees, also a login that had no default account before. On a terminal, without an argument, the visible accounts are offered. `use` does not support `--dry-run` (exit code 2).
- `disable <account>...` changes nothing at Cloudflare and keeps the credentials. It drops what the inventory cached of the accounts at once: their zones, the DNS records of those zones, their R2 buckets and their domains in the index; nothing is synced again because of it. An account that is disabled already is left as it is (exit code 0); one the credentials do not see is exit code 4. With `--offline`, or with credentials that cannot list their accounts, an id is taken as it is, with a note.
- Disabling the default account needs a new default: `--default <account>`, naming an account that stays enabled (exit code 2 without it in the non-interactive flow; on a terminal it is asked, and the only account that stays becomes the default without a question). `--default` is applied whenever the call disables an account, also when the default is not one of them; when every account named is disabled already, nothing is written (exit code 0) and a note says that `--default` was not applied (`use` sets the default). Disabling every account is exit code 2 (use `polyctl auth logout cloudflare`); it can only be told when the credentials list all their accounts. A login without a default account can disable accounts by id, and nothing needs a new default there.
- `enable <account>...` takes disabled accounts back and makes the cached sets of the login due: each set is synced by the next online command that reads it, and the commands that route by domain (`polyctl dns`, `polyctl domain` other than `domain list`, which prints the index as it stands, and the DNS-01 challenge of `polyctl cert`) sync the zone set before they look a domain up, once ([routing rule 5](../commands.md#routing-rules)). An account that is enabled already is exit code 0 (nothing to do); one that is neither disabled nor visible is exit code 4 (name it with `--account`, or make it the default with `use`). When the credentials cannot list their accounts, nothing tells that they do not see an id: it counts as enabled already (exit code 0). A disabled account that is no longer visible is simply forgotten. Works with `--offline` for accounts named by id. With `--offline` nothing tells either whether the credentials see an account that is not disabled: it counts as enabled already, and a note says it was not checked.
- **`enable` manages which accounts are enabled. Without arguments, on a terminal, it opens the list**: every account the credentials see, the enabled ones ticked. What is ticked when you confirm is enabled, the rest is disabled; a default that was unticked is replaced by `--default <account>`, or by the answer to a question (the only account that stays is taken without one). Ticking nothing changes nothing (exit code 0). The list needs the network (`--offline`: exit code 6). Credentials that cannot list their accounts are offered the accounts read off their zones, which leaves out an account without a zone; credentials that see no zone either have nothing to offer (exit code 2: pass the ids). In the non-interactive flow the accounts are required (exit code 2).
- `disable` never opens the list: it is the shortcut that disables the accounts named, for scripts, and without an account it is exit code 2 on a terminal too, with a message that names `polyctl cloudflare account enable`.
- `enable` and `disable` support `--dry-run`: the change report names `account/<id>` with `disabled`, `enabled` or `default`, and nothing is written, dropped or made due. No confirmation is asked by any of them: only `config.yaml` and a cache the next sync rebuilds change.
- `polyctl cloudflare account add` and `remove` are hidden names of `enable` and `disable`, with the same flags and arguments (no release had them as visible commands).
- Whatever changed the disabled accounts (also an edited `config.yaml`, or `--set disabled_accounts` of a new login), the `cloudflare` commands never find or change a zone or bucket through a cached row of a disabled account; `--account` still reaches it. A default account listed in `disabled_accounts` by hand is ignored there.

**What a sync reads.**

- Zones: **one** listing of every zone the credentials see, whatever the number of accounts; the zones of disabled accounts are left out of the result. Those zones are still paged through (50 per page): what disabling an account saves is the record sync of each of its zones, its R2 listing and every lookup in it. The record sync of the same run reuses the zone listing. A zone name is looked up with one request, and the same answer tells when the zone is in a disabled account.
- When the zone listing fails, the zone sync fails and replaces nothing (the cached rows stay). An account that refuses zone listing simply shows no zones.
- Records: a zone that answers 403 or 404 is skipped with a warning. Any other failure makes the account of that zone a failed account when the zones are of several accounts: the other accounts are synced, the rows cached for the failing one are kept, a warning names `polyctl cloudflare account disable <id> --profile <name>`, and the set is synced again on its next use. When every enabled account fails, the sync fails.
- R2 buckets are read per account, from the enabled accounts the credentials list (one request for the list). An account that cannot be used for R2 holds no buckets; one note per run names all of them, and since such an account may still hold zones, it does not suggest disabling it:

```text
note: cloudflare/acme: R2 is not usable in 2 account(s): fedcba9876543210fedcba9876543210 (R2 is not enabled), 00112233445566778899aabbccddeeff (no R2 permission)
```

**`--account <id or name>`** on the `zone`, `dns`, `cache`, `redirect`, `dev-mode`, `ssl-mode` and `r2` commands names the account of that one call:

- Lookups and lists read only that account; a new zone goes to it instead of the default account.
- The account need not be enabled: a disabled account is read live and nothing of it is written to the inventory (so `--offline` cannot serve it: exit code 6). Without the flag, a zone of a disabled account is not found (exit code 4; the error names the account, `account enable` and `--account`).
- A zone id given with the `--account` of another account is exit code 2, and nothing is written.
- An account the credentials do not see is exit code 4 when they can list their accounts. With `--offline`, a name or id the profile does not know cannot be looked up (exit code 6). `cloudflare account ...`, `whoami` and the platform-neutral commands do not take the flag.

**The same name in several accounts.** Cloudflare lets a second account add a zone for a domain another account holds (it stays `pending`), and the name of an R2 bucket is unique in its account only.

- On a terminal polyctl asks which one this call means; the list shows the account of each candidate.
- In the non-interactive flow the command fails with exit code 5. The error lists every candidate (a zone as `cloudflare/<profile> account <id> (<name>) zone <zone id> <status>`, a bucket as `cloudflare/<profile> account <id>`) and names what chooses: `--account <id or name>`, the zone id for a zone, and `--profile <name>` when the candidates are of different logins.
- The platform-neutral commands (`dns`, `domain`, `cert`) route by domain: a domain that two enabled accounts of one login hold a zone of is ambiguous there too. The candidates name the account and the status of each zone, as above, and the error points to the `polyctl cloudflare` commands, which take `--account <id or name>` or the zone id (the platform-neutral commands take neither).
- `zone ensure` reuses a zone in whichever enabled account holds it; `zone create` fails naming that account.
- With every visible account enabled, one name in two accounts is met more often than before. Disabling the account that is not used removes its candidate.

**Ids.** Zone ids and DNS record ids are Cloudflare's own and unique across accounts; a zone row of the inventory carries its account as parent. An `r2_bucket` row has the id `<account id>/<bucket>`.

**Kinds of credentials.**

- An account-owned API token belongs to one account and sees only it: that account is the default of its login, and there is nothing to disable.
- A user token without `Account:Read` cannot list accounts. Its zones are still those of every account it sees, minus the disabled ones; R2 works on the default account alone (another account with `--account`). Its login takes `--set account_id` as given; without it the login has no default account (for a new zone see [Zones](#zones)), and `account use <id>` names one later. `account list` is not available to it. The other `account` commands read its accounts off its zones, as for a browser login without the scope (next item): the list of `enable` offers them, a name is the name of one of them, and an id that list does not show is taken as given, with a note. A token that sees no zone either has no such list: the list of `enable` is exit code 2 and an account is named by its id.
- A browser login (`method=oauth`) without the `account-settings.read` scope reads the accounts off its zones, so an account without a zone is not listed. That list is offered by the `account` commands, but it is not complete: an id it does not show is accepted with a note.

**Upgrading.** A login made by an earlier polyctl was bound to one account and worked on that account alone (a login without an account worked on everything it saw). Now every account the credentials see is enabled: after the upgrade such a login covers more than before, without a new login, and its account is the default. The first run of this version makes the cached Cloudflare sets due once (their rows are kept). A set that is due is synced by the next online command that reads it (the lists and lookups of `polyctl cloudflare ...`, `sync`), and the platform-neutral commands that route by domain (`polyctl dns`, `polyctl domain` other than `domain list`, which prints the index as it stands, and the DNS-01 challenge of `polyctl cert`) sync the zone set before they look the domain up, once ([routing rule 5](../commands.md#routing-rules)): a zone in an account that was not covered before is found without `--refresh`. With `--offline` nothing is synced and the old rows are served. R2 bucket rows get their id `<account id>/<bucket>` when their set is synced. A token that sees a zone of the same name in a second account now gets exit code 5 for that name until one of the accounts is disabled or `--account` chooses. `config.yaml` is read as before.

## Zones

```sh
polyctl cf zone create example.com --profile acme
polyctl cf zone ensure example.com --preset optimized --ssl flexible
polyctl cf zone ensure example.com --preset optimized --dry-run -o json
polyctl cf zone delete example.com --yes
```

A zone command covers every enabled account of the login, or the one of `--account`; a new zone goes to `--account`, else to the default account. A zone name that two accounts in the scope of the call hold a zone of is asked about on a terminal and exit code 5 otherwise (see [Accounts](#accounts)). `zone list` shows an `ACCOUNT` column when its zones are of several accounts.

A login without a default account (its credentials could not list accounts) needs `--account <id>` for a new zone, or `account use <id>` before: while the credentials cannot list accounts the command fails without it (exit code 3). When they can by now, the only account they see is used; when they see several, the account is asked for on a terminal and it is a usage error otherwise (pass `--account`). The zone lifecycle commands read the platform, so `--offline` is refused (exit code 6).

**`zone create <domain>`** adds a full zone to the account of `--account`, else to the default account.

- `<domain>` is a registered domain such as `example.com`. Something plainly not a domain (no dot, a URL, an IP address, spaces) is a usage error (exit code 2).
- The new zone stays `pending` until you set its nameservers at the registrar; polyctl does not wait and never changes the registrar itself. The nameservers are printed under `Nameservers (set these at your registrar):`, with the matching `polyctl domain ns set` command on stderr.
- Foundation DNS is switched on by default (`--foundation-dns=false` skips it). An account that cannot use it is reported `skipped`; any other refusal fails the command (the zone stays created).
- A zone that already exists is exit code 1 (use `ensure`). Without `--account` it is looked for in every enabled account and the error names the account that holds it; with `--account` in that account alone. A zone Cloudflare refuses because an account the login does not cover (a disabled one, or one its credentials do not see) holds the domain (code 1061, `already exists`) is exit code 1 as well: pass `--account` or `--profile` for that account.
- A zone created with `--account` in a disabled account is not stored in the inventory (a note names `polyctl cloudflare account enable`).

**`zone ensure <domain>`** reuses the zone (`unchanged`) or creates it as `create` does. Without `--account` the zone is looked for in every enabled account and reused in the one that holds it (`target.account_id` of the report names it); zones of the name in two of them are asked about on a terminal and exit code 5 otherwise. With `--account` only that account is looked in. Then:

- `--preset optimized` converges, reading first and writing only what differs, in this order: `0rtt` on, `early_hints` on, `rum` on; on Enterprise zones only, `response_buffering` on, `ipv6` off and Argo Smart Routing on (elsewhere `skipped`, since Argo is billed); `always_use_https` on, `automatic_https_rewrites` on; last `ssl`.
- `ssl` is `--ssl` (`flexible` or `strict`), else `defaults.cloudflare.ssl`, else `strict`. `strict` replaces `flexible` (`flexible -> strict`), so pass `--ssl flexible` for an origin without HTTPS. `off` and `full` are set with `cloudflare ssl-mode`. `--ssl` without `--preset` sets the SSL mode only.
- A setting the plan cannot change is `skipped`.
- `--foundation-dns` applies to a new zone by default; an existing zone is switched on only when the flag is given explicitly, and never switched off.
- It does not wait (no `--wait`); a new zone stays `pending`. A failure stops where it is without undoing anything; running it again continues.
- Report rows: `zone/<domain>`, `zone/<domain>/foundation-dns`, `zone/<domain>/setting/<id>` (`from -> to`; JSON `attrs.from` / `attrs.to`). JSON: `{"target": {"platform", "profile", "account_id"}, "dry_run", "zone": {"id", "name", "status", "plan", "name_servers", "original_name_servers"}, "changes"}`.
- `--dry-run` for a zone that does not exist yet shows its id and current values as `(pending)` and the Enterprise-only settings as `skipped` (`plan unknown until created`).
- A failure is sent to `hooks.on_failure` as `cloudflare.zone.ensure.failed` (`cloudflare.zone.create.failed` for `create`); see [Configuration](../configuration.md).

**`zone delete <zone>`** deletes a zone (name or id) with all of its DNS records.

- It asks for confirmation, showing the plan, status and number of DNS records (`--yes` in the non-interactive flow; see [Confirmations](../interactive.md#confirmations)). A name found in several accounts is asked about on a terminal and exit code 5 in the non-interactive flow: pass `--account`, `--profile` or the zone id.
- An Enterprise zone must be moved to the Free plan first. polyctl does that only with `--downgrade-enterprise` (changes billing); otherwise it stops with exit code 1. A token without billing permission is exit code 3 and nothing is deleted. If the downgrade succeeds and the deletion fails, the zone stays on Free: run the command again.
- `--dry-run` reports `zone/<domain>  would delete  plan=free records=12` (plus `zone/<domain>/subscription  would update  enterprise -> free`).

A zone the inventory remembers but Cloudflare no longer has is dropped from the inventory and looked up again by name (not found: exit code 4). A zone the inventory does not know triggers one sync of the Cloudflare accounts, and a zone name is looked up only after the zone sets that are due were synced (their TTL passed, or the disabled accounts of the login changed), so that a zone of that name in an account that was enabled again is seen.

## Zone settings

```sh
polyctl cf zone setting list example.com
polyctl cf zone setting get example.com min_tls_version
polyctl cf zone setting set example.com always_use_https on
polyctl cf zone setting set example.com argo_smart_routing on
```

- `list` columns: `SETTING`, `VALUE`, `EDITABLE`, `MODIFIED_ON` (JSON `[{"id", "value", "editable", "modified_on", "zone"}]`). `rum`, `argo_smart_routing` and `foundation_dns` are not listed; read them with `get`.
- Settings are named by their Cloudflare id (`ssl`, `always_use_https`, `0rtt`, `min_tls_version`, ...), plus `argo_smart_routing` (on / off) and `foundation_dns` (true / false).
- `set` reads first and reports `unchanged` without writing, else `updated  from -> to`. Booleans take `on` / `off` (`true` / `false` are written as on / off); other values are sent as given (number or JSON object when the setting holds one).
- An unknown setting is exit code 4; one the plan cannot change is exit code 7; an invalid value is exit code 1 with the API's message.
- Setting `foundation_dns` changes the zone's nameservers: `set` waits up to `--timeout` (default `1m`) for the new ones and prints them with the `polyctl domain ns set` command to run.

## DNS records

```sh
polyctl cf dns create example.com --type A --name www --value 203.0.113.10 --proxied
polyctl cf dns update example.com <record-id> --proxied=false
```

- Records are addressed by their Cloudflare record id, an argument of `update` and `delete`.
- `--name` is relative to the zone (`www`, `@`) or an FQDN; default the zone apex.
- `--ttl` in seconds; `0` or `1` means automatic.
- `--proxied` is the orange cloud: `--proxied` on, `--proxied=false` off. Without it, `create` uses Cloudflare's default and `update` keeps the current setting.
- `--priority` for MX/SRV/URI records; `--comment` sets a comment (`update --comment ""` clears it).

`dev-mode` and `ssl-mode` without a value show the current state.

## Cache and redirect rules

`cache rule` manages Cache Rules (phase `http_request_cache_settings`), `redirect rule` manages Single Redirects (phase `http_request_dynamic_redirect`). Cloudflare replaces the whole rule list of a phase on every write, so polyctl always reads before it writes. Rules are not cached in the inventory: `--offline` is refused (exit code 6).

```sh
polyctl cf cache rule list example.com -o yaml > rules.yaml   # edit, then:
polyctl cf cache rule set example.com --file rules.yaml --dry-run
polyctl cf cache rule set example.com --file rules.yaml
polyctl cf cache rule set example.com --file rules.yaml --replace -y
```

**`rule list <zone>`** shows the rules in execution order: `#`, `ENABLED`, `DESCRIPTION`, `EXPRESSION`, plus `CACHE`, `EDGE_TTL`, `BROWSER_TTL` (cache rules) or `STATUS`, `TARGET`, `KEEP_QUERY` (redirect rules). Expressions are cut at 40 characters; `--wide` prints them whole and adds `STATUS_TTL` and `REF`. The `-o yaml` / `-o json` output (`{"zone", "phase", "ruleset_id", "rules"}`) is a valid `--file` for `set`.

**`rule set <zone> --file <file>`** writes the rules of a YAML or JSON file (`-` reads stdin):

```yaml
rules:
  - description: cache static assets     # required, unique in the file; identifies the rule
    action: set_cache_settings           # required: set_cache_settings (cache) or redirect (redirect)
    expression: (http.request.uri.path.extension in {"css" "js"})   # required
    enabled: true                        # default true
    action_parameters:                   # passed to the API as written
      cache: true
      edge_ttl: {mode: override_origin, default: 2678400}
    # ref: optional
```

- A bare list is accepted too. Only these keys are allowed; any other key, a missing field, a duplicate description, a wrong action or an unreadable file is a usage error (exit code 2) before anything is sent.
- **Merge (default):** a rule whose description matches an existing one replaces it in place; new rules are appended (`--first` puts them first, in file order; the order is the execution order, so mind a catch-all rule). Existing rules the file does not name are kept, so nothing is deleted. If several existing rules share a description, the first is replaced and a warning is printed. A rule without `ref` keeps the `ref` of the rule it replaces.
- **`--replace`:** the file becomes the whole list; rules it does not name are deleted. This asks for confirmation (default no) after listing them, and needs `--yes` in the non-interactive flow. A declined confirmation writes nothing (exit code 0). `--first` and `--replace` cannot be combined.
- When the result equals what exists (order included), nothing is written and every rule is `unchanged`. Otherwise the whole list is written in one request that succeeds or fails as a whole.
- There is no lock: run one `set` per zone and phase at a time.
- Report rows per rule: `zone/<zone>/cache-rule/<description>` (or `redirect-rule/...`) with `unchanged`, `created` (`position 2`), `updated` (`edge_ttl.default 3600 -> 2678400`, `expression`, `enabled true -> false`, `position 3 -> 1`) or `deleted`; a last row `zone/<zone>/cache-rules  updated  PUT entrypoint (4 rules)` stands for the write.

Errors: a missing zone is exit code 4 (and leaves the inventory); a token without the phase's Rulesets permission is exit code 3; more rules than the plan allows is exit code 7 (Free: 10 cache rules); an invalid expression or parameter is exit code 1 with the API's message.

## R2 custom domains

`cloudflare r2` manages the custom domains of R2 buckets. Objects, and creating or deleting buckets, are not covered.

```sh
polyctl cf r2 bucket list --wide
polyctl cf r2 domain attach assets cdn.example.com --min-tls 1.2
polyctl cf r2 domain ensure assets cdn.example.com
polyctl cf r2 domain detach assets cdn.example.com --yes
```

**Accounts and inventory**

- The R2 commands cover every enabled account of every Cloudflare profile. `--profile` narrows them to the enabled accounts of that profile, and `--account <id or name>` to one account; a disabled account is read live with `--account` and nothing of it is cached. The same account in two profiles counts once. Messages name the account next to the profile (`account <id> of cloudflare/<profile>`) when it is not the default account of the login, or when the command reads several accounts of the profile.
- The enabled accounts are the ones the credentials list (one request per command that reads R2 live or syncs it), minus the disabled ones. Credentials that cannot list their accounts work on the default account alone for R2; a login that has no default account either fails then (pass `--account <id>`, or name the default with `polyctl cloudflare account use <id>`).
- An account without R2 is exit code 7 when it is the only one asked; among several it is skipped, and one note per run names the accounts in which R2 is not usable (the listing of a profile fails only when none of its accounts can be used for R2).
- `bucket list` without `--profile` lists the buckets of every Cloudflare profile; accounts without R2 are skipped, a failing profile is a warning, and the command fails only when no account could be read. A profile that lists the buckets of several accounts adds an `ACCOUNT` column.
- Buckets of the default jurisdiction are cached as `r2_bucket`, one row per account and bucket (id `<account id>/<bucket>`; fresh for an hour; `polyctl sync --type r2_bucket` fills it). `--offline` lists only the inventory; `--wide`, `--jurisdiction` and the `--account` of a disabled account read live (exit code 6 with `--offline`).
- The `r2 domain` commands find the account that holds `<bucket>`. One account to look in (`--account`, or `--profile` with a login of one account) is used as it is. Otherwise the inventory answers when it names exactly one account for the bucket; failing that (and with `--refresh` or `--jurisdiction`) every account is asked live. A bucket found nowhere is exit code 4. The name of a bucket is unique in its account only: a name held by several accounts is asked about on a terminal and exit code 5 otherwise, listing each as `cloudflare/<profile> account <id>`; pass `--account`, or `--profile` when the accounts are of different profiles. Without `<bucket>` a terminal offers the buckets, each with its account when a profile has several.
- `--jurisdiction eu|fedramp` addresses that R2 jurisdiction instead of the default one.

**Commands**

- `bucket list`: profile, account (when a profile lists several), name, creation date; `--wide` adds location, storage class and jurisdiction (one request per bucket). stderr says `<n> bucket(s) in <m> account(s)`, the accounts being the ones that were read, also those without a bucket; a listing the local inventory answered says `<n> bucket(s) (local inventory)`, as the inventory holds the buckets and not the accounts.
- `domain list` / `get`: enabled state, zone, minimum TLS (`-` when never set), ownership and SSL status (`pending` / `initializing` right after binding is normal). A domain not bound to the bucket is exit code 4.
- `domain attach`: binds `<domain>` (no wildcards). The zone is `--zone` (name or id) or the longest zone name the domain ends in, within the bucket's account; it must be active. Cloudflare creates the proxied CNAME `<domain> -> public.r2.dev`. A domain already bound (to any bucket), or an existing A, AAAA or CNAME record of that name, is exit code 1 (a TXT record is fine). `--disabled` binds it disabled; `--min-tls` sets the minimum TLS version (not set by default).
- `domain update`: changes `--enabled` / `--enabled=false` and/or `--min-tls` (at least one).
- `domain detach`: unbinds the domain and Cloudflare deletes its CNAME. Asks for confirmation (default no); needs `--yes` in the non-interactive flow.
- `domain ensure`: idempotent; a binding with the wanted enabled state (and `--min-tls`, when given) is `unchanged`, a differing one is updated, a missing one is attached. A binding in another zone than `--zone` is an error and is never unbound automatically.
- `update`, `detach` and `ensure` read the domain first; a domain that is not bound is exit code 4.
