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

Every command can be written with `cf` in place of `cloudflare` (`polyctl cf zone list`). Profile selection: `--profile` (must have a Cloudflare account, else exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5). One login works on several Cloudflare accounts, the ones selected for it: see [Accounts](#accounts). Inventory types: `zone`, `dns_record`, `r2_bucket`.

## Commands

```text
cloudflare whoami                 # verifies the API token (id, status, expiry) or the browser authorization (granted scopes)
cloudflare account list            # visible accounts; SELECTED marks the selection, * the default
cloudflare account current         # the default account and the selection (works offline)
cloudflare account use <account>   # <account> is an account id or name
cloudflare account add <account>...
cloudflare account remove <account>... [--default <account>]
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
| `account list`; `account use` / `add` and `--account` to check an account or look its name up | `Account:Read` (without it `account list` fails with exit code 3, and `use` / `add` / `--account` take an account id unchecked) |
| `whoami` showing your email | `User:Read` |
| `cache purge`, `dev-mode`, `ssl-mode`, `zone create` / `ensure` / `delete` | `Zone:Edit` (at the account level to create a zone) |
| `zone ensure`, `zone setting` | zone settings edit |
| `zone delete --downgrade-enterprise` | billing |
| `cache rule` / `redirect rule` | Cache Rules / Single Redirects (Dynamic URL Redirects) |
| `r2` | R2 read and write; `r2 domain attach` / `ensure` also DNS edit on the domain's zone |

A browser login (`method=oauth`) does not cover R2: the `r2` commands need an API token.

## Accounts

One Cloudflare login of a profile works on the accounts **selected** for it. One of them is the **default account**.

| | Covers |
| --- | --- |
| Inventory sync (`polyctl sync`, automatic refreshes), `find`, `inventory list` | every selected account |
| Looking a zone up by name or id (`zone get`, `dns`, `cache`, `redirect`, `dev-mode`, `ssl-mode`, `zone setting`, `zone delete`) | every selected account |
| Domain routing of the platform-neutral `dns`, `domain` and `cert` commands (DNS-01 validation included) | every selected account |
| `zone list`, `r2 bucket list` | every selected account; an `ACCOUNT` column appears when the rows are of several |
| Finding the account of an R2 bucket (`r2 domain ...`) | every selected account, of every Cloudflare profile unless `--profile` is given |
| Creating a zone (`zone create`, `zone ensure` of a zone that does not exist) | the default account |

```sh
polyctl cf account list                       # visible accounts; SELECTED marks the selection, * the default
polyctl cf account current                    # the default account and the selection
polyctl cf account use "Acme Ltd"             # make it the default (selects it if needed)
polyctl cf account add 0123456789abcdef0123456789abcdef "Acme Lab"   # select more accounts
polyctl cf account remove "Acme Lab"          # take an account out of the selection
polyctl cf account remove "Acme Ltd" --default "Acme Lab"   # removing the default names its successor
polyctl cf zone list --account "Acme Lab"     # one account for this call
```

- The login selects the accounts (see [Accounts: Cloudflare](../accounts.md#cloudflare)); `use`, `add` and `remove` change the selection without a new login. A login stored with one account (every login made before the selection existed) has exactly that account selected and works as before.
- An account is named by its id or its name (case-insensitive), in the `account` commands, in `--default` and in `--account`. Two visible accounts of one name are exit code 5: pass the id.
- `account list` needs the network and the permission to list accounts. It marks the selected accounts (`SELECTED`) and the default one (`*` after its name); JSON is `{"profile", "accounts": [{"id", "name", "type", "selected", "default"}]}`. A selected account the credentials do not list is shown without a type, with a note.
- `account current` reads the local configuration only (works with `--offline`): `{"profile", "account_id", "account_name", "accounts", "method", "email"}`.
- `use` and `add` check that the credentials see the account (exit code 4 otherwise). Nothing is checked, with a note, with `--offline` or when the credentials cannot list their accounts; a name can then only be one the profile already knows. On a terminal, without an argument `use` offers the visible accounts and `add` those not selected yet (tick several). `add` of accounts that are all selected already is exit code 0 (nothing to do). The first account given to a login without an account becomes its default.
- `remove` changes nothing at Cloudflare and keeps the credentials. It works with `--offline`. An account that is not selected is exit code 4. Removing the default account needs `--default <account>`, naming an account that stays selected (exit code 2 without it; on a terminal it is asked, and the only account that stays becomes the default without a question); removing every account is exit code 2 (use `polyctl auth logout cloudflare`). No confirmation is asked.
- `use`, `add` and `remove` change `config.yaml` only and do not support `--dry-run` (exit code 2).
- **Deselecting drops the cache.** An account that leaves the selection, by `account remove` or by a new login, loses what the inventory cached of it at once: its zones, their DNS records, its R2 buckets and its domains in the index. The cached sets of the login are synced again on their next use. Whatever changed the selection (also an edited `config.yaml`), the `cloudflare` commands never find or change a zone or bucket through a cached row of an account that is no longer selected; `--account` still reaches it.
- **A failing account keeps its rows.** When a sync cannot read one of several selected accounts, the others are synced, the rows cached for the failing account (its zones with their records, its buckets) are kept, a warning names `polyctl cloudflare account remove <id>`, and the set is synced again on its next use. When every selected account fails, the sync fails. An account without R2 counts as holding no buckets. An account the credentials no longer see usually lists no zones, so its rows simply go with the next sync.

**`--account <id or name>`** on the `zone`, `dns`, `cache`, `redirect`, `dev-mode`, `ssl-mode` and `r2` commands names the account of that one call:

- Lookups and lists read only that account; a new zone goes to it instead of the default account.
- The account need not be selected: an account outside the selection is read live and nothing of it is written to the inventory (so `--offline` cannot serve it: exit code 6). Without the flag, a zone of an unselected account is not found (exit code 4; the error names the account, `account add` and `--account`).
- A zone id given with the `--account` of another account is exit code 2, and nothing is written.
- An account the credentials do not see is exit code 4 when they can list their accounts. `cloudflare account ...`, `whoami` and the platform-neutral commands do not take the flag.

**The same name in several accounts.** Cloudflare lets a second account add a zone for a domain another account holds (it stays `pending`), and the name of an R2 bucket is unique in its account only.

- On a terminal polyctl asks which one this call means; the list shows the account of each candidate.
- In the non-interactive flow the command fails with exit code 5. The error lists every candidate (a zone as `cloudflare/<profile> account <id> (<name>) zone <zone id> <status>`, a bucket as `cloudflare/<profile> account <id>`) and names what chooses: `--account <id or name>`, the zone id for a zone, and `--profile <name>` when the candidates are of different logins.
- The platform-neutral commands (`dns`, `domain`, `cert`) route by domain: a domain that two selected accounts of one login hold a zone of is ambiguous there too, and the error points to `polyctl cloudflare ... --account <id or name>` or the zone id.
- `zone ensure` reuses a zone in whichever selected account holds it; `zone create` fails naming that account.

**Ids.** Zone ids and DNS record ids are Cloudflare's own and unique across accounts; a zone row of the inventory carries its account as parent. An `r2_bucket` row has the id `<account id>/<bucket>`.

**Kinds of credentials.**

- An account-owned API token belongs to one account and sees only it: its login works on that account, and another account cannot be added.
- A user token without `Account:Read` cannot list accounts. Its login takes `--set account_id` / `--set accounts` as given; without them it is not bound to an account and works on every zone it sees (for a new zone see [Zones](#zones)). `account use <id>` binds such a login to an account later.
- A browser login (`method=oauth`) without the `account-settings.read` scope reads the accounts off its zones, so an account without a zone is not listed; a selected account that list does not show is kept.

**Upgrading.** Nothing is migrated: `config.yaml` is read as before, and rows cached by an older polyctl are replaced by the next sync of their type (R2 bucket rows get their new id then).

## Zones

```sh
polyctl cf zone create example.com --profile acme
polyctl cf zone ensure example.com --preset optimized --ssl flexible
polyctl cf zone ensure example.com --preset optimized --dry-run -o json
polyctl cf zone delete example.com --yes
```

A zone command covers every selected account of the login, or the one of `--account`; a new zone goes to `--account`, else to the default account. A zone name that two accounts in the scope of the call hold a zone of is asked about on a terminal and exit code 5 otherwise (see [Accounts](#accounts)). `zone list` shows an `ACCOUNT` column when its zones are of several accounts.

A login without an account (its credentials could not list accounts) uses the only account the credentials see for a new zone; when they see several, the account is asked for on a terminal and a usage error otherwise (pass `--account`). The zone lifecycle commands read the platform, so `--offline` is refused (exit code 6).

**`zone create <domain>`** adds a full zone to the account of `--account`, else to the default account.

- `<domain>` is a registered domain such as `example.com`. Something plainly not a domain (no dot, a URL, an IP address, spaces) is a usage error (exit code 2).
- The new zone stays `pending` until you set its nameservers at the registrar; polyctl does not wait and never changes the registrar itself. The nameservers are printed under `Nameservers (set these at your registrar):`, with the matching `polyctl domain ns set` command on stderr.
- Foundation DNS is switched on by default (`--foundation-dns=false` skips it). An account that cannot use it is reported `skipped`; any other refusal fails the command (the zone stays created).
- A zone that already exists is exit code 1 (use `ensure`). Without `--account` it is looked for in every selected account and the error names the account that holds it; with `--account` in that account alone. A zone Cloudflare refuses because an account the login does not select holds the domain (code 1061, `already exists`) is exit code 1 as well: pass `--account` or `--profile` for that account.
- A zone created with `--account` in an account outside the selection is not stored in the inventory (a note says so).

**`zone ensure <domain>`** reuses the zone (`unchanged`) or creates it as `create` does. Without `--account` the zone is looked for in every selected account and reused in the one that holds it (`target.account_id` of the report names it); zones of the name in two of them are asked about on a terminal and exit code 5 otherwise. With `--account` only that account is looked in. Then:

- `--preset optimized` converges, reading first and writing only what differs, in this order: `0rtt` on, `early_hints` on, `rum` on, `response_buffering` on; on Enterprise zones only, `ipv6` off and Argo Smart Routing on (elsewhere `skipped`, since Argo is billed); `always_use_https` on, `automatic_https_rewrites` on; last `ssl`.
- `ssl` is `--ssl` (`flexible` or `strict`), else `defaults.cloudflare.ssl`, else `strict`. `strict` replaces `flexible` (`flexible -> strict`), so pass `--ssl flexible` for an origin without HTTPS. `off` and `full` are set with `cloudflare ssl-mode`. `--ssl` without `--preset` sets the SSL mode only.
- A setting the plan cannot change is `skipped`.
- `--foundation-dns` applies to a new zone by default; an existing zone is switched on only when the flag is given explicitly, and never switched off.
- It does not wait (no `--wait`); a new zone stays `pending`. A failure stops where it is without undoing anything; running it again continues.
- Report rows: `zone/<domain>`, `zone/<domain>/foundation-dns`, `zone/<domain>/setting/<id>` (`from -> to`; JSON `attrs.from` / `attrs.to`). JSON: `{"target": {"platform", "profile", "account_id"}, "dry_run", "zone": {"id", "name", "status", "plan", "name_servers", "original_name_servers"}, "changes"}`.
- `--dry-run` for a zone that does not exist yet shows its id and current values as `(pending)` and the Enterprise-only settings as `skipped` (`plan unknown until created`).
- A failure is sent to `hooks.on_failure` as `cloudflare.zone.ensure.failed` (`cloudflare.zone.create.failed` for `create`); see [Configuration](../configuration.md).

**`zone delete <zone>`** deletes a zone (name or id) with all of its DNS records.

- It asks for confirmation, showing the plan, status and number of DNS records (`--yes` in the non-interactive flow; see [Confirmations](../interactive.md#confirmations)). A name found in several accounts is exit code 5: pass `--account`, `--profile` or the zone id.
- An Enterprise zone must be moved to the Free plan first. polyctl does that only with `--downgrade-enterprise` (changes billing); otherwise it stops with exit code 1. A token without billing permission is exit code 3 and nothing is deleted. If the downgrade succeeds and the deletion fails, the zone stays on Free: run the command again.
- `--dry-run` reports `zone/<domain>  would delete  plan=free records=12` (plus `zone/<domain>/subscription  would update  enterprise -> free`).

A zone the inventory remembers but Cloudflare no longer has is dropped from the inventory and looked up again by name (not found: exit code 4). A zone the inventory does not know triggers one sync of the Cloudflare accounts.

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

- The R2 commands cover every selected account of every Cloudflare profile. `--profile` narrows them to the selected accounts of that profile, and `--account <id or name>` to one account; an account the login does not select is read live with `--account` and nothing of it is cached. The same account in two profiles counts once. Messages name the account next to the profile (`account <id> of cloudflare/<profile>`) when the profile works on several.
- An account without R2 is exit code 7 when it is the only one asked; among several it is skipped (of a profile with several selected accounts, the listing fails only when none of them can be used for R2). A login without an account uses the only account its credentials see; when they see several it is exit code 5: pass `--account`, or select the accounts with `polyctl cloudflare account use <id>`.
- `bucket list` without `--profile` lists the buckets of every Cloudflare profile; accounts without R2 are skipped, a failing profile is a warning, and the command fails only when no account could be read. A profile that lists the buckets of several accounts adds an `ACCOUNT` column.
- Buckets of the default jurisdiction are cached as `r2_bucket`, one row per account and bucket (id `<account id>/<bucket>`; fresh for an hour; `polyctl sync --type r2_bucket` fills it). `--offline` lists only the inventory; `--wide`, `--jurisdiction` and an unselected `--account` read live (exit code 6 with `--offline`).
- The `r2 domain` commands find the account that holds `<bucket>`. One account to look in (`--account`, or `--profile` with a login of one account) is used as it is. Otherwise the inventory answers when it names exactly one account for the bucket; failing that (and with `--refresh` or `--jurisdiction`) every account is asked live. A bucket found nowhere is exit code 4. The name of a bucket is unique in its account only: a name held by several accounts is asked about on a terminal and exit code 5 otherwise, listing each as `cloudflare/<profile> account <id>`; pass `--account`, or `--profile` when the accounts are of different profiles. Without `<bucket>` a terminal offers the buckets, each with its account when a profile has several.
- `--jurisdiction eu|fedramp` addresses that R2 jurisdiction instead of the default one.

**Commands**

- `bucket list`: profile, account (when a profile lists several), name, creation date; `--wide` adds location, storage class and jurisdiction (one request per bucket).
- `domain list` / `get`: enabled state, zone, minimum TLS (`-` when never set), ownership and SSL status (`pending` / `initializing` right after binding is normal). A domain not bound to the bucket is exit code 4.
- `domain attach`: binds `<domain>` (no wildcards). The zone is `--zone` (name or id) or the longest zone name the domain ends in, within the bucket's account; it must be active. Cloudflare creates the proxied CNAME `<domain> -> public.r2.dev`. A domain already bound (to any bucket), or an existing A, AAAA or CNAME record of that name, is exit code 1 (a TXT record is fine). `--disabled` binds it disabled; `--min-tls` sets the minimum TLS version (not set by default).
- `domain update`: changes `--enabled` / `--enabled=false` and/or `--min-tls` (at least one).
- `domain detach`: unbinds the domain and Cloudflare deletes its CNAME. Asks for confirmation (default no); needs `--yes` in the non-interactive flow.
- `domain ensure`: idempotent; a binding with the wanted enabled state (and `--min-tls`, when given) is `unchanged`, a differing one is updated, a missing one is attached. A binding in another zone than `--zone` is an error and is never unbound automatically.
- `update`, `detach` and `ensure` read the domain first; a domain that is not bound is exit code 4.
