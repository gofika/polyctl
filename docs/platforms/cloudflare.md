# Cloudflare

Commands of `polyctl cloudflare` (alias `polyctl cf`): zones and their settings, DNS records, cache, cache and redirect rules, and R2 custom domains.

- [Commands](#commands)
- [Login and permissions](#login-and-permissions)
- [Zones](#zones)
- [Zone settings](#zone-settings)
- [DNS records](#dns-records)
- [Cache and redirect rules](#cache-and-redirect-rules)
- [R2 custom domains](#r2-custom-domains)

Every command can be written with `cf` in place of `cloudflare` (`polyctl cf zone list`). Profile selection: `--profile` (must have a Cloudflare account, else exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5). Inventory types: `zone`, `dns_record`, `r2_bucket`.

## Commands

```text
cloudflare whoami                 # verifies the API token (id, status, expiry) or the browser authorization (granted scopes)
cloudflare account list
cloudflare account current
cloudflare account use <account>
cloudflare account add <account>...
cloudflare account remove <account>... [--default <account>]
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
cloudflare r2 bucket list [--wide] [--jurisdiction eu|fedramp]      # every r2 command: [--account <id|name>]
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
| `account list` | `Account:Read` |
| `whoami` showing your email | `User:Read` |
| `cache purge`, `dev-mode`, `ssl-mode`, `zone create` / `ensure` / `delete` | `Zone:Edit` (at the account level to create a zone) |
| `zone ensure`, `zone setting` | zone settings edit |
| `zone delete --downgrade-enterprise` | billing |
| `cache rule` / `redirect rule` | Cache Rules / Single Redirects (Dynamic URL Redirects) |
| `r2` | R2 read and write; `r2 domain attach` / `ensure` also DNS edit on the domain's zone |

A browser login (`method=oauth`) does not cover R2: the `r2` commands need an API token.

## Zones

```sh
polyctl cf zone create example.com --profile acme
polyctl cf zone ensure example.com --preset optimized --ssl flexible
polyctl cf zone ensure example.com --preset optimized --dry-run -o json
polyctl cf zone delete example.com --yes
```

A login works on its selected accounts, one of them the default account. The login selects them ([Accounts](../accounts.md#cloudflare)); `account use <account>` makes an account (id or name) the default, `account add` and `account remove` change the selection without a new login (local configuration only, no confirmation, no `--dry-run`), and `account current` shows it. `account list` marks the selected accounts (`SELECTED`) and the default one (`*`; `selected` and `default` in JSON). An account that leaves the selection, by `account remove` or by a new login, loses its cached zones, records and R2 buckets at once; removing the default account needs `--default <account>` (asked on a terminal), and removing every account is a usage error. `--account <id or name>` on the `zone`, `dns`, `cache`, `redirect`, `dev-mode`, `ssl-mode` and `r2` commands names one account for the call: lookups and lists cover that account instead of every selected one, and a new zone goes to it instead of the default account. An account outside the selection is read live with `--account` and nothing of it is stored in the inventory; without the flag its zones are not found (exit code 4, naming the account). A zone id given with the `--account` of another account is a usage error (exit code 2).

A zone name that two accounts in the scope of the call hold a zone of (an active zone in one, a pending one in the other) is asked about on a terminal and exit code 5 otherwise, listing each zone with its account: `--account`, `--profile` when the zones are in different logins, or the zone id choose. `zone list` shows an `ACCOUNT` column when its zones are of several accounts.

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
- Buckets of the default jurisdiction are cached as `r2_bucket`, one row per account and bucket (id `<account>/<bucket>`; fresh for an hour; `polyctl sync --type r2_bucket` fills it). `--offline` lists only the inventory; `--wide`, `--jurisdiction` and an unselected `--account` read live (exit code 6 with `--offline`).
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
