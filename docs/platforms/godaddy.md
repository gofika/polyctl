# GoDaddy

Commands of `polyctl godaddy`: registered domains and the DNS records GoDaddy hosts for them.

Profile selection: `--profile` (must have a GoDaddy account, else exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5). Inventory types: `domain`, `zone`, `dns_record`.

## Commands

```text
godaddy whoami                    # verified by listing one domain: method, environment
godaddy domain list [--status ACTIVE,EXPIRED]   godaddy domain get <domain>
godaddy domain ns get <domain>    godaddy domain ns set <domain> <nameserver>...
godaddy domain lock <domain>      godaddy domain unlock <domain>
godaddy domain autorenew <domain> on|off
godaddy domain check <name>...    # availability and price
godaddy dns list <domain> [--type] [--name]
godaddy dns add <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority]          # one more record; the others stay
godaddy dns upsert <domain> --type A --name www --value <v> [--value <v>...] [--ttl] [--priority]   # sets the whole name+type set
godaddy dns delete <domain> (--type A --name www | --id <TYPE|name|value>) [--yes]
```

- `whoami` needs the network (exit code 6 with `--offline`); credentials that no longer work exit with code 3.
- List commands honour `--refresh` / `--offline`; writes always go to GoDaddy.

## DNS records

GoDaddy has no record ids: records are addressed by type and name.

- `add` appends one record to the name+type set; the others stay.
- `upsert` creates the set or replaces all of it with the given `--value`s (repeat `--value` for several records), like `record upsert` on Route 53 and Cloud DNS.
- `delete --type --name` deletes the whole set; `delete --id` deletes one record. It lists what it would delete and asks for confirmation (`--yes` in the non-interactive flow; see [Confirmations](../interactive.md#confirmations)). A set or record that does not exist is exit code 4 and asks nothing.
- `--name` is relative to the domain (`www`, `@`); default `@`.
- `--ttl` in seconds, minimum 600; `0` (default) uses GoDaddy's default.
- `--priority` for MX/SRV records.

The record id is synthetic, `TYPE|name|value` with each part percent-encoded, so the neutral `dns` commands and `godaddy dns delete --id` can target one record:

```sh
polyctl godaddy dns upsert example.com --type A --name www --value 203.0.113.10 --value 203.0.113.11
polyctl godaddy dns delete example.com --id 'TXT|@|v=spf1%20include:_spf.example.com%20~all' --yes
```

## Login and permissions

A Personal Access Token created at <https://developer.godaddy.com/personal-access-token>:

```sh
polyctl auth login godaddy --profile acme
printf '%s\n' "$GODADDY_TOKEN" | polyctl auth login godaddy --profile acme --set token=-   # scripts
polyctl auth login godaddy --profile acme-ote --set token=... --set env=ote                # OTE test environment
polyctl auth login godaddy --profile legacy --set api_key=... --set api_secret=-           # legacy key pair (deprecated by GoDaddy)
```

- For production API access GoDaddy requires the account to hold at least one domain or be on a plan that grants API access; paid operations need a billing method on file. Otherwise requests fail with `403 ACCESS_DENIED`, reported as exit code 3: use an OTE credential (`--set env=ote`, `api.ote-godaddy.com`) for development.

More in [Accounts](../accounts.md#godaddy).
