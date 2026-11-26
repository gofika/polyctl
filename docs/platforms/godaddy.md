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
godaddy dns add <domain> <name> <type> <value> [--ttl 600] [--priority <n>]        # one more record; the others stay
godaddy dns upsert <domain> <name> <type> <value>... [--ttl 600] [--priority <n>]   # sets the whole name+type set
godaddy dns delete <domain> (<name> [<type>] | --id <zone|TYPE|name|value>) [--yes]
```

- `whoami` needs the network (exit code 6 with `--offline`); credentials that no longer work exit with code 3.
- List commands honour `--refresh` / `--offline`; writes always go to GoDaddy.

## DNS records

GoDaddy has no record ids: records are addressed by type and name.

Only domains GoDaddy serves DNS for are indexed as zones: a domain whose nameservers are not GoDaddy's (`*.domaincontrol.com`; a domain with no nameservers listed keeps GoDaddy's defaults), or whose status is cancelled, expired or transferred out, is left out of the zone and record sync, so the neutral `dns` commands do not route to it. `godaddy dns` still reaches it when named.

- `add` appends one record to the name+type set; the others stay.
- `upsert` creates the set or replaces all of it with the values given (each `<value>` is one record), like `record upsert` on Route 53 and Cloud DNS.
- `delete <domain> <name> [<type>]` deletes the whole set (`<type>` is needed only for a name with records of several types); `delete --id` deletes one record and cannot be combined with a positional record (exit code 2). It lists what it would delete with the ids, says for several records how to delete one of them only (`--id`), and asks for confirmation (`--yes` in the non-interactive flow; see [Confirmations](../interactive.md#confirmations)). A set or record that does not exist is exit code 4 and asks nothing.
- `<type>` of `delete` is needed only to tell records apart: a name whose records all have one type needs none. A name with records of several types is not deleted as a whole: a terminal offers its records to pick one, and the non-interactive flow names the types and exits with code 5, also with `--yes`. The NS and SOA records of the apex are not meant by `@` alone.
- `<name>` is relative to the domain (`www`, `a.b`), `@` for the apex, or a full name inside the domain. `<type>` is case-insensitive. A value is one argument: quote one that contains spaces, and put `--` before one that starts with `-`.
- A wrong number of record arguments is exit code 2, and the message shows the usage (`usage: polyctl godaddy dns add <domain> <name> <type> <value>`). On a terminal, what is left out is asked in the order domain, name, type, value: the record may stop after the domain, the name or the type. The name is chosen from the names the domain already has, `@` for the apex, or typed in (it is never taken to be the apex without asking); the type from the types the platform writes, the one the name already has preselected. `upsert` shows the current records of the set, proposes the first value and asks for values until one is left empty. `delete` with only `<domain>` asks for the record to delete.
- Former form (0.5.x): `add` and `upsert` still read the record from `--name`, `--type` and `--value` (repeated on `upsert`), `delete` from `--name` and `--type` (without `--name`, the apex; on a terminal `add` and `upsert` ask for the name instead; `--type` is optional as `<type>` is). These flags are no longer listed in the help. A positional record together with one of them is exit code 2.
- `--ttl` in seconds, minimum 600; `0` (default) uses GoDaddy's default.
- `--priority` for MX/SRV records.

The record id is synthetic, `zone|TYPE|name|value` with each part percent-encoded, so the neutral `dns` commands and `godaddy dns delete --id` can target one record. The zone keeps the ids of the same record in two domains apart (GoDaddy gives every domain the same apex NS records); `godaddy dns delete --id` with an id of another domain than the one named is exit code 2, and the neutral `dns delete --id` finds no such record in the zone named (exit code 4). MX ids add the priority (`example.com|MX|@|mail.example.com|10`) and SRV ids add service, protocol, port, weight and priority (`example.com|SRV|@|sip.example.com|_sip|_udp|5060|0|0`): GoDaddy keeps every SRV record of an owner in one set, and these fields tell apart records with the same target.

An id without the MX or SRV fields, and the `TYPE|name|value` id older polyctl versions printed, still work while they name one record; when one matches several it is exit code 5 and the error lists the ids to use instead. The first run of this version drops the GoDaddy records cached under the older ids; they are fetched again on their next use.

```sh
polyctl godaddy dns add example.com @ TXT "v=spf1 include:_spf.example.net ~all"
polyctl godaddy dns upsert example.com www A 203.0.113.10 203.0.113.11
polyctl godaddy dns delete example.com www A --yes
polyctl godaddy dns delete example.com --id 'example.com|TXT|@|v=spf1%20include:_spf.example.com%20~all' --yes
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
