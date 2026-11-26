# name.com

Commands of `polyctl namecom`: registered domains and the DNS records name.com hosts for them.

Profile selection: `--profile` (must have a name.com account, else exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5). Inventory types: `domain`, `zone`, `dns_record` (every name.com domain is also its own zone).

## Commands

```text
namecom whoami                    # GET /v4/hello: user name, environment, server time
namecom domain list               namecom domain get <domain>
namecom domain ns get <domain>    namecom domain ns set <domain> <nameserver>...
namecom domain lock <domain>      namecom domain unlock <domain>
namecom domain autorenew <domain> on|off
namecom domain check <name>...    # availability and price
namecom dns list <domain> [--type] [--name]
namecom dns create <domain> <name> <type> <value> [--ttl 300] [--priority]
namecom dns update <domain> <record-id> [--type] [--name] [--value] [--ttl] [--priority]
namecom dns delete <domain> <record-id>
```

- Records are addressed by their name.com record id, an argument of `update` and `delete`.
- `create` takes the record as arguments: `<name>` is relative to the domain (`www`, `a.b`), `@` for the apex, or a full name inside the domain; `<type>` is case-insensitive; the value is one argument (quote one that contains spaces; one that starts with `-` goes after `--`). A wrong number of arguments is exit code 2.
- Former form (0.5.x): `create` still reads the record from `--name`, `--type` and `--value` (without `--name`, the apex). These flags are no longer listed in the help. A positional record together with one of them is exit code 2.
- `update` changes the fields given as `--name`, `--type` and `--value`; `--name` is relative to the domain (`www`, `@`).
- `--ttl` in seconds, minimum 300; `0` (the default of `create`) uses name.com's default.
- `--priority` for MX/SRV records.
- `whoami` needs the network (exit code 6 with `--offline`); credentials that no longer work exit with code 3.
- List commands honour `--refresh` / `--offline`; writes always go to name.com.

```sh
polyctl namecom dns create example.com www A 203.0.113.10
polyctl namecom dns create example.com @ MX mail.example.com --priority 10
polyctl namecom domain ns set example.com ns1.example.net ns2.example.net
```

## Login and permissions

Username plus API token, created at <https://www.name.com/account/settings/api>:

```sh
polyctl auth login namecom --profile acme
printf '%s\n' "$NAMECOM_TOKEN" | polyctl auth login namecom --profile acme --set username=acme --set token=-   # scripts
```

- API access must be enabled in the name.com account settings, and name.com may require your IP address to be whitelisted there.
- `--set env=test` uses name.com's test environment (`api.dev.name.com`), which needs a token generated for it; polyctl appends `-test` to the username when missing. A second name.com account needs its own profile.

More in [Accounts](../accounts.md#namecom).
