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
namecom dns update <domain> (<name> [<type> [<value>]] | --id <record-id>) [--type] [--name] [--value] [--ttl] [--priority]
namecom dns delete <domain> (<name> [<type> [<value>]] | --id <record-id>) [-y]
```

- `update` and `delete` find their record by `<name>`. `<type>` and `<value>` are needed only to tell records apart; `--id <record-id>` names one record exactly and cannot be combined with a positional record. The records of the domain are read live. With only `<domain>`, a terminal lists the records to choose from.
- `delete`: a name whose records have one type needs no `<type>`. A single match is deleted at once. Several matches are listed with their ids and the way to delete one of them only (`<value>` or `--id`), then confirmed (`--yes` in the non-interactive flow; see [Confirmations](../interactive.md#confirmations)). A name with records of several types is never deleted as a whole: a terminal lists its records to tick, scripts get exit code 5 naming the types, also with `--yes`. JSON: `{"profile", "domain", "records": [...]}`, plus `"deleted_id": "<record-id>"` when one record was deleted.
- `update` changes exactly one record. Several matches are a list to choose one from on a terminal, and exit code 5 with the candidates and their ids on stderr otherwise (also with `--yes`).
- Former form: `update|delete <domain> <record-id>` still works. A single argument after the domain that is the id of a record of the domain, and not the name of one, is taken for that id; one that is both is exit code 5 and names `--id` and the full record name as the two ways to say which.
- `create` takes the record as arguments: `<name>` is relative to the domain (`www`, `a.b`), `@` for the apex, or a full name inside the domain; `<type>` is case-insensitive; the value is one argument (quote one that contains spaces; one that starts with `-` goes after `--`). A wrong number of arguments is exit code 2.
- Former form (0.5.x): `create` still reads the record from `--name`, `--type` and `--value` (without `--name`, the apex). These flags are no longer listed in the help. A positional record together with one of them is exit code 2.
- `update` changes the fields given as `--name`, `--type`, `--value`, `--ttl` and `--priority`; `--name` is relative to the domain (`www`, `@`). The positional `<type>` and `<value>` say which record is meant, the flags what it becomes. Without any of these flags a terminal asks for the new value (the current one is the default; the same value changes nothing, exit code 0), and the non-interactive flow is exit code 2.
- `--ttl` in seconds, minimum 300; `0` (the default of `create`) uses name.com's default.
- `--priority` for MX/SRV records.
- `whoami` needs the network (exit code 6 with `--offline`); credentials that no longer work exit with code 3.
- List commands honour `--refresh` / `--offline`; writes always go to name.com.

```sh
polyctl namecom dns create example.com www A 203.0.113.10
polyctl namecom dns create example.com @ MX mail.example.com --priority 10
polyctl namecom dns update example.com www --value 203.0.113.20
polyctl namecom dns update example.com www A 203.0.113.10 --value 203.0.113.20
polyctl namecom dns delete example.com old
polyctl namecom dns delete example.com --id 12345
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
