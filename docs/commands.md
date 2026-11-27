# Commands

Platform-neutral commands that take a domain (or an address) and find the account that holds it for you, and the conventions shared by the platform-specific commands.

- [Choosing the account](#choosing-the-account)
- [DNS](#dns)
- [Domains](#domains)
- [Certificates](#certificates)
- [Deploying certificates](#deploying-certificates)
- [Finding resources by IP or DNS name](#finding-resources-by-ip-or-dns-name)
- [Routing rules](#routing-rules)
- [Platform-specific commands](#platform-specific-commands)

## Choosing the account

`dns`, `domain` and `cert ensure` route a domain to the account (platform + profile) that owns it; see [Routing rules](#routing-rules). Narrow the choice with:

- `--profile <name>` / `-p`: only the accounts of that profile.
- `--platform <platform>`: only the account on that platform. Takes the same names and aliases as `auth login`.

`cert deploy` uses the same two flags to select the accounts it deploys to. `find` searches every account; its `--platform` takes a comma-separated list, as on `sync`.

The status line on stderr always names the account used, for example `zone example.com via cloudflare/acme (local inventory)`.

## DNS

```text
polyctl dns list   <domain> [--type A] [--name www]
polyctl dns add    <domain> <name> <type> <value> [--ttl 300] [--priority 10] [--proxied[=false]]
polyctl dns ensure <domain> <name> <type> <value>... [--ttl 300|auto] [--priority 10] [--proxied[=false]]
polyctl dns ensure <domain> (-r <name:type:value[:ttl[:proxied]]>... | -f records.yaml) [--prune-duplicates]
polyctl dns delete <domain> (<name> [<type> [<value>]] | --id <record-id>) [-y]
polyctl dns delete <domain> --all [--type <T>[,<T>...]]... [--keep-bound] [-y]
```

Every `dns` command also takes `--profile` and `--platform`.

One record is written like a line of a zone file, after the domain:

```sh
polyctl dns ensure example.com @ A 192.0.2.10
polyctl dns ensure example.com www CNAME target.example.net
polyctl dns ensure example.com api A 203.0.113.10 --ttl 300
polyctl dns add example.com @ TXT "v=spf1 include:_spf.example.net ~all"
polyctl dns delete example.com www A
```

**Names and values**

- `<domain>` may be the zone apex or any name under it: `www.example.com` resolves to the `example.com` zone.
- `<name>` (and `--name` of `dns list`) is relative to the zone (`www`, `a.b`, `@` for the apex), a full name in the zone (`www.example.com`), or an absolute name ending with a dot (`www.example.com.`). A name outside the zone (`www.other.org`, `www.other.org.`) is exit code 2, never put inside the zone.
- `<type>` is case-insensitive.
- Each `<value>` is one argument: quote one that contains spaces (`"v=spf1 -all"`, `"10 mail.example.com"`). A value that starts with `-` goes after `--`: `polyctl dns ensure example.com note TXT -- -text`.
- A record's data is its **value** everywhere: the `<value>` argument, the `VALUE` column and the `value` field of `-o json` / `-o yaml`. What one command prints can be passed to another.
- A wrong number of record arguments is exit code 2, and the message shows the usage (`usage: polyctl dns add <domain> <name> <type> <value>`). On a terminal, `dns add` and `dns ensure` ask for what is left out, in the order zone, name, type, value: the record may stop after `<domain>`, `<name>` or `<type>`. The name is chosen from the names the zone already has, `@` for the apex, or typed in; the type from the types the platform writes at that name, the one the name already has preselected (a CNAME is left out at the apex on the platforms that refuse one there; `dns ensure` also leaves out NS at the apex, and with `--proxied` the types other than A, AAAA and CNAME; GoDaddy offers SRV only at a `_service._proto` name). A `<type>` given is checked first: an unknown type is exit code 2, one the platform cannot write exit code 7, a `<name>` given that the command does not take (outside the zone, or a relative name ending in a top-level domain) exit code 2, and with both given, a name and type the command refuses together exit code 2, all before the zone is read; `dns ensure` proposes the current value of the record and asks for values until one is left empty. `dns delete` with only `<domain>` lists the records. The non-interactive flow asks nothing.
- Former form (0.5.x): `dns add` and `dns delete` still read the record from `--name`, `--type` and `--value` (without `--name`, or with an empty one, the record name is `<domain>` itself: a `<domain>` below its zone names the record, and the zone itself is its apex; on a terminal, `dns add` asks for the name in that second case instead of writing to the apex). These flags are no longer listed in the help (`--type` of `dns delete` stays, for `--all`). A positional record together with one of them is exit code 2.
- `polyctl dns set` was removed, use `polyctl dns ensure <domain> <name> <type> <value>`. `dns set` was keyed on name + type and left records of other types alone; `dns ensure` is the same on a name without records of other types, and on a name that holds one record of the type (it is updated in place, and records of other types beside it are left alone). It differs only on a name that holds records of other types and none of the type: with one, `dns ensure` now replaces it (deletes it, then creates the record: confirmed on a terminal, `--yes` in a script, exit code 2 without it); with several, it stops with exit code 5 in a script, also with `--yes`. To write a record beside such records, use `dns add`; to replace them, `dns delete` first. This also applies to 0.5.x `dns ensure -r` / `-f` runs, which created the record beside records of other types. `dns ensure` takes no `--name`, `--type` and `--value`, checks the type and the value before it writes, and prints a change report in place of the record.
- `--ttl` of `dns add` is in seconds; `0` or no flag means the platform default. `--ttl` of `dns ensure` is described [below](#dns-ensure).
- In tables, special TTLs are shown by name: `auto` (Cloudflare automatic, `1` in the API), `alias` (Route 53 alias records) and `default` (a GoDaddy record written without `--ttl`). JSON and YAML keep the raw value.
- `--proxied` is Cloudflare only. `--proxied` turns the proxy on, `--proxied=false` turns it off (the `=` is required). Without it, `dns ensure` keeps the current setting of an existing record, and a new record gets Cloudflare's default. The `PROXIED` column appears for Cloudflare zones.

### Record types

Every command that writes a record (`dns add`, `dns ensure`, and the `create`, `add`, `upsert` and `update` record commands of the platforms) checks it before anything is sent:

- A type polyctl does not know is exit code 2, and the message lists the known types. `SOA` is managed by the platforms. URL forwarding (`URL`, `REDIRECT_URL`, `FORWARD_URL`, ...) and Route 53 alias targets are not record types: they stay with the platform's own tools (Cloudflare: `polyctl cloudflare redirect rule set`), and the message says so.
- A known type the platform does not write is exit code 7, and the message names the types it writes (`SPF` adds: write the policy as a TXT record; `ALIAS` / `ANAME` name the platform's own word for it).
- An invalid value is exit code 2: the message says what is wrong and shows a valid value of the type.
- A valid value is sent in a normal form: host names in lower case without the trailing dot (internationalized names in punycode), addresses canonical, hex in lower case, the value of CAA and the strings of NAPTR and URI quoted. Each platform gets it in the fields of its API (the components of Cloudflare's `data`, the priority field of name.com, the SRV fields of GoDaddy, the trailing dots Cloud DNS expects). Alibaba Cloud, GoDaddy and name.com take the text of a TXT record: a value written as quoted strings (`"v=DKIM1; k=rsa; " "p=MIIB..."`) reaches them unquoted and joined.
- GoDaddy also takes `@` for the zone apex as the target of a CNAME, NS, MX or SRV record, as it lists its default `www CNAME @`; the other platforms refuse it (exit code 2) and take the zone's name. GoDaddy takes an SRV record with a port from 1 and a name of the form `_service._proto[.owner]`; anything else is refused before any request (exit code 2), also by a `--dry-run`.
- The priority of an MX record goes in front of its value (`"10 mail.example.com"`) or in `--priority` / `priority`; a new MX record needs one. SRV, HTTPS, SVCB, URI and NAPTR carry theirs as a field of the value: `--priority` with them is exit code 2, and the message says which field it is. Other types take no priority.
- Records that cannot share a name are refused: a CNAME beside any other record (on Cloudflare beside A, AAAA or NS records), NS below the zone apex beside anything but DS on Cloudflare and Alibaba Cloud, ALIAS / ANAME beside A, AAAA or CNAME records. `dns ensure` checks its records among themselves (against the zone it replaces or asks, see [What ensure changes](#what-ensure-changes)); `dns add` refuses them against the zone. A CNAME at the zone apex is refused before any request (exit code 2) on the platforms that do not take one there (Route 53, Cloud DNS, GoDaddy, name.com), as the apex holds the zone's NS records.

| Type | Value | Example | Cloudflare | Route 53 | Cloud DNS | Alibaba Cloud | name.com | GoDaddy |
|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `A` | IPv4 address | `203.0.113.10` | yes | yes | yes | yes | yes | yes |
| `AAAA` | IPv6 address | `2001:db8::10` | yes | yes | yes | yes | yes | yes |
| `CNAME` | host | `target.example.net` | yes | yes | yes | yes | yes | yes |
| `ALIAS` | host | `target.example.net` | | | yes (apex only) | yes | | |
| `ANAME` | host | `target.example.net` | | | | | yes | |
| `MX` | `[<priority>] <host>` | `10 mail.example.com` | yes | yes | yes | yes | yes | yes |
| `NS` | host | `ns1.example.net` | yes | yes | yes | yes | yes | yes |
| `TXT` | text, or `"<string>" ["<string>"...]` of at most 255 bytes each | `"v=spf1 -all"` | yes | yes | yes | yes | yes | yes |
| `SPF` | as TXT | `"v=spf1 -all"` | | yes | yes | | | |
| `SRV` | `<priority> <weight> <port> <target>` | `10 5 5060 sip.example.com` | yes | yes | yes | yes | yes | yes |
| `CAA` | `<flags> <tag> "<value>"` | `0 issue "letsencrypt.org"` | yes | yes | yes | yes | | yes |
| `PTR` | host | `host.example.com` | yes | yes | yes | | | |
| `NAPTR` | `<order> <preference> "<flags>" "<service>" "<regexp>" <replacement>` | `100 10 "S" "SIP+D2U" "" _sip._udp.example.com` | yes | yes | yes | | | |
| `HTTPS` | `<priority> <target> [<key>=<value>...]` (priority 0: alias mode, no parameters) | `1 . alpn="h3,h2"` | yes | yes | yes | yes | | |
| `SVCB` | as HTTPS | `1 svc.example.net port=8443` | yes | yes | yes | yes | | |
| `TLSA` | `<usage> <selector> <matching-type> <hex data>` | `3 1 1 <64 hex digits>` | yes | yes | yes | yes | | |
| `SMIMEA` | as TLSA | `3 1 1 <64 hex digits>` | yes | | | | | |
| `SSHFP` | `<algorithm> <fingerprint-type> <hex fingerprint>` | `4 2 <64 hex digits>` | yes | yes | yes | | | |
| `DS` | `<key-tag> <algorithm> <digest-type> <hex digest>` | `12345 13 2 <64 hex digits>` | yes | yes | yes | | | |
| `DNSKEY` | `<flags> 3 <algorithm> <base64 key>` | `257 3 13 mdss...GQ==` | yes | | yes | | | |
| `CERT` | `<type> <key-tag> <algorithm> <base64 certificate>` (type a number or `PKIX`, `PGP`, ...) | `PKIX 0 0 MIIBszCC...` | yes | | | | | |
| `URI` | `<priority> <weight> "<target URI>"` | `10 1 "https://www.example.com/"` | yes | | | | | |
| `LOC` | `<d> [<m> [<s>]] N\|S <d> [<m> [<s>]] E\|W <altitude>[m] [<size>[m] [<hp>[m] [<vp>[m]]]]` | `52 22 23.000 N 4 53 32.000 E -2.00m` | yes | | | | | |
| `OPENPGPKEY` | `<base64 key>` | `mDMEXEcE6RYJ...` | yes | | | | | |
| `IPSECKEY` | `<precedence> <gateway-type> <algorithm> <gateway> [<base64 key>]` | `10 1 2 192.0.2.38 AQNR...` | | | yes | | | |

The hex data has the length its type calls for (TLSA / SMIMEA matching type 1: 64 digits, 2: 128; SSHFP fingerprint type 1: 40, 2: 64; DS digest type 1: 40, 2 and 3: 64, 4: 96). `polyctl dns --help` prints the same table from the checks themselves.
- After a write, the inventory is updated, so the next `dns list` shows the change without `--refresh`.
- A Cloudflare, name.com or GoDaddy request refused for its rate limit (HTTP 429) waits for the delay the platform announces (`Retry-After`, `RateLimit-Reset`; at most 2 minutes per wait, 3 waits per request) and is sent again, so a long `dns delete --all` or sync rides out the limit window instead of failing partway.

### dns add

- `dns add` always creates one more record and leaves the others of the name alone, of its type or of others. Use it to build round-robin `A` records, several `TXT` / `MX` records, or records of several types on one name. To change a record, use `dns ensure`, which is for a name with one record.
- A record whose name already holds a record it cannot share the name with (a CNAME beside an A record, a second CNAME, ...) is refused before the write.

### dns ensure

Brings records of one zone to the desired state. Safe to run again and again. It is meant for names that hold one record, or the set of one type (several `MX` or `TXT` values); for more than one record on a name, or records of several types, use `dns add`.

```sh
polyctl dns ensure example.com www A 203.0.113.10 --ttl 300 --proxied
polyctl dns ensure example.com mail MX "10 mx1.example.net" "20 mx2.example.net"
polyctl dns ensure example.com -r www:A:203.0.113.10:300:true -r 'mail:MX:10 mx1.example.net'
polyctl dns ensure example.com -f records.yaml --dry-run
polyctl dns ensure example.com www CNAME target.example.net --yes   # replaces the A record of www
```

```yaml
records:
  - name: www
    type: A
    value: 203.0.113.10
    ttl: 300          # optional; a number or auto
    proxied: true     # optional, Cloudflare only
  - name: mail
    type: MX
    value: mx1.example.net
    priority: 10      # MX only
```

- The positional record is one name and type; several values are the set of that name and type. `--ttl` (seconds or `auto`), `--priority` and `--proxied` apply to it only and are exit code 2 without one.
- The positional record, `--record` / `-r` (repeatable) and `--file` / `-f` can be combined. What happens to each name is in [What ensure changes](#what-ensure-changes). Records of names you do not give are never touched.
- Names are relative (`www`, `@`, `a.b`) or full names in the zone (`www.example.com`, with or without the trailing dot). A name outside the zone (`www.other.com`) is a usage error.
- TTL (seconds or `auto`) and proxied (`true` / `false`) are optional. Left out, an existing record keeps its value and a new one gets the platform default (Cloudflare: automatic TTL, not proxied). `auto` and `0` mean automatic on Cloudflare; elsewhere `auto` equals leaving the TTL out and `0` is refused.
- Values are compared as the platform stores them (host names, hex and parameter keys without case, no trailing dot, compressed IPv6, TXT and SPF unquoted and joined), so an equivalent value is `unchanged`. What is case sensitive keeps its case: base64 keys and certificates, the `ech`, `dohpath` and `alpn` of HTTPS / SVCB, the regexp of NAPTR.
- Values and priorities are checked as [Record types](#record-types) says: an MX priority in front of the value (`"10 mail.example.com"`, `@:MX:10 mail.example.com`) or in `--priority` / `priority`, needed for a new MX record; SRV values are `<priority> <weight> <port> <target>`.
- Inline, a value ending in `:<number>` or an IPv6 address that could be read with a TTL is refused as ambiguous: use the file.
- `proxied=true` on a platform other than Cloudflare is reported `skipped`; `proxied=false` there is ignored. On a proxied Cloudflare record the TTL is not compared.
- Usage errors (exit code 2), found before the zone is read: unknown fields, a record given twice, an invalid value or type, two CNAMEs of one name, records of types that cannot share a name (see [Record types](#record-types)), `proxied` on types other than A / AAAA / CNAME, `SOA`, and a CNAME at the zone apex on a platform that does not take one there (Route 53, Cloud DNS, GoDaddy, name.com: the apex holds the zone's NS records; write ALIAS / ANAME where the platform has it, or A / AAAA records), which would otherwise fail only after the records it replaces were deleted (one with `proxied: true` is only reported as skipped there, so it is not refused). A type the platform cannot write is exit code 7.
- The zone is always read live, so `--offline` is refused (exit code 6).
- The first failed write stops the run. Run the command again to continue from there. When the write that fails (a create, an update, or a later delete of the same replace) comes after records it replaces were deleted, the error says so, names each deleted record with its type, value and TTL, and prints the `polyctl dns add ...` command that restores it (exit code 1).
- Report rows are `dns-record/<name>/<TYPE>`. An update lists its changed fields (`value a -> b; ttl 300 -> 600`); in JSON, `attrs.changed` holds the old and new `value`, `ttl`, `proxied` and `priority`. A replaced record is a `deleted` row of its own type before the rows of the records that replace it; its `attrs` keep its `value`, `ttl`, `priority` and `proxied`, and `replaced_by` the types that replace it.

#### What ensure changes

For each name it is given. The SOA and NS records of the zone apex are the zone's own: they never count, and a desired `@ NS` record is refused (exit code 2) before the zone is read. Records of other names are never touched.

| The name holds | dns ensure |
| --- | --- |
| no record | creates the record |
| one record of the type | leaves it `unchanged` when it is as desired, else updates it in place (keeping its id; an existing TTL and proxied setting are kept unless given) |
| one record of another type | replaces it: deletes it, then creates the record. On a terminal the record is shown and confirmed first (default no); a script needs `--yes` (exit code 2 without it) |
| a record of the type beside records of other types | updates that record as above and leaves the records of other types alone, unless the type cannot share the name with them (a CNAME): then as in the next row |
| several records of other types, none of the type | on a terminal lists them and asks: replace them all (then confirmed, with the count), keep them and add the record beside them (as `dns add` does; offered when the types can share the name), or cancel. A script stops with exit code 5, with or without `--yes`, and the error lists them: use `dns add` to add the record beside them, or `dns delete` first to replace them. Several records of a name are never deleted without a terminal |
| several records of the type (duplicates) | fine when one is as desired or has the desired value (only its other fields, such as the TTL, are updated); the others are left alone. Otherwise exit code 5, unless `--prune-duplicates` keeps one (the one that matches or has the desired value, else the oldest, which is updated) and deletes the others after the creates and updates, without asking |

- Several records of one name and type in one run form a set: missing values are created, nothing is updated. Records of other types on the name follow the table, with the set in place of the one record.
- A record of another type that belongs to another service of the platform (the CNAME of a Cloudflare R2 custom domain, which the DNS API cannot delete) is never replaced: the run stops before anything is written (exit code 1) and points at `dns add`, or at `dns delete`, which unbinds it. Nor is a record that the `polyctl dns add` command restoring it could not write again (a Route 53 alias record, a record of a Route 53 or Cloud DNS routing policy): change it with the platform's record commands, or delete it first.
- Every name of a run is decided before anything is written: a `--file` with several names stops before the first write when one of them needs `--yes` or a terminal. A no or a cancel writes nothing (exit code 0). A `--dry-run` reports the `would delete` and `would create` rows of a replace, asks no confirmation and needs no `--yes`; a choice between several records is still asked on a terminal (exit code 5 in a script).

### dns delete

```sh
polyctl dns delete example.com www                          # every record of www, when they have one type
polyctl dns delete example.com www A                        # one record, or asks when several match
polyctl dns delete example.com www A 203.0.113.10           # only the record with this value
polyctl dns delete example.com --id 372e67954025e0ba6aaa6d586b9e0b59
polyctl dns delete example.com --all --type TXT --dry-run
```

- Only `<name>` is required. `<type>` and `<value>` narrow the selection and are needed only to tell records apart: a name whose records all have one type is deleted as if that type had been given.
- A name with records of several types is never deleted as a whole. On a terminal its records are listed (type, value, TTL, id) to tick the ones to delete; ticking none deletes nothing (exit code 0). Non-interactive, the command names the types found and exits with code 5 without deleting anything, also with `-y`: give `<type>`. The SOA and NS records of the zone apex are not meant by `@` alone; give `NS` to select the apex NS records.
- `<value>` narrows the match. It is compared as `dns ensure` compares values: host names ignore case and a trailing dot, addresses are compared in canonical form, TXT text with or without its quotes, and an MX value may be `10 mx.example.com` (as `dns list` prints it; the priority must match) or the host alone. `--id` deletes exactly one record by platform id and cannot be combined with a record; an empty `--id` is refused too (exit code 2). An id that names several records (an older GoDaddy id, see [GoDaddy](platforms/godaddy.md#dns-records)) is exit code 5 and deletes nothing.
- A selector that matches several records lists them with their ids, says how many match and how to delete one of them only (its `<value>` after the `<type>`, or `--id <id>`), and asks first (`-y` skips the question). Answering no deletes nothing and exits with code 0 (`nothing to do: no record was deleted; to delete one of them only, ...`).
- Non-interactive: nothing is asked or deleted without `-y`; the command exits with code 2 (`confirmation required: pass --yes to proceed ...`).
- No matching record is exit code 4.
- A record that fails to delete does not stop the others; the command ends with `N of M step(s) failed; first error: ...` (exit code 1).

**`--all`** deletes every record of the zone, for retiring a domain or emptying it before a move.

- `--type` (repeatable or comma-separated, any case) limits it to those types across the zone. Without `--all`, `--type` takes a single type.
- Cannot be combined with a positional record or `--id` (exit code 2).
- Clears only the account the domain routes to. A zone held by several accounts is exit code 5 until `--profile` / `--platform` picks one.
- Never deleted: the SOA and the NS records of the zone apex (reported `skipped`, also with `--type NS`). NS records below the apex (delegations) are deleted. The zone itself stays.
- Records owned by another service (Cloudflare R2 custom domains) are removed by unbinding them; `--keep-bound` skips them instead.
- Interactive: prints a summary per type and asks `delete N records in zone <domain> (y/N)`. Non-interactive: requires `--yes` (exit code 2 otherwise). `--dry-run` needs neither.
- The zone is read live, so `--offline` is refused (exit code 6).
- A record that cannot be deleted is `failed` and the rest continue (exit code 1). Nothing to delete prints `no records to clean up` (exit code 0).
- In JSON, each deleted record keeps its full data in `attrs` (`value`, `ttl`, `priority`, `proxied`), so it can be restored with `polyctl dns add`, one command per record (`dns ensure` would replace a record of another type that the name holds by then); `summary` counts `deleted`, `skipped` and `failed`.

**Cloudflare R2 custom domains.** The CNAME Cloudflare creates for an R2 bucket's custom domain cannot be deleted through the DNS API. `dns delete` (and `cloudflare dns delete`) removes it by unbinding the domain from its bucket; the question and the dry run say so. The bucket is looked up in the zone's account first, then in the other enabled accounts of the same login, then in the other Cloudflare profiles. Without R2 permission, with R2 not enabled or with no bucket named in the record, the record stays and the command fails.

## Domains

```text
polyctl domain info  <domain>
polyctl domain ns get <domain>
polyctl domain ns set <domain> <nameserver>...
polyctl domain ns check <domain> [--resolver <ip>[,<ip>...]] [--timeout 5s] [--no-registrar] [--no-zone]
polyctl domain which <domain>
polyctl domain index
polyctl domain list  [--refresh]
```

All take `--profile` and `--platform`.

- **`domain info`** shows the registrar view (status, expiry, auto-renew, lock, privacy, nameservers) and the DNS zone that serves the domain with its nameservers. Either part may be missing if only one kind of account knows the domain. With `--platform`, a part held on another platform is mentioned on stderr.
- **`domain ns get` / `ns set`** read and write the nameservers **at the registrar** (name.com, GoDaddy, Route 53 Domains, Alibaba Cloud Domains). `ns set` takes at least one nameserver; each argument may be a comma-separated list:

  ```sh
  polyctl domain ns set example.com ns1.example.net ns2.example.net
  ```

  After a change, `ns set` re-indexes the zones of the registrar account (when the registrar also hosts DNS), so a GoDaddy or name.com zone that stops serving the domain no longer takes its routing. When that zone is gone, a note on stderr says so; the zones of other accounts are not re-indexed, so run `polyctl domain index` if the account now serving the domain was never indexed. A failed re-index is a warning; the nameserver change stands.

- **`domain which`** lists every index entry for the domain and its parents: kind (`zone` or `domain`), platform, profile, resource id, index time. Use it when routing surprises you. With `--profile` / `--platform` the list is narrowed; no owner under the selection is exit code 4. Like routing, it first indexes the sets that were marked due (rule 5 below), or with `--refresh` every selected account (rule 4). When the index holds no entry, it indexes the accounts as routing does (rule 6 below), and never asks which owner: every owner is listed.
- **`domain index`** rebuilds the domain index from every domain-capable account (narrowed by `--profile` / `--platform`). **`domain list`** prints the index as it stands, a set marked due included (rule 5 below does not apply: nothing is looked up); `--refresh` re-indexes first. An account that fails to sync during `--refresh` is a warning, the index is still printed as it stands, and the exit code is then 1, or 3 when every failure is a credential or permission one (as for `domain index`). An unknown `--profile` is exit code 4. A selection with no domain-capable account is not an error: empty output, a `nothing to do: ...` note, exit code 0.

### domain ns check

Answers "who serves this domain, and is the delegation in place?" by comparing three sets of nameservers:

| Side | Source |
|------|--------|
| `registrar` | set at the registrar |
| `zone` | assigned to the hosted zone (Cloudflare, Alibaba Cloud DNS, Route 53, Cloud DNS, ...) |
| `live` | what public resolvers return now |

```sh
polyctl domain ns check example.com
polyctl domain ns check www.example.com -o json
polyctl domain ns check example.com --resolver 223.5.5.5,114.114.114.114
```

- A subdomain is checked as its registered domain (`www.example.com` → `example.com`; `example.co.uk` stays itself). Internationalized names are checked in punycode. A URL, a name with a port, or a name without a registered domain (`localhost`, an IP, `co.uk`) is a usage error (exit code 2).
- `--resolver`: IP or IP:port, comma-separated or repeated (default `1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4`, or `dns.resolvers`). The system resolver is never used. `--timeout` per query (default `5s`, or `dns.timeout`).
- Registrar and zone sides are read live. The sets that were marked due are indexed first, as routing does ([rule 5](#routing-rules)), so a second zone of the name in an account covered since then is listed; the index is refreshed if it has no entry (or with `--refresh`). Every hosted zone is listed in `zones` with `live_match` (`equal`, `partial`, `none`); the one the live nameservers point to is compared. Private zones are left out.
- `--no-registrar` / `--no-zone` skip a side (not both).
- `status`:
  - `ok`: live equals the zone (and the registrar, when known)
  - `partial`: some overlap, or the registrar lists others
  - `mismatch`: no overlap
  - `no-zone`: no account hosts the domain
  - `no-live`: resolvers return NXDOMAIN, NODATA or SERVFAIL (SERVFAIL comes with a DNSSEC / DS hint)
  - `unknown`: a needed side was skipped or unreadable
- JSON also has `match` (pairwise comparisons), `provider_guess` (`cloudflare`, `aliyun`, `aws`, `gcp`, `mixed`, `unknown`; a hint), `message` (what to do) and, for an unavailable side, `available: false` with a `reason`.
- It is a report: every status exits with code 0, so scripts read `status` from `-o json`. Exit code 1 only when every requested side failed (the report is still printed; 3 instead when one of those failures is a credential or permission error), 3 when the selected accounts cannot authenticate, 4 when `--platform` holds the domain neither as registration nor as zone, 7 when that platform cannot read the requested sides, 6 under `--offline`.

## Certificates

```text
polyctl cert ensure <domain> [--days 30] [--force] [--staging] [--email <addr>] [--agree-tos]
                             [--key-type ec256|ec384|rsa2048|rsa4096] [--timeout 15m]
                             [--profile <name>] [--platform <platform>]
polyctl cert get    <domain> [--print fullchain|cert|chain|privkey] [--staging]
polyctl cert deploy (<domain> | --all) [--days 30] [--force] [--region <r>]... [--deployer <id>]...
                             [--prune-expired] [--no-wait] [--timeout 10m] [--issue-timeout 15m]
                             [--email <addr>] [--agree-tos]
                             [--profile <name>] [--platform <platform>]
```

`cert ensure` keeps a Let's Encrypt certificate for a domain and its wildcard in the local store; `cert get` shows it; `cert deploy` puts it on cloud load balancers and certificate stores. Run it daily from cron:

```sh
polyctl cert ensure example.com            # issues when missing, renews at 30 days left or fewer, else does nothing
polyctl cert ensure example.com --dry-run  # what it would do, writing nothing
polyctl cert get www.example.com --print fullchain > fullchain.pem
polyctl cert get example.com --print privkey > privkey.pem && chmod 600 privkey.pem
```

### cert ensure

- **Names.** Every certificate covers a root domain and its wildcard (`example.com` and `*.example.com`). `www.example.com`, `*.example.com` and `example.com` all mean the certificate of `example.com`. The root is the registered domain (`a.b.example.co.uk` → `example.co.uk`). A name without a registered domain (`com`, `localhost`, an IP) is exit code 2.
- **When it issues.** Nothing happens (`unchanged`) while the certificate has more than `--days` whole days left (default `cert.renew_days`, 30), holds both names and has the `--key-type` key (default `cert.key_type`, `ec256`). Otherwise it is issued (`created`) or renewed (`updated`). `--force` always renews; mind the CA's rate limits.
- **Validation (DNS-01).** polyctl writes TXT records `_acme-challenge.<root>` in the zone the root domain routes to, so no separate DNS credentials are needed. No hosting account is exit code 4; several are exit code 5 until `--profile` / `--platform` or `cert.dns_accounts` picks one (`cert.dns_accounts: {example.com: cloudflare/main}`, value `profile` or `platform/profile`; `--profile` / `--platform` win over it). It warns when the public nameservers do not match the hosting zone, and refuses a CNAME at `_acme-challenge.<root>` (delegated validation is not supported). Its own records are deleted afterwards and listed in `challenges/<root>.json` until they are; the next run deletes what an interrupted one left there. Other `_acme-challenge.<root>` TXT records (another ACME client validating the domain, or records older polyctl versions left) are kept with a note: the CA needs one matching value only.
- **Propagation.** The CA is asked to validate once `cert.dns.min_resolvers` (default 2) of `cert.dns.resolvers` (default `1.1.1.1`, `8.8.8.8`, `223.5.5.5`, `114.114.114.114`) see the record, checked every `poll_interval` (10s) for up to `propagation_timeout` (5m), plus `settle_delay` (20s). `-v` shows each resolver's answer.
- **ACME account.** The first issuance needs an e-mail (`--email` or `cert.email`) and agreement to the CA's terms (`--agree-tos` or `cert.agree_tos: true`). Interactive runs ask for what is missing; non-interactive runs fail with exit code 2 before writing anything. When the CA no longer knows the stored account key (a reset staging CA), the run registers the same key again and saves the new account URI; that also needs the agreement to the terms, asked before the per-domain lock is taken. A deactivated account is different: the CA refuses its key for good (RFC 8555 section 7.3.6), so the run fails until its directory under `accounts/` is removed; the next run then registers a new account.
- **Private keys.** Each issuance gets a new key; `cert.reuse_key: true` keeps the current one.
- **Failures** are never retried automatically. The error includes the CA's detail and, on a rate limit, its `Retry-After`. Exit code 1, 3 when the DNS account's credentials are rejected, 7 when its platform cannot write TXT records. Failures are sent to `hooks.on_failure` as `{"event": "cert.ensure.failed", "domain", "error", "time"}`.
- `--timeout` (default 15m) bounds the whole run, including waiting for the per-domain lock held by another run.
- `--dry-run` checks routing, nameservers and the challenge name and reports `would create` / `would update`; it writes nothing. `--offline` is exit code 6 when a certificate would have to be issued.
- `--staging` uses the Let's Encrypt staging CA (untrusted certificates, for testing) with a separate store; it cannot be combined with a custom `cert.acme_directory`.
- Report rows: `acme-account/<ca>` and `cert/<root>` (`names=... not_after=YYYY-MM-DD days_left=N`). Issued certificates also appear in `inventory list --type certificate` (platform `local`).

### cert get

Reads the store only: names, subject, issuer, serial, validity, days left, key type, SHA-256 fingerprint and directory. It never shows the private key unless `--print privkey` writes it to stdout. `--print` writes one PEM file (`fullchain`, `cert`, `chain`, `privkey`). No certificate is exit code 4.

### The certificate store

`cert.dir` (default `<config dir>/certs`) uses certbot's `live/<domain>/` layout. To move a certbot certificate in, copy its `fullchain.pem` and `privkey.pem` into `live/<root>/`.

```text
<cert.dir>/                          0700
  accounts/<CA host>/<id>/           account.key (0600), account.json
  live/<root>/                       fullchain.pem  cert.pem  chain.pem  privkey.pem (0600, PKCS#8)  meta.json
  archive/<root>/<UTC time>/         the last 3 previous bundles
  pending/<root>/                    privkey.pem of an issuance in progress, and fullchain.pem once issued, until installed
  locks/<root>.lock
  challenges/<root>.json             challenge records written and not deleted yet (0600)
  history.log                        one JSON line per certificate created, updated or deployed
  ca/<host>/...                      store of any other CA (staging)
```

Replacements are atomic: the new bundle is written to `live/.<root>.staging-<pid>/`, the current one moved to the archive, and the staging directory renamed to `live/<root>/` (on Windows a rename blocked by another process, such as an antivirus scan, is tried again for about a second). A certificate the CA issued is kept in `pending/<root>/` until it is installed: when installing fails, the next `cert ensure` installs it without ordering another one (unless `--force`, or it no longer has more than `--days` days left), which spares the CA's duplicate-certificate limit. When a run was interrupted between the two renames, the next `cert ensure` restores `live/<root>/` from the complete staging directory (the new certificate, then recorded in `history.log` and the inventory and reported as `created` or `updated`), else from the newest archived bundle, and removes staging directories left by interrupted runs. A private key readable by others is reported and fixed to `0600` by `cert ensure`.

## Deploying certificates

`cert deploy` finds, live, every place in your cloud accounts that serves a certificate and puts the store's certificate on those that need it. It renews the local certificate first when needed. The first certificate registers the ACME account: pass `--email` and `--agree-tos` once, or set `cert.email` and `cert.agree_tos: true` for cron. On a terminal the missing one is asked for, once per run (declining the terms or leaving the e-mail prompt skips the targets of every root domain that needs the account); in the non-interactive flow each root domain that needs the account fails (exit code 1).

```cron
17 3 * * *  /usr/local/bin/polyctl cert deploy --all --prune-expired --yes -o json >> /var/log/polyctl-cert.log 2>&1
```

cron has a minimal environment: set `PATH` and `HOME` (or `POLYCTL_CONFIG_DIR`), and use `credential_store: file` when no login keyring is available.

```sh
polyctl cert deploy example.com                       # every target of example.com without the current certificate
polyctl cert deploy example.com --dry-run -o json
polyctl cert deploy --all --platform aliyun --profile acme --deployer aliyun-alb --dry-run
polyctl cert deploy example.com --deployer gcp-lb --region asia-east2
```

**Deployers** (`--deployer`, repeatable; default all):

| Deployer | Targets | Notes |
|----------|---------|-------|
| `aliyun-alb` | HTTPS listeners of Alibaba Cloud ALB (default certificate) | Uploads to the region's CAS store as `cert.name_template` (default `upload_<root>_<YYYY-MM-DD of expiry>`) and waits for each listener to be `Running` again. Stopped listeners and SNI certificates are left alone. A region named with `--region` or `cert.aliyun.regions` whose ALB endpoint does not resolve (a typo such as `cn-hongkongg`) fails the account; the profile region without ALB is only a warning. |
| `gcp-lb` | Target HTTPS proxies of global and regional forwarding rules | Creates `cert-<root with hyphens>-<YYYYMMDD>` and deletes the old self-managed certificate. When a proxy holds an RSA and an ECDSA certificate of the same names, only the one of the store's key type (`cert.key_type`) is replaced; the other is kept and reported `skipped`. A lone certificate of another key type is replaced, and the row says the key type changes. Google-managed certificates and certificate maps are `skipped`. |
| `aws-acm` | Imported ACM certificates | Re-imports under the same ARN, so load balancers and CloudFront need no change. A different key type (or a re-import ACM refuses) is imported as a new certificate (tag `polyctl:domain=<root>`): set the new ARN where the old one was used. Later runs find the new certificate (by its serial number, or after a renewal as the unexpired imported certificate of the new key type that serves every name of the old one, which the run re-imports in place) and report the old one `skipped` (with a warning while something still uses it) instead of importing again; delete the old certificate once nothing uses it (`--prune-expired` does once it expired). Amazon-issued certificates are `skipped`. Never imports a certificate for the first time (use `aws acm certificate import`). |

**Options**

- `--all`: update targets with `--days` whole days left or fewer (default `cert.renew_days`, 30). `<domain>`: update every target of that root domain that does not hold the store's current certificate, whatever its expiry. `--force`: every matching target.
- A target whose current certificate holds a name the store's certificate does not cover (a deeper subdomain such as `api.staging.example.com`, or another root domain in its SAN) is `skipped`, even with `--force`: it needs a certificate of its own.
- The local certificate is ensured with `--days` + 5 before deploying. A root domain no DNS account hosts and the store holds no certificate of is `skipped` (managed elsewhere). When the store does hold one but no DNS account hosts the domain any more, it cannot be renewed: an unexpired certificate is still deployed, with a warning on the `cert/<root>` row and a `cert.deploy.failed` notification; an expired one fails the domain (exit code 1).
- DNS account: the renewal routes the root domain among every account; `--profile` and `--platform` do not apply to it. When several accounts host the zone, an interactive run asks and a non-interactive one fails the domain; name one in `cert.dns_accounts` (`{example.com: cloudflare/main}`). A root domain whose `cert.dns_accounts` account does not host its zone fails (it is not skipped as managed elsewhere).
- Accounts: every account with a deployer, narrowed by `--profile`, `--platform` and `--deployer`. `cert.skip_accounts` leaves out a profile (`name`) or one deployer of it (`name:aliyun-alb`).
- Regions: `--region` (repeatable) replaces `cert.aws.regions` / `cert.aliyun.regions` (default: the profile's region; CloudFront certificates are in `us-east-1`, list it). GCP scans every region unless `--region` is given (`global` for global proxies).
- `--no-wait` returns once a change is requested (`--wait` is the default). `--timeout` (default 10m) bounds each wait.
- `--issue-timeout` (default 15m) bounds ensuring the certificate of each root domain, including waiting for the per-domain lock held by another run; a domain that does not finish in time fails (exit code 1, `hooks.on_failure`) and the run goes on.
- `--prune-expired` also deletes expired certificates nothing uses. It asks once (default no); non-interactive runs need `--yes`.
- `--dry-run` does every read and reports `would create` / `would update` / `would delete`. `--offline` is exit code 6.

**Failures** are handled per target and the run goes on. Each is sent to `hooks.on_failure` as `{"event": "cert.deploy.failed", "platform", "profile", "deployer", "target", "domain", "error", "time"}`. Exit code 1 when anything failed, 3 when every failure was a credential or permission error, 0 otherwise (no targets at all is 0). Nothing is rolled back; the next run finishes the job.

**Report rows**: `<deployer>/<profile>/<target>` (for example `aliyun-alb/acme/lb-example(HTTPS:443)`, `gcp-lb/acme/acme-prod/global/proxy-web`, `aws-acm/acme/us-east-1/<arn>`). A `gcp-lb` target starts with its project: the deployer covers every enabled project of the account ([GCP: Projects](platforms/gcp.md#projects)); before 0.4.0 the target had no project part. Each JSON row's `attrs` holds `deployer`, `platform`, `profile`, `region`, `domain`, `old_cert_id`, `old_days_left`, `new_not_after` and `cert_name`.

## Finding resources by IP or DNS name

```text
polyctl find <ip|dns-name> [--platform <p>[,<p>...]] [--profile <name>] [--detail]
                           [--refresh | --offline] [-o table|json|yaml]
```

```text
$ polyctl find 203.0.113.10
PLATFORM  PROFILE  TYPE           NAME      REGION/ZONE   INTERNAL    EXTERNAL      STATE    NETWORK
gcp       acme     instance       web-1     asia-east1-a  10.140.0.5  203.0.113.10  RUNNING  default
gcp       acme     load_balancer  fr-web-1  asia-east1    -           203.0.113.10  -        -
matched 2 resource(s) (local inventory, synced 4m ago)
```

- The argument is an IPv4 / IPv6 address or a DNS name (load balancer, instance public or private name, database endpoint). Anything else is exit code 2.
- Searches `instance`, `load_balancer`, `eip` and `db_instance` of every account on AWS, GCP and Alibaba Cloud. Every address counts: all network interfaces, secondary and alias addresses, IPv6 prefixes, public and elastic addresses, load balancer addresses.
- **Reads the local inventory only** and never syncs on its own. `--refresh` syncs those four types for the selected accounts first (`find.concurrency` accounts at a time). `--offline` cannot be combined with `--refresh` or `--detail`.
- Several matches are normal (the same private address exists in many networks): all are listed, exit code 0.
- `--detail` looks up each matched instance's VPC and subnet on its platform (each within `find.detail_timeout`). The table shows console links with `-v` or `--detail`.
- Nothing found is exit code 4; the message tells you to run `polyctl find <query> --refresh` or `polyctl sync --type instance,load_balancer,eip,db_instance`. Stale results are shown with a note on stderr.
- With `--refresh`, an account that cannot be synced is listed in `errors` and the others are still searched. Exit code 1 only when every account fails and nothing matches.

Platform coverage:

- **AWS**: EC2 instances, ELBv2 load balancers, elastic IPs and unattached network interfaces (NAT gateways, ...), RDS instances. Every enabled region is synced.
- **GCP**: instances, forwarding rules (regional and global), reserved addresses, of every enabled project of an account. JSON matches carry `project`, and the console link opens the resource in its own project.
- **Alibaba Cloud**: ECS instances, ALB load balancers, EIPs. Every region is synced; a failing region is reported and the others are kept.

`-o json` fields: `query`, `kind` (`ip` / `dns`), `cached`, `synced_at`, `matches`, `errors` and, when there is one, `hint`. Each match has `platform`, `profile`, `type`, `id`, `name`, `region`, `zone`, `state`, `matched_field`, `internal_ips`, `external_ips`, `network`, `url` and, where they apply, `project` (GCP), `dns_names`, `subnet`, `note`, `addresses` and `detail`.

## Routing rules

1. Without `--profile` / `--platform`, every account is searched. Each flag narrows the search; together they name one account.
2. polyctl looks up the domain and its parents (`a.b.example.com`, `b.example.com`, `example.com`) in the domain index, for the kind the command needs (`zone` for `dns`, `domain` for registrar operations). **The longest match wins**, so a delegated sub-zone beats its parent. Index rows of accounts no longer in the config (kept by `auth logout --keep-inventory`, or left by a hand edit) are ignored, here and everywhere the index is read: the domain and nameserver pickers, `domain which`, `domain list` and shell completion leave them out. `inventory list` still shows them.
3. A match held by several accounts is exit code 5. The error lists the candidates as `platform/profile` and names the flag that tells them apart. Two zones of one account holding the same name are as ambiguous: for GCP, where one account spans several projects, the candidates show the zone ids (`<project>/<managed zone>`) and the error points to `polyctl gcp dns ... --project <id>`; for Cloudflare, where one login works on several accounts and two of them can hold a zone of one domain (active in one, pending in the other), the candidates show the zone ids and the error points to `polyctl cloudflare ... --account <id or name>`. On a terminal polyctl asks which owner is meant instead.
4. `--refresh` re-indexes the selected accounts before the lookup (once per run), so a zone moved to another account or deleted is not routed to its old owner. Without it, a match in the index is used as is, with the one exception of rule 5.
5. A set that polyctl itself marked due is indexed before the lookup, without `--refresh`: the zones (or registered domains, for registrar operations) of each selected account whose cached set was marked due by an upgrade that widened what its account covers, by a login that changed what it covers, or by `gcp project enable` / `use` and `cloudflare account enable`, or a `use` that enables its account again ([GCP](platforms/gcp.md#projects), [Cloudflare](platforms/cloudflare.md#accounts)). Only those accounts are asked, each once per run, and a sync that reads everything the account covers clears the mark, so this happens once. A zone such an account covers since then is found, and a name it holds a second time is ambiguous (rule 3) instead of going to the zone indexed earlier. A set whose TTL merely passed is not indexed by a lookup. An account that fails here is a warning on stderr and stays marked for the next run; the lookup goes on with the index as it stands. That holds for an account of which only one project (GCP) or one account of the login (Cloudflare) failed: what the others returned is stored, the mark stays, and the next run asks again.
6. No match: polyctl indexes the accounts automatically the first time (no candidate account was ever indexed), then retries. Otherwise: "domain not found in local index" (exit code 4); run `polyctl domain index` or pass `--refresh`. When indexing (automatic, of the sets marked due, or `--refresh`) could sync none of the accounts it asked and the domain is still not found, the error is that failure, not exit code 4: exit code 3 when every account failed for credentials or permissions, 1 otherwise. `cert deploy` then fails the domain instead of skipping it as managed elsewhere.
7. With `--offline` nothing is indexed, a set marked due included: its rows are used as they are, and an unknown domain is an error.
8. An unknown `--profile`, or a `--profile` / `--platform` pair with no suitable account, is exit code 4.

A registrar (name.com, GoDaddy) indexes a domain it holds as a zone only while it serves the domain's DNS: a domain whose nameservers point elsewhere (to Cloudflare, say), or a cancelled or expired GoDaddy domain, is not a second owner. The usual ambiguity is the same zone in two accounts, for example in the Cloudflare accounts of the profiles `acme` and `acme-old`; pass the flag the error names:

```text
$ polyctl dns list example.com
error: ambiguous owner of zone "example.com": candidates are [cloudflare/acme (zone 9a1...) cloudflare/acme-old (zone 4c2...)]; pass --profile <name> to choose

$ polyctl dns list example.com --profile acme
zone example.com via cloudflare/acme
...
```

Registrar commands (`domain ns ...`) look the domain up as a `domain`, not a `zone`, so a domain registered at one platform and served by another has one owner for each. Two resources with the same name in one account (two Route 53 hosted zones called `example.com`) cannot be told apart this way; use the platform's own command with the resource id.

**Resources addressed by name or id** (instances, load balancers, ...) are found the same way, so you do not need to name the profile. An id match wins over a name match. Several matches are exit code 5 (pass `--profile`, `--platform`, or the id). No match syncs that resource type once for accounts with a missing or expired cache, then reports not found (exit code 4). A name found in the cache only tells the account and region: the name is then looked up live there, so a resource renamed since the last sync is never acted on in place of the one that holds the name now.

`find` does not follow these rules: it lists every match instead of choosing one.

## Platform-specific commands

Each platform has its own subtree: `cloudflare` (alias `cf`), `namecom`, `godaddy`, `aws`, `gcp`, `aliyun`. The commands and flags of each are on its page: [Cloudflare](platforms/cloudflare.md), [name.com](platforms/namecom.md), [GoDaddy](platforms/godaddy.md), [AWS](platforms/aws.md), [GCP](platforms/gcp.md), [Alibaba Cloud](platforms/aliyun.md).

- **Account**: `--profile` (it must have an account on that platform, otherwise exit code 3) > `current_profile` (if it has one) > the only profile that has one > an error listing the candidates (exit code 5).
- **Cache**: list commands honour `--refresh` / `--offline` as the neutral commands do; writes always go to the platform.
- **`<platform> whoami`** checks the credentials against the platform and prints `profile`, `platform` and `identity` (`account`, `user`, `extra`). On GCP `account` is the default project and on Cloudflare the default account; `extra.disabled_projects` / `extra.disabled_accounts` hold the ids of the disabled ones, comma-separated, when there are any. It needs the network (exit code 6 with `--offline`); credentials that no longer work are exit code 3.

The same operation has the same verb and shape on every platform:

| Kind | Commands |
| --- | --- |
| Registrar groups | `list`, `get <domain>`, `ns get <domain>`, `ns set <domain> <nameserver>...` |
| Records with an id (Cloudflare, name.com, Alibaba Cloud) | `create`, `update <zone> [<name> [<type> [<value>]]]`, `delete <zone> [<name> [<type> [<value>]]]` (`<domain>` on name.com and Alibaba Cloud): the record is found by name, `<type>` and `<value>` only tell records apart (on Alibaba Cloud also the line), and `--id <record-id>` names one exactly (the former `<zone> <record-id>` still works) |
| Record sets by name and type (Route 53, Cloud DNS, GoDaddy) | `upsert` sets the whole record set. `delete <zone> [<name> [<type>]]` on Route 53 deletes a record set (`--set-identifier` tells routing-policy sets apart; there is no `--id`); `delete <zone> [<name> [<type> [<value>]]]` on Cloud DNS deletes a record set or one value of it; `delete <domain> [<name> [<type> [<value>]]]` on GoDaddy deletes records as the platforms with record ids do. `<type>` is needed only for a name with records of several types, and `--id` (Cloud DNS, GoDaddy) names one record exactly |
| Compute services | `<service> instance list\|start\|stop ...` |

- **`create`** makes one new resource and fails when it exists. **`set` / `upsert`** set one object (the nameservers of a domain, a zone setting, a record set) and never create anything else.
- **`ensure`** converges a group of related resources: it reads what exists, changes only what differs, reports `unchanged` for what matches, and never deletes resources it was not told about (`dns ensure` replaces records of other types on a name it is given, as [What ensure changes](#what-ensure-changes) says). Any command that creates dependencies you did not name one by one (a VPC, a security group, a certificate, a listener) is an `ensure` command. Exit code 0 includes "everything was unchanged". It prints a [change report](configuration.md#dry-runs-and-change-reports).
- **Waiting**: asynchronous changes take `--wait` (wait until the change has completed; the default of `ensure` commands and of every `instance create`), `--no-wait` (return once the change was requested; accepted by every command that has `--wait`) and `--timeout <duration>` (upper bound of the wait, default `10m`). A wait that runs out of time is exit code 1 and names the resource and its last status.
