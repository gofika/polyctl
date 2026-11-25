# GCP

Commands under `polyctl gcp`: Cloud DNS, Compute Engine instances, firewall rules, networks, SSL certificates and load balancers.

- [Login and permissions](#login-and-permissions)
- [Projects](#projects)
- [Common behaviour](#common-behaviour)
- [Command summary](#command-summary)
- [Cloud DNS](#cloud-dns)
- [Instances](#instances)
- [Firewall rules](#firewall-rules)
- [Networks and subnetworks](#networks-and-subnetworks)
- [SSL certificates](#ssl-certificates)
- [Load balancers](#load-balancers)

## Login and permissions

```sh
polyctl auth login gcp --profile acme                                             # browser login, gcloud not needed
polyctl auth login gcp --profile ci --set method=service_account --set key_file=./sa.json
polyctl auth login gcp --profile adc --set method=adc --set project=acme-prod     # Application Default Credentials
polyctl auth login gcp --profile adc --set project=acme-prod --set projects=acme-prod,acme-dns   # several projects
polyctl auth login gcp --profile me --set method=oauth --set client_id=<id> --set client_secret=-
```

- `method` is `oauth` (default on a terminal: consent in the browser with polyctl's built-in OAuth client, or your own with `client_id` / `client_secret`; refresh token stored), `service_account` (JSON key file, stored in the credential store) or `adc` (default without a terminal: Application Default Credentials from `gcloud auth application-default login`). Details, including what the consent screen shows and builds without a built-in client, in [Accounts](../accounts.md#gcp).
- One account works on several projects ([Projects](#projects)). On a terminal the login lists the visible projects for ticking (what was selected before is ticked; a first login ticks one project at most) and, when several are ticked, asks which one is the default. `--set project=` is the default project and `--set projects=a,b,c` the selected ones; non-interactively, without them, the default is the previous login's project, then the ADC project, then the only visible project, and the selection of the previous login is kept.
- `polyctl gcp whoami` checks the credentials and shows the default project, the selected projects, the account and the login method. `gcp project list` / `gcp project current` show the projects.
- The Compute Engine API must be enabled in a project whose Compute Engine resources are used. A disabled API or a missing permission (`compute.instances.*`, `compute.addresses.*`, `compute.firewalls.*`, `compute.sslCertificates.*`, `compute.targetHttpsProxies.setSslCertificates`, ...) is exit code 3 and names what is missing.

See [Accounts](../accounts.md) for profiles and all login options.

## Projects

One GCP account of a profile works on the projects **selected** for it. One of them is the **default project**.

| | Covers |
| --- | --- |
| Inventory sync (`polyctl sync`, automatic refreshes), `find`, `inventory list` | every selected project |
| Looking up a resource by name (instance, load balancer and its components, firewall rule, certificate, network, managed zone) | every selected project |
| Domain routing of the platform-neutral `dns` commands, `cert deploy` | every selected project |
| List commands (`instance list`, `firewall list`, `dns zone list`, ...) | every selected project; each row names its project |
| Creating a resource (`instance create`, `firewall create` / `ensure`, `ssl-certificate create`) | the default project |
| A command that takes an instance (`load-balancer ensure <instance>`, `firewall ensure --instance`) | the project of the instance |

```sh
polyctl gcp project list                      # visible projects; SELECTED marks the selection, * the default
polyctl gcp project current                   # the default project and the selection
polyctl gcp project use acme-dns              # make it the default (selects it if needed)
polyctl gcp project add acme-dns acme-lab     # select more projects
polyctl gcp project remove acme-lab           # take a project out of the selection
polyctl gcp project remove acme-prod --default acme-dns   # removing the default names its successor
```

- The login selects the projects (see [Login and permissions](#login-and-permissions)); `use`, `add` and `remove` change the selection without a new login. An account logged in before the selection existed has exactly its one project selected and works as before.
- `use` and `add` check that the credentials reach a project before they select it (Cloud DNS, Compute Engine or Resource Manager; exit code 3 otherwise; not checked with `--offline`, and `use` of a project that is selected already checks nothing). On a terminal, without an argument `use` offers the visible projects and `add` those of them that are not selected yet (tick several); listing them needs the network (`--offline` is exit code 6). `add` of projects that are all selected already is exit code 0 (nothing to do).
- `remove` changes nothing in Google Cloud. It drops what the inventory cached of the project (stored instance passwords stay) and works with `--offline`. A project that is not selected is exit code 4. Removing the default project needs `--default <id>`, naming a project that stays selected (exit code 2 without it, also when only one project stays; on a terminal it is asked, and the only project that stays becomes the default without a question); removing every project is exit code 2 (use `polyctl auth logout gcp`). No confirmation is asked.
- `use`, `add` and `remove` change `config.yaml` only and do not support `--dry-run` (exit code 2). The cached inventory of the account is synced again on its next use.
- A new login that changes the selection does the same to the cache: what was cached of the projects that left the selection is dropped at once (stored instance passwords stay) and the cached inventory of the account is synced again on its next use. Whatever changed the selection (also an edited `config.yaml`), the `gcp` commands never find or change a resource through a cached row of a project that is no longer selected; `--project` still reaches it.
- A selected project in which the API of a type is not enabled, or whose billing is off, counts as holding nothing of that type (a DNS-only project does not fail the instance sync), also when it is the only project of the account: syncs and lists skip it with exit code 0, and one note per run on stderr names the skipped projects and `polyctl gcp project remove <id>`, which stops asking them. A list or lookup read live from the project of `--project` keeps the error (exit code 3). Any other failure of one project (a removed permission) is reported as a warning naming `polyctl gcp project remove <id>`; the rows cached for that project are kept, the other projects are synced, and the set is synced again on its next use. When every selected project fails, the sync fails and replaces nothing.

**`--project <id>`** on every `gcp dns` and `gcp compute` command names the project of that one call:

- Lookups and lists read only that project; a create goes to it instead of the default project.
- The project need not be selected: a project outside the selection is read live and nothing of it is written to the inventory (so `--offline` cannot serve it, the pick lists of the interactive flow, which read the inventory, do not offer its instances, and a load balancer there is found by its URL map name, not by a forwarding rule name).
- A zone id names its project: `--project` with a zone id of another project (`gcp dns record list acme-dns/example-zone --project acme-prod`) is exit code 2, and nothing is read or written.
- A value that cannot be a project id (empty, or with a slash, comma or space) is exit code 2. `gcp project ...` and the platform-neutral commands do not take the flag.

**Ids.** A managed zone id is `<project>/<managed zone>` (`acme-prod/example-zone`), a DNS record id starts with it (`acme-prod/example-zone|A|www.example.com|203.0.113.10`), and a certificate's inventory id is `<project>/<region or global>/<name>`. Instance, forwarding rule and address ids are the numeric ids of Compute Engine. Where a command takes a zone or a record id, a bare managed zone name (`example-zone`, `example-zone|A|...`) is still accepted and means the zone of that name: in the project of `--project` when given, else in the selected projects. A record id with a bare zone name given to `gcp dns record delete <zone> --id` is of the project of `<zone>`.

**The same name in several projects** (or zones, regions, accounts):

- On a terminal polyctl asks which one this call means. The list shows the project and the zone or region of each candidate, and what else tells them apart (id, status, addresses, DNS name).
- In the non-interactive flow the command fails with exit code 5. The error lists every candidate as `gcp/<profile> project <project> <zone or region> (<id>, <status>)` and names the flags that choose among them, only those whose value differs: `--profile`, `--project`, and `--zone` (or `--region` / `--global`), plus the numeric id or the zone id where there is one.
- Read-only commands that answer for every owner (`domain which`, `find`, the lists) ask nothing and report all of them.

**Upgrading.** Rows cached by a polyctl older than the project selection did not carry their project. The first run of this version drops the cached GCP rows once (stored instance passwords are kept) and the next command that needs them syncs them again; with `--offline` right after the upgrade, GCP data is "not in the local inventory" until one online run. `config.yaml` and the credential store are unchanged, and an older polyctl still reads them (it sees the default project only). Should an older polyctl sync into the same directory again, run `polyctl sync --platform gcp` with the new one afterwards.

## Common behaviour

- Profile selection: `--profile` (must have a GCP account, else exit code 3) > `current_profile` (if it has a GCP account) > the only profile with one > exit code 5 listing the candidates. A `--profile` with no GCP account is exit code 7 for the network and subnet commands.
- List commands honour `--refresh` / `--offline`; writes always go to the platform. Commands that read live need the network (`--offline` is exit code 6).
- Writes print a change report and support `--dry-run` (reads run, nothing is written). See [Configuration](../configuration.md).
- Asynchronous writes wait by default; `--no-wait` returns once the change is requested, `--timeout` (default `10m`) bounds each wait. Running out of time is exit code 1.
- Destructive commands ask for confirmation (default no). `--yes` skips it and is required in the non-interactive flow (otherwise exit code 2). A declined confirmation is exit code 0. See [Interactive use](../interactive.md).
- `ensure` commands are idempotent: they change only what differs, report `unchanged` otherwise, and never delete.
- Names of Compute Engine resources: a lower-case letter first, then lower-case letters, digits and hyphens, at most 63 characters (otherwise exit code 2).
- Quota and capacity errors (`QUOTA_EXCEEDED`, `ZONE_RESOURCE_POOL_EXHAUSTED`) are exit code 1 with a hint to try another zone or machine type. Quota and rate limit errors of the other APIs (a Cloud DNS managed zone that holds its maximum of records answers 403 `quotaExceeded`) are exit code 1 too, not 3: they are not a credentials problem.
- Failures of `firewall ensure` and `load-balancer ensure` are also sent to `hooks.on_failure` (`gcp.compute.firewall.ensure.failed`, `gcp.compute.load-balancer.ensure.failed`).
- Lists across every zone and region (instances, addresses, forwarding rules, certificates, load balancer components) ask the API for partial results. A zone or region the API cannot reach is reported as a failure of `<project>/<zone or region>`: a sync keeps that scope's inventory rows from the previous sync instead of dropping them (when the global scope of a project cannot be reached, the sync of that type fails for the project and keeps all its rows), list commands print a warning naming the scopes, and lookups that must see every scope (subnetworks, URL maps, the proxies using a certificate, `cert deploy` targets) fail with exit code 1.
- Every command works on the selected projects of the account, or on the project of `--project`; see [Projects](#projects). Rows and change reports name the project (`project` in JSON, a PROJECT column in tables, `target.project` in reports).
- Inventory types: `zone`, `dns_record`, `instance`, `load_balancer`, `eip` (static addresses), `certificate`. Firewall rules, networks and subnetworks are always read live.

## Command summary

```text
gcp whoami
gcp project list | current
gcp project use <project-id> | add <project-id>... | remove <project-id>... [--default <project-id>]

# every gcp dns and gcp compute command also takes --project <id>
gcp dns zone list | get <zone>
gcp dns record list <zone> [--type] [--name]
gcp dns record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300] [--priority <n>]
gcp dns record delete <zone> (--type A --name www [--value <v>] [--priority <n>] | --id <project/zone|TYPE|name|value>) [--yes]

gcp compute instance list
gcp compute instance get <name|id> [--zone <z>] [--field external-ip|internal-ip|status|zone|machine-type]
gcp compute instance start|stop <name|id> [--zone <z>] [--wait] [--timeout 10m]
gcp compute instance create <name> [flags]                      # see Instances
gcp compute instance delete <name|id> [--zone <z>] [--release-ips] [--wait] [--timeout 10m]   # alias: terminate
gcp compute instance resize <name|id> --machine-type <type|size> [--zone <z>] [--start[=false]] [--wait-port <n>] [--timeout 10m]
gcp compute instance reboot <name|id|ip> [--zone <z>] [--wait] [--timeout 3m]
gcp compute instance update <name|id> --ip-forward[=false] [--zone <z>]
gcp compute instance password <name|id> [--zone <z>] [--reset [--user <name>] [--password-timeout 10m]]
gcp compute instance ssh-key list|add|remove <name|id> ...     # see Instances

gcp compute firewall list [--network <n>] | get <name>
gcp compute firewall create <name> --allow <proto[:ports]>... (--source-range <cidr>... | --direction egress --destination-range <cidr>...) [...]
gcp compute firewall update <name> [--allow ...] [--source-range ... | --add-source-range ...] [--destination-range ...] [--target-tag ...] [--description ...] [--priority ...]
gcp compute firewall delete <name>
gcp compute firewall ensure [<name>] (--preset lb-health-check | --allow ... --source-range ...) [...]

gcp compute network list | get <name>
gcp compute subnet list [--network <n>] [--region <r>] [--proxy-only]

gcp compute ssl-certificate list [--global | --region <r>] [--expiring-in <days>]
gcp compute ssl-certificate create <name> --cert-file <pem> --key-file <pem> (--global | --region <r>) [--description <text>]
gcp compute ssl-certificate update <name> --cert-file <pem> --key-file <pem> (--global | --region <r>) [--keep-old]
gcp compute ssl-certificate delete <name> (--global | --region <r>)

gcp compute load-balancer ensure <instance> --protocol http|https|tcp [...]
gcp compute load-balancer cert set <lb> --domain <d> [--cert-file <pem> --key-file <pem>] [--days 30] [--new-ip] [--keep-old] [--region <r> | --global]
gcp compute load-balancer list | get <name> | delete <name> [--global | --region <r>]
gcp compute backend-service | forwarding-rule | health-check  list | get <name> | delete <name>  [--global | --region <r>]
gcp compute instance-group list | get <name> | delete <name> [--zone <z>]
```

## Cloud DNS

- `<zone>` is a managed zone id (`<project>/<managed zone>`), a managed zone name or a DNS name. A managed zone name wins over a DNS name. A name several zones answer to (one managed zone name in two projects, or a public and a private zone of one DNS name) is a pick on a terminal and exit code 5 otherwise; `--project` or the zone id chooses. Until this version a DNS name of such a public and private pair silently meant the first of the two.
- `zone list` shows the zones of every selected project with their project; in JSON a zone's `id` is the zone id and `extra.project` / `extra.managed_zone` are its two parts.
- Record sets are shown one record per value; `upsert` sets the whole record set, `delete` removes the set or, with `--value`, one value. Deleting a whole set lists its values and asks first ([Confirmations](../interactive.md#confirmations)); the non-interactive flow needs `--yes`, and a set that does not exist is exit code 4 and asks nothing. One value (`--value`, `--id`) is removed without a question. Writes are applied as one atomic change.
- `--name` is relative to the zone (`www`, `@`) or an FQDN; default is the zone apex.
- `--ttl 0` keeps the existing TTL; a new set gets 300.
- `--id` (`project/zone|TYPE|name|value`, as shown by `list`) picks one record instead of `--name` / `--type`, and cannot be combined with `--name`, `--type`, `--value` or `--priority` (exit code 2).

## Instances

### Finding an instance

`get`, `start`, `stop`, `delete`, `resize`, `reboot`, `update`, `password` and `ssh-key` take the name or numeric id. polyctl finds the project and zone from the inventory of every selected project of every selected GCP account (synced once when the instance is unknown, always with `--refresh`), then reads it live.

- One name in several zones, projects or accounts: on a terminal polyctl asks which instance is meant (the list shows id, status, zone, addresses, project and account). In the non-interactive flow it is exit code 5; the error lists the candidates and names what chooses: `--project`, `--zone`, `--profile` (those that differ) or the instance id.
- `--zone` pins the instance: only an instance in that zone is used (instance names are unique only within a zone). It also finds an instance the inventory does not know. A name held only in other zones is exit code 4, and the error names those zones.
- `--project` pins it in the same way: only an instance of that project is used. With both flags the instance must be in that zone of that project. A project outside the selection is searched live.
- Not found is exit code 4.
- `reboot` also takes an internal or external IP.

### get, start, stop, reboot, update

- `get` shows addresses, network, tags, IP forwarding, deletion protection and disks. `--field` prints one raw value for scripts; `--field external-ip` on an instance without an external IP is exit code 1 with empty stdout.
- `start` / `stop`: an instance already in that state is `unchanged`. `stop` asks for confirmation. A stopped instance loses its ephemeral external IP; a static address stays bound.
- `reboot` is a hard reset (like `gcloud compute instances reset`): no graceful OS shutdown, addresses kept. The instance must be `RUNNING` (otherwise exit code 1). Asks for confirmation.
- `update --ip-forward[=false]` switches IP forwarding in place on a running or stopped instance, without a restart.

### create

```sh
polyctl gcp compute instance create web-1 --machine-type e2-standard-4 --zone us-central1-a \
  --disk 100 --os ubuntu --ssh-key-file ~/.ssh/id_ed25519.pub --tag http-server --dry-run
polyctl gcp compute instance create tmp-1 --machine-type 2H4G --os debian --os-version 12 --static-ip=false
polyctl gcp compute instance create win-1 --machine-type e2-standard-4 --zone us-central1-a --os windows
```

`create` is not an ensure: an instance of that name in the zone is exit code 1.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--zone` | `defaults.gcp.zone` | Zone (required one way or the other, else exit code 2). |
| `--machine-type` | `defaults.gcp.machine_type` | Machine type, or a size such as `2H4G` (see [Machine sizes](#machine-sizes)). Checked in the zone first (exit code 2). |
| `--os` | `debian` | `debian`, `ubuntu`, `centos`, `rocky`, `almalinux`/`alma`, `rhel`, `windows`, `suse`, `opensuse`, `cos`. The latest public image for the machine type's architecture is used. |
| `--os-version` | latest | Release such as `12` or `22.04`. |
| `--image` | | `projects/<p>/global/images/<name>` or `.../family/<family>`; overrides `--os`. Must match the machine type's architecture (exit code 2). |
| `--boot-disk-size` | image minimum | Boot disk `{name}-boot` in GB; smaller than the image minimum is exit code 2. |
| `--disk-type` | `pd-balanced` | Boot disk type (`pd-standard`, `pd-balanced`, `pd-ssd`, `pd-extreme`). |
| `--disk` | 0 (none) | Adds an empty data disk `{name}-data` of that size in GB. |
| `--data-disk-type` | `--disk-type` | Data disk type. |
| `--network` | `defaults.gcp.network`, else `default` | VPC network. |
| `--subnet` | `defaults.gcp.subnet`, else the network's only ordinary subnetwork in the region | Must exist (exit code 4) and belong to the network (exit code 2). Several candidates is exit code 2. |
| `--static-ip` | `true` | Reserves `{name}-external-ip` (premium tier) and `{name}-internal-ip` and binds them; existing ones are reused. `--static-ip=false` uses ephemeral addresses. |
| `--ssh-key` | | Public key itself, optionally `user:<key>` (repeatable). |
| `--ssh-key-file` | | Every key line of the file (repeatable, `~` expanded). |
| `--ssh-user` | | User for keys without a `user:` prefix; otherwise the whole part before `@` of the e-mail address that ends the key comment (`john.smith@laptop` gives `john.smith`). |
| `--ssh-key-instance-only` | off | Write keys to instance metadata even when project metadata already holds them. |
| `--tag` | | Network tag (repeatable; added to `defaults.gcp.tags`). |
| `--service-account` | `default` | Service account e-mail, or the default compute service account. |
| `--spot` | off | Spot instance (no automatic restart). |
| `--ip-forward` | off | Allow IP forwarding. |
| `--windows-user` | `polyctl-admin` | Windows only: the administrator user the guest agent creates. |
| `--password-timeout` | `10m` | Windows only: wait for the guest agent to set the password. |
| `--no-wait` / `--timeout` | wait, `10m` | By default waits until the instance is `RUNNING` and prints its addresses. |

Notes:

- Linux instances log in with an SSH key only; polyctl never sets a password. Keys go into the instance's `ssh-keys` metadata, together with `defaults.gcp.ssh_keys`. A Linux create without any key is allowed only when the project metadata holds SSH keys or enables OS Login; otherwise exit code 2 before anything is written.
- A key the project metadata already holds for that user is not repeated (unless `--ssh-key-instance-only`). With `block-project-ssh-keys=TRUE` all keys go to the instance. With `enable-oslogin=TRUE` you get a warning: OS Login ignores `ssh-keys`.
- The instance gets Shielded VM (vTPM, integrity monitoring), automatic restart and the host maintenance policy Compute Engine picks for the machine type (live migration, or stop for GPU machine types that cannot migrate; with `--spot` it stops and does not restart), and no deletion protection. Both disks are deleted with the instance.
- The names derived from the instance name (`{name}-boot`, `{name}-data`, and with `--static-ip` the two address names) must also be valid Compute Engine names (at most 63 characters). With the default address names an instance name longer than 51 characters is exit code 2 before any call; shorten it, change `naming.gcp_instance_*_ip`, or pass `--static-ip=false` (then up to 58 characters).
- Windows instances get a user and password from the guest agent once running; see [Instances](../instances.md). `password <name|id>` shows them again, `--reset` sets a new one.
- Nothing is rolled back on failure: reserved addresses stay and are reused by the next create of the same name.
- Static address names come from `naming.gcp_instance_external_ip` / `naming.gcp_instance_internal_ip`.

### Machine sizes

`--machine-type` of `create` and `resize` (and `defaults.gcp.machine_type`) also takes `<cores>H<memory>G`, such as `2H2G`, `2H4G`, `6H12G`. It resolves in the zone on every run:

- A predefined E2 type of that shape first: `e2-micro` (2H1G), `e2-small` (2H2G), `e2-medium` (2H4G), `e2-standard-<n>` (n vCPU, 4n GiB), `e2-highcpu-<n>` (n, n), `e2-highmem-<n>` (n, 8n).
- Otherwise the E2 custom type `e2-custom-<cores>-<MiB>` (`2H3G` is `e2-custom-2-3072`): an even 2-32 vCPUs, 0.5-8 GiB per vCPU, at most 128 GiB, in 0.25 GiB steps.
- The choice is printed on stderr. No fit is exit code 4 with the nearest size.

### resize

```sh
polyctl gcp compute instance resize web-1 --machine-type e2-standard-8 --yes
```

- The type is checked in the instance's zone first (exit code 2). The same type is `unchanged`.
- A running instance is stopped after confirmation. Its ephemeral IPs are made static first (`{name}-external-ip` / `{name}-internal-ip`) so they survive the stop; an external IP keeps its network tier (a standard tier IP becomes a standard tier address).
- The instance ends in the power state it had. `--start` starts a stopped one; `--start=false` leaves a running one stopped.
- `--wait-port <n>` waits up to 5 minutes until that TCP port (22 for SSH) accepts connections.

### delete

```sh
polyctl gcp compute instance delete tmp-1 --release-ips --yes
```

- Shows the instance, its disks and kept static addresses, then asks for confirmation.
- An instance with deletion protection is exit code 1; polyctl never switches it off.
- `--release-ips` also deletes `{name}-external-ip` and `{name}-internal-ip` when they are `RESERVED` and implies `--wait`.
- The stored Windows login of the instance is removed.

### SSH keys

```sh
polyctl gcp compute instance ssh-key list web-1
polyctl gcp compute instance ssh-key add web-1 --ssh-key-file ~/.ssh/id_ed25519.pub [--user deploy]
polyctl gcp compute instance ssh-key remove web-1 --fingerprint SHA256:abc... --yes
```

Shared behaviour is in [Instances](../instances.md#managing-ssh-keys). On Compute Engine:

- `add` and `remove` edit only the instance's own `ssh-keys` metadata through the API; every other line and metadata item is kept. No SSH login; the instance may be stopped. Keys in the legacy `sshKeys` item count as present and are removed too.
- **User**: `--user`, else the whole `user` of the `user@host` that ends the key's comment (dots and hyphens included; a local part with other characters, such as `john+ci`, gives no user); a terminal asks, the non-interactive flow is exit code 2. `remove` without `--user` removes the key for every user that has it.
- **Project-wide keys** are listed `read-only` and never changed (`add` of a key already there is `unchanged`). With `block-project-ssh-keys=TRUE` they are listed `ignored`, and `add` puts the key into the instance metadata.
- **Expired keys** (`google-ssh` with a past `expireOn`) are listed `ignored`; `add` adds the key again without an expiry.
- **OS Login** (`enable-oslogin=TRUE` on the instance, else on the project): `list` marks every key `ignored`; `add` and `remove` are exit code 7 and point at `gcloud compute os-login ssh-keys add`. An organization policy that forces OS Login (`compute.requireOsLogin`) is not detected.

### Windows password

```sh
polyctl gcp compute instance password win-1                 # stored login
polyctl gcp compute instance password win-1 --reset --yes   # set a new one
```

- `create` of a Windows instance asks the guest agent to create `--windows-user` (default `polyctl-admin`; 1-20 characters without spaces or `"/\[]:;|=,+*?<>@`, else exit code 2) and waits up to `--password-timeout` (default `10m`). If the agent does not answer in time, the serial port cannot be read (`compute.instances.getSerialPortOutput`) or `--no-wait` is given, the create still succeeds and a note names `--reset`. `--windows-user` and `--password-timeout` with a Linux image are exit code 2.
- `password` shows the stored login; nothing stored is exit code 4 with a hint to use `--reset`.
- A name whose login is stored for several instances is a pick on a terminal and exit code 5 otherwise; the candidates show the project and zone of each, and the instance id, `--project` or `--zone` chooses. The login is stored by zone and instance id, so `--project` tells the instances apart by the inventory: it leaves out an instance the inventory knows to be of another project.
- `--reset` sets a new password on a running Windows instance (also one polyctl did not create) for the stored user, else `polyctl-admin`, or `--user`. The old password stops working, so it asks for confirmation. A Linux instance is exit code 2, a stopped one exit code 1, no answer within `--password-timeout` exit code 1.

## Firewall rules

```sh
polyctl gcp compute firewall create allow-ssh-internal --network default --allow tcp:22 --source-range 10.0.0.0/8 --target-tag ssh-internal
polyctl gcp compute firewall update allow-ssh-internal --allow tcp:22,2222
polyctl gcp compute firewall ensure --preset lb-health-check --network default --region us-central1 --instance web-1
```

- `list` shows the rules of every network, or of `--network` (exact name), of every selected project, each project's rules sorted by priority.
- `get`, `update` and `delete` find `<name>` in the selected projects: one project holding it is used; several are a pick on a terminal and exit code 5 otherwise (pass `--project`); none is exit code 4, naming the projects searched. With one project selected, or with `--project`, the rule is read in that project straight away.
- `create` fails when the rule exists (exit code 1). The rule is created in the default project, or in the project of `--project`.
  - `--allow` (required, repeatable): `tcp`, `udp`, `icmp` or `all`; only `tcp`/`udp` take ports, such as `tcp:80,443,8000-8100` or aliases (`ssh`, `http`, `https`, `mysql`, ...).
  - An ingress rule requires `--source-range` (use `0.0.0.0/0` to mean everyone; polyctl will not open it implicitly). `--direction egress` requires `--destination-range` instead.
  - No `--target-tag` means every instance of the network. `--network` defaults to `defaults.gcp.network`, else `default`. `--priority` 0-65535, default 1000.
- `update` changes only the given fields. `--allow`, `--source-range`, `--destination-range` and `--target-tag` replace the list; `--add-source-range` adds to it. Network and direction cannot change (exit code 2: delete and recreate). `--target-tag ""` makes the rule apply to every instance.
- `delete` asks for confirmation. A missing rule is exit code 4.
- `ensure` creates a missing rule or adds the missing ranges, tags and protocols to an existing one; it never removes anything. A rule on another network, with the other direction, disabled, a deny rule, or targeting service accounts is exit code 1.
  - `--preset lb-health-check` makes the rule load balancer health checks and proxies need: name `allow-lb-health-check-{network}` (`naming.gcp_lb_firewall`), sources Google's health check ranges (`35.191.0.0/16`, `130.211.0.0/22`) plus the subnetworks of the network in `--region` (proxy-only included), all TCP ports, target tag `defaults.gcp.lb_network_tag` (`lb-health-check`) or `--target-tag`. Run it again per region whose load balancers use the network.
  - `--instance` (with optional `--zone`, which pins the instance to that zone) also adds the target tag to that instance; its network and region become the defaults. Without it, `--region` defaults to the region of `defaults.gcp.zone`.

## Networks and subnetworks

Read-only, always live.

- `network list` shows mode (`auto`, `custom`, `legacy`), routing mode, MTU and subnetwork count. `network get <name>` adds the subnetworks with their ranges.
- `subnet list` lists every region (or `--region`), optionally of one `--network` (exact name). `--proxy-only` keeps only proxy-only subnetworks.
- Both lists cover every selected project. `network get <name>` looks for the name in each of them (several holders: a pick on a terminal, exit code 5 otherwise, `--project` chooses); without `<name>` on a terminal it asks for the project first when several are selected.

## SSL certificates

Self-managed certificates for load balancers. A regional certificate serves regional load balancers of its region, a global one global load balancers; `create`, `update` and `delete` need exactly one of `--region` or `--global`. Google-managed certificates are shown but never changed.

```sh
polyctl gcp compute ssl-certificate create web-example-com-cert-20261117 --cert-file fullchain.pem --key-file privkey.pem --region us-central1
polyctl gcp compute ssl-certificate list --expiring-in 30
```

- `list` shows domains, expiry (UTC), days left and the HTTPS proxies using each certificate, for every selected project. An unused self-managed certificate is marked `*` (an orphan to delete by hand). `--expiring-in <days>` filters.
- `update` and `delete` find `<name>` (in its scope) in the selected projects, like the firewall commands: several holders are a pick on a terminal and exit code 5 otherwise (pass `--project`). On a terminal, without `<name>`, the project is asked first when several are selected. `create` goes to the default project, or to the project of `--project`.
- `create` uploads `--cert-file` (full chain, leaf first) and `--key-file` (unencrypted PEM key). `@-` reads stdin. polyctl checks before upload that the key matches the leaf and that the leaf has not expired (exit code 2 otherwise). An existing name is exit code 1.
- `update <name>` replaces a certificate in use: it uploads a new one named `{slug}-cert-{YYYYMMDD}` (`naming.gcp_ssl_certificate`), switches every HTTPS proxy of the scope from `<name>` to it, then deletes `<name>` unless `--keep-old`. A certificate already holding the same leaf is `unchanged`; a re-run after a failed switch reuses the uploaded one.
- `delete` asks for confirmation. A certificate still used by a proxy is exit code 1.

### load-balancer cert set

```sh
polyctl gcp compute load-balancer cert set lb-web-1 --domain example.com --dry-run
polyctl gcp compute load-balancer cert set lb-web-1 --domain www.example.com --cert-file fullchain.pem --key-file privkey.pem
```

Puts the certificate of `--domain` on every HTTPS proxy of a load balancer. `<lb>` is a forwarding rule name or the load balancer (URL map) name.

- Without files, the certificate comes from polyctl's store (`polyctl cert ensure`) and is issued or renewed first when it has `--days` (default `cert.renew_days`, 30) or fewer left. Given files must cover `--domain` (exit code 2).
- Certificates of that domain on the proxy are replaced; old ones are deleted unless `--keep-old`. A second run writes nothing. A certificate the new one does not fully cover (a wildcard-only certificate under an apex-only `--cert-file`, or one that also names another domain) is not replaced: it stays on the proxy beside the new one (SNI), reported `skipped` with the names it would lose.
- A regional load balancer with only an HTTP proxy is upgraded: an HTTPS proxy and a `:443` forwarding rule are created on the same IP as the `:80` rule (an ephemeral IP is first reserved as `<lb>-ip`; for an internal load balancer such as `INTERNAL_MANAGED` it is an internal `SHARED_LOADBALANCER_VIP` address in the `:80` rule's subnetwork, and an internal address of another purpose already holding the IP is exit code 1 before anything is written). `--new-ip` uses a new IP instead (DNS must change). Global load balancers are not upgraded (exit code 1).
- `--no-wait` only affects the creation of a new `:443` rule.

## Load balancers

Regional external Application and proxy Network Load Balancers (`EXTERNAL_MANAGED`). A load balancer is named after its forwarding rule's `polyctl-lb` label, else its URL map, else the rule's name.

### ensure

```sh
polyctl gcp compute load-balancer ensure web-1 --protocol http --dry-run
polyctl gcp compute load-balancer ensure web-1 --protocol https --ssl-certificate web-example-com-cert-20261117
polyctl gcp compute load-balancer ensure db-1 --protocol tcp --port 3306 --address lb-tcp-db-1-ip
```

Builds or completes a load balancer in front of an existing instance, in the instance's region and network. Missing components are created, existing ones reused; a component that differs in a way polyctl cannot change in place is exit code 1 with nothing written (delete it or use `--name`). Nothing is deleted or rolled back, so a re-run continues from a failed step.

Requirements, checked before anything is written (also in `--dry-run`):

- `--protocol https` needs `--ssl-certificate`, an existing regional certificate in the region (exit code 4 otherwise).
- The network needs an active proxy-only subnetwork in the region (purpose `REGIONAL_MANAGED_PROXY`); without one it is exit code 1 with an example `gcloud compute networks subnets create` command.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--protocol` | | `http`, `https` or `tcp` (required). |
| `--port` | 80 (http), 443 (https) | Frontend port; required for tcp. |
| `--backend-port` | 80 for http/https, `--port` for tcp | Port the instance serves on. |
| `--backend-protocol` | `http` | With https: `https` re-encrypts to the backend. |
| `--health-check-port` | backend port | TCP health check port. |
| `--health-check-name` | `check-{port}` | Shared by the load balancers of the region. |
| `--name` | `lb-{instance}` (tcp: `lb-tcp-{instance}`) | Load balancer name; other components follow it (`ig-`, `bs-`, `proxy-`, `fr-`). |
| `--address` | ephemeral IP | Regional static external address, reserved when missing (suggested `{lb-name}-ip`). When the forwarding rule already exists, the address is reserved with its IP, in the rule's network tier. |
| `--health-timeout` | `3m` | Wait for a `HEALTHY` backend (http/https). Timing out is reported `skipped` with a checklist, exit code 0. |
| `--no-wait` / `--timeout` | wait, `10m` | `--no-wait` skips the health wait; `--timeout` bounds each operation. |
| `--zone` / `--region` | the instance's | `--zone` pins the instance (only one in that zone is used); a different `--region` is noted and the instance's region used. |

Components: the health check firewall rule and instance tag (as `firewall ensure --preset lb-health-check`; skipped with a reason when the account may not manage firewall rules), a TCP health check, the instance group `ig-{instance}` with a named port, the backend service, for http/https a URL map and HTTP or HTTPS proxy, for tcp a TCP proxy, and the forwarding rule. Prefixes are set by `naming.gcp_lb_prefix`, `gcp_instance_group_prefix`, `gcp_backend_service_prefix`, `gcp_proxy_prefix` and `gcp_forwarding_rule_prefix`. An instance already in an instance group keeps it, so several load balancers (http, https, tcp) can share one group. The load balancer address is printed on stderr.

### list, get, delete

- `list`: one row per forwarding rule with its project, protocol, IP, port, backend and health, for every selected project. `--region` / `--global` narrow it.
- `get <name>` (load balancer or forwarding rule name) shows the whole chain with backend health. A regional match wins over a global one. Several matches (in several projects, regions or accounts) are a pick on a terminal and exit code 5 otherwise; the error names `--project`, `--region` / `--global` or `--profile`, whichever differ.
- `delete <name>` deletes the forwarding rules, then the proxies, URL maps and backend services only they use. Instance groups, health checks, firewall rules and static addresses are never deleted. Asks for confirmation.

### Components

`backend-service`, `forwarding-rule`, `health-check` (`--region` / `--global`) and `instance-group` (`--zone`) each have `list`, `get` and `delete`, for troubleshooting and clean-up. They cover every selected project; a name several projects or scopes hold is a pick on a terminal and exit code 5 otherwise (`--project`, `--region` / `--global` or `--zone` choose). `delete` asks for confirmation; a component still used by another is exit code 1 naming the user.
