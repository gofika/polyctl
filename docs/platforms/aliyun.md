# Alibaba Cloud

Commands under `polyctl aliyun`: Alidns, the domain registrar, ECS, VPC, EIP, ALB and CAS.

- [Login and permissions](#login-and-permissions)
- [Common behaviour](#common-behaviour)
- [Command reference](#command-reference)
- [DNS and domains](#dns-and-domains)
- [ECS instances](#ecs-instances)
- [Instance sizes](#instance-sizes)
- [Security groups](#security-groups)
- [Key pairs](#key-pairs)
- [Images](#images)
- [VPCs and vSwitches](#vpcs-and-vswitches)
- [Elastic IP addresses](#elastic-ip-addresses)
- [Application Load Balancer (ALB)](#application-load-balancer-alb)
- [Certificates (CAS)](#certificates-cas)
- [Inventory types](#inventory-types)

## Login and permissions

```sh
polyctl auth login aliyun --profile acme --set region=cn-hangzhou
printf '%s\n' "$AK_SECRET" | polyctl auth login aliyun --profile ci --set site=intl --set access_key_id=LTAI... --set access_key_secret=-
polyctl auth login aliyun --profile acme --set site=cn --set aliyun_profile=default   # import from an aliyun CLI profile
```

polyctl uses a RAM AccessKey pair and needs the account's site (`cn` or `intl`). The full login flow is in [Accounts](../accounts.md).

Grant the RAM user what the commands you use need:

| Commands | Permissions |
| --- | --- |
| `dns` | `AliyunDNSFullAccess` |
| `domain` | `AliyunDomainFullAccess` |
| `ecs` reads | `AliyunECSReadOnlyAccess` |
| `ecs` writes (instances, security groups, key pairs, `ssh-key` through Cloud Assistant) | `AliyunECSFullAccess` |
| `vpc` reads, VPC lookups of `ecs security-group` | `AliyunVPCReadOnlyAccess` |
| `vpc` and `eip` writes | `AliyunVPCFullAccess`, plus `AliyunResourceManagerReadOnlyAccess` to look up a resource group by name |
| `alb` | `AliyunSLBFullAccess` or the `alb:*` actions |
| `alb load-balancer ensure` | also `AliyunVPCFullAccess`, `AliyunECSReadOnlyAccess`, `yundun-cert:ListUserCertificateOrder`, `AliyunResourceManagerReadOnlyAccess` |
| `cas` | the `yundun-cert:*` actions |
| `cas certificate delete` (listener check) | `alb:ListLoadBalancers`, `alb:ListListeners`, `alb:GetListenerAttribute`, `alb:ListListenerCertificates`, `alb:DescribeRegions`, `ecs:DescribeRegions` |

A RAM denial (`Forbidden.RAM`) exits with code 3. The RAM actions of `ecs instance ssh-key` are listed under [SSH keys](#ssh-keys).

## Common behaviour

- **Profile.** `--profile` (it must have an Alibaba Cloud account, else exit code 3), else `current_profile` if it has one, else the only profile with one; otherwise exit code 5 with the candidates.
- **Region.** `--region`, default the profile's region. Alidns is region-independent.
- **Names.** Alibaba Cloud does not keep names unique. Every resource can be given by its id (`i-`, `sg-`, `vpc-`, `vsw-`, `eip-`, `alb-`, `sgp-`, `acl-`) or by its name. A name several resources share exits with code 5 (pass the id); a missing resource exits with code 4.
- **Cache.** List commands read the local inventory and honour `--refresh` and `--offline`; writes always go to the platform. Commands that are always read live exit with code 6 under `--offline`.
- **Waiting.** `--wait`, `--no-wait` and `--timeout` work as described in [Platform-specific commands](../commands.md#platform-specific-commands). `ensure` commands wait by default.
- **Confirmations.** Destructive commands ask first (default no). `--yes` skips the question; the non-interactive flow needs `--yes` or exits with code 2. See [Interactive use](../interactive.md).
- **`ensure`** is idempotent: it changes only what differs, reports `unchanged` for the rest, never deletes anything and never rolls back. If a step fails, run it again to continue. `--dry-run` reads everything and reports what would change, with `(pending)` for ids that do not exist yet.
- Errors carry the Alibaba Cloud code and message.

## Command reference

```text
aliyun whoami                                     # account, ARN, identity type
aliyun dns domain list
aliyun dns record list <domain> [--type] [--name]
aliyun dns record create <domain> --type A --name www --value 203.0.113.10 [--ttl 600] [--priority] [--line default|telecom|unicom|mobile|oversea]
aliyun dns record update <domain> <record-id> [--name] [--type] [--value] [--ttl] [--priority] [--line]
aliyun dns record delete <domain> <record-id>
aliyun domain list | get <domain>
aliyun domain ns get <domain> | ns set <domain> <nameserver>...

aliyun ecs instance list [--region <r>]
aliyun ecs instance get <name|id> [--region <r>]
aliyun ecs instance create <name> --type <type|size> --security-group <name|id> [--vswitch <id|name>] [--image <id> | --os alibaba-cloud-linux|windows] [--disk 20] [--disk-category cloud_essd_entry] [--key-pair <name>] [--ssh-key <public key> | --ssh-key-file <path>] [--eip] [--no-wait] [--timeout 10m] [--region <r>]
aliyun ecs instance ensure <name> [--type <type|size>] [--disk 20] [--disk-category <c>] [--image <id> | --os ...] [--vswitch <id|name>] [--security-group <name|id>] [--rule <rule>]... [--key-pair <name>] [--ssh-key ... | --ssh-key-file ...] [--eip[=false]] [--no-wait] [--timeout 10m] [--region <r>]
aliyun ecs instance delete <name|id> [--force] [--yes] [--wait] [--timeout 10m] [--region <r>]   # alias: terminate
aliyun ecs instance reboot <name|id> [--force [--yes]] [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance resize <name|id> --type <type|size> [--start[=false]] [--yes] [--wait] [--wait-port <n>] [--timeout 10m] [--region <r>]
aliyun ecs instance start <name|id> [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance stop <name|id> [--force] [--yes] [--wait] [--timeout 10m] [--region <r>]
aliyun ecs instance password <name|id> [--region <r>]
aliyun ecs instance ssh-key list <name|id> [--user <name>] [--region <r>]
aliyun ecs instance ssh-key add <name|id> (--ssh-key <public key> | --ssh-key-file <path>) [--user <name>] [--region <r>]
aliyun ecs instance ssh-key remove <name|id> (--fingerprint SHA256:... | --ssh-key <key> | --ssh-key-file <path>) [--user <name>] [--yes] [--region <r>]
    # ssh-key also: [--address <ip>] [--port 22] [--identity-file <private key>] [--login-user <name>] [--accept-new-host-key]
aliyun ecs security-group list [--vpc <vpc-id>] [--region <r>]
aliyun ecs security-group get <name|id> [--vpc <id|name>] [--region <r>]
aliyun ecs security-group create <name> --vpc <id|name> [--description <text>] [--region <r>]
aliyun ecs security-group delete <name|id> [--vpc <id|name>] [--yes] [--region <r>]
aliyun ecs security-group ensure <name> [--vpc <id|name>] [--description <text>] [--instance <name|id>] [--rule <rule>]... [--priority 1-100] [--region <r>]
aliyun ecs security-group rule add <sg> --rule <rule>... [--description <text>] [--priority 1-100] [--vpc <id|name>] [--region <r>]
aliyun ecs security-group rule remove <sg> (--rule <rule>... | --rule-id <sgr-id>...) [--yes] [--vpc <id|name>] [--region <r>]
aliyun ecs key-pair list [--region <r>]
aliyun ecs key-pair import <name> (--ssh-key <public key> | --ssh-key-file <path>) [--region <r>]
aliyun ecs key-pair ensure [<name>] [--ssh-key <public key> | --ssh-key-file <path>] [--region <r>]
aliyun ecs image latest [--os alibaba-cloud-linux|windows] [--arch x86_64|arm64] [--region <r>]

aliyun vpc vpc list [--all] [--region <r>]
aliyun vpc vpc get <name|id> [--region <r>]
aliyun vpc vpc create <name> [--cidr 172.16.0.0/12] [--wait] [--timeout 60s] [--region <r>]
aliyun vpc vpc ensure [<name>] [--cidr 172.16.0.0/12] [--zones b,c] [--netmask 22] [--no-wait] [--timeout 60s] [--region <r>]
aliyun vpc vswitch list [--vpc <id|name>] [--region <r>]
aliyun vpc vswitch get <name|id> [--vpc <id|name>] [--region <r>]
aliyun vpc vswitch create <name> --vpc <id|name> --zone <zone-id|suffix> [--cidr <cidr>] [--region <r>]
aliyun vpc vswitch ensure [--vpc <id|name>] [--zones b,c] [--prefix <name-prefix>] [--netmask 22] [--region <r>]

aliyun eip address list [--unused | --bound] [--region <r>]
aliyun eip address allocate [--bandwidth 200] [--isp BGP_PRO] [--resource-group default] [--region <r>]
aliyun eip address associate <allocation-id|ip> --instance <name|id> [--region <r>]
aliyun eip address ensure [--count 1] [--instance <name|id>] [--exclude <allocation-id>]... [--bandwidth 200] [--isp BGP_PRO] [--resource-group default] [--region <r>]

aliyun alb load-balancer list [--region <r>] [--name <text>]
aliyun alb load-balancer get <name|id> [--region <r>]
aliyun alb load-balancer create <name> --vpc <vpc-id> --zone-mapping <zone:vswitch-id:eip-allocation-id>... [--resource-group default] [--wait] [--timeout 10m] [--region <r>]
aliyun alb load-balancer update <name|id> [--name <new-name>] [--deletion-protection[=false]] [--no-wait] [--timeout 10m] [--region <r>]
aliyun alb load-balancer delete <name|id> [--force] [--yes] [--wait] [--timeout 10m] [--region <r>]
aliyun alb load-balancer ensure <domain> --service <ecs-name|id> [--listener http:80 --listener https:443] [--https-backend] [--cert <cas-cert-id>] [--server-group <name>] [--zones b,c] [--vpc <id|name>] [--eips 2] [--no-wait] [--timeout 10m] [--region <r>]
aliyun alb listener list --lb <name|id> [--protocol HTTP|HTTPS|QUIC] [--region <r>]
aliyun alb listener get <listener-id> [--region <r>]
aliyun alb listener create --lb <name|id> --listener <proto:port> --server-group <name|id> [--cert <cas-cert-id>] [--region <r>]
aliyun alb listener update <listener-id> [--server-group <name|id>] [--cert <cas-cert-id>] [--region <r>]
aliyun alb listener delete <listener-id> [--yes] [--region <r>]
aliyun alb listener cert set <listener-id> --cert <cas-cert-id> [--region <r>]
aliyun alb server-group list [--name <name>] [--region <r>]
aliyun alb server-group get <name|id> [--region <r>]
aliyun alb server-group create <name> --vpc <id|name> --protocol HTTP|HTTPS [--resource-group default] [--region <r>]
aliyun alb server-group update <name|id> [--name <new-name>] [--scheduler Wrr|Wlc|Sch] [--health-check[=false]] [--health-check-path <path>] [--sticky-session[=false]] [--region <r>]
aliyun alb server-group delete <name|id> [--yes] [--region <r>]
aliyun alb server-group server add <server-group> --instance <ecs-name|id> --port <n> [--region <r>]
aliyun alb acl list [--name <name>] [--region <r>]
aliyun alb acl get <name|id> [--region <r>]
aliyun alb acl create <name> [--resource-group default] [--region <r>]
aliyun alb acl delete <name|id> [--yes] [--region <r>]
aliyun alb acl entry add <acl> <cidr>... [--description <text>] [--region <r>]
aliyun alb acl entry remove <acl> <cidr>... [--region <r>]

aliyun cas certificate list [--name <text>] [--expired] [--expires-within <days>]
aliyun cas certificate upload <name> --cert <fullchain.pem> --key <privkey.pem>
aliyun cas certificate delete (<cert-id> | --expired) [--force] [--region <r>]... [--yes]
```

`whoami` checks the credentials and prints `profile`, `platform` and `identity` (`account`, `user`, `extra`). It needs the network; credentials that no longer work exit with code 3.

## DNS and domains

- Alidns calls the relative record name `RR`; polyctl exposes it as `--name` (`www`, `@`). `--ttl 0` uses the Alidns default (600). `--priority` is for MX records (1-50).
- Records carry a resolution line (`--line`, shown in the `LINE` column).
- Records have ids, so `update` and `delete` take `<record-id>` as an argument.
- `domain ns set` writes the nameservers at the registrar. The registrar API used depends on the account's site.

## ECS instances

Instances are given by id (`i-...`) or name. Names are compared case-sensitively.

**Lookup.** Without `--region`, `get`, `start`, `stop`, `delete`, `reboot`, `resize` and `ssh-key` find the instance in the local inventory of every selected account (synced once if it is not there) and then read it live. With `--region` the selected profile is asked in that region directly.

**`get`** shows `NAME`, `ID`, `REGION`, `TYPE`, `STATUS`, `PUBLIC_IP`, `PRIVATE_IP` and `EIP`. JSON: `{"name", "id", "profile", "region", "zone", "type", "status", "public_ip", "private_ip", "eip": {"allocation_id", "ip"} | null, "vpc_id", "vswitch_id", "security_group_ids", "key_pair", "created_at", "cached"}`. With `--offline` it shows the inventory (exit code 6 if the instance is not there).

**`create <name>`** creates one pay-as-you-go instance from existing network resources. It has no public address of its own; use `--eip` (or `ensure`) for one.

- `--type` (or `defaults.aliyun.ecs_instance_type`) is required: a type id or a [size](#instance-sizes) such as `2H4G`.
- `--vswitch` decides the zone. Default: the vSwitch `naming.aliyun_vswitch` names for zone `b` in the VPC `naming.aliyun_vpc` names; it must exist (else exit code 2).
- `--security-group` (required) must be in that vSwitch's VPC (another VPC is exit code 1).
- **Image:** `--image <id>` (any image, e.g. Ubuntu or Debian; a missing or deprecated image is exit code 4), else the newest public image of `--os` for the type's architecture (see [Images](#images)).
- **Disk:** `--disk` GiB (default 20, at least the image size) of `--disk-category` (default `cloud_essd_entry`).
- **Linux login is key-only.** The key pair is `--key-pair`, or the one holding `--ssh-key` / `--ssh-key-file` (imported under `--key-pair` if missing), or `defaults.aliyun.ecs_key_pair` if it exists in the region. Without any of these, a terminal offers the region's key pairs or a new import; the non-interactive flow exits with code 2.
- **Windows** (`--os windows`, or an `--image` whose OS type is `windows`): no key pair (key flags are exit code 2). polyctl generates the `Administrator` password and stores it encrypted; read it with `ecs instance password` (see [Instances](../instances.md)). `--disk` defaults to 40 and may not be smaller than the image. `--os windows` is Windows Server Datacenter (Chinese edition), x86_64 only. The host name is cut to 15 characters.
- Names: 2 to 128 characters, no `*`, not starting with `i-`. The host name is derived from the name (invalid characters become `-`). An instance of the same name in the region is exit code 1 (use `ensure`).
- Waits until `Running` (unless `--no-wait`; `--eip` always waits), then binds an EIP if `--eip`.
- Retries are safe: a repeated request never creates a second instance.
- No stock of the type in the zone is exit code 1: pass `--vswitch` in another zone or another `--type`.

**`delete <name|id>`** (alias `terminate`) shows the instance and asks first. A `Running` instance is stopped, then deleted; `--force` deletes it at once. A new instance cannot be deleted for about 45 seconds; polyctl retries for up to 2 minutes. Deletion protection is exit code 1 (polyctl never turns it off). `--wait` waits until the instance is gone. A bound EIP is not released: it stays billed and the next `ensure` reuses it. Stored Windows credentials are removed after the delete.

**`reboot <name|id>`** reboots a `Running` instance (any other status is exit code 1). `--force` is a forced stop (unsaved data is lost) and asks first. `--wait` waits until it is `Running` again.

**`resize <name|id> --type <type|size>`** changes the type. A `Running` instance is stopped (after a confirmation), changed and started again; a `Stopped` one stays stopped unless `--start`. `--start=false` leaves a running instance stopped. `--wait` waits until it runs; `--wait-port <n>` (implies `--wait`) also waits until that TCP port accepts connections. The same type is `unchanged`. A failure leaves the instance `Stopped` with its old type (exit code 1). A size picks the cheapest x86 type in stock that the instance can change to in its zone.

**`start` / `stop`** report `unchanged` when the instance is already `Running` / `Stopped`. `stop` asks first; `--force` forces the stop. `--wait` waits for the target state.

**`ensure <name>`** makes sure the instance exists, is `Running` and holds an EIP.

- An existing instance is used as it is. A different `--type` or `--disk` is reported `skipped` (use `resize`); a `Stopped` instance is `skipped` (start it).
- A missing instance is created with everything it needs, in order: the key pair; the VPC (`naming.aliyun_vpc`, `172.16.0.0/12`); vSwitches in zones `b` and `c` (`naming.aliyun_vswitch`, first free `/22`); the security group (`--security-group`, else `naming.aliyun_ecs_security_group`, `sg-common`) with the `--rule` rules (else `defaults.aliyun.ecs_security_group_rules`, else `icmp:all:0.0.0.0/0`, `tcp:80:0.0.0.0/0`, `tcp:443:0.0.0.0/0`); then the instance in zone `b` (or the zone a size resolved to). With `--vswitch`, that vSwitch is used and no VPC or vSwitch is ensured.
- The default type is `defaults.aliyun.ecs_instance_type`, else `ecs.u1-c1m1.large`. Image, disk and login work as in `create`.
- `--eip` (default) binds an idle EIP of the region, else a new one; `--eip=false` skips it. `--no-wait` returns at once and skips the EIP.
- Rows: `key-pair/<name>`, `vpc/<name>`, `vswitch/<name>`, `security-group/<name>`, `security-group/<name>/rule`, `instance/<name>`, `instance/<name> status`, `eip/<name>`. `-o json` adds `"result": {"instance_id", "public_ip"}`.
- The default group name `sg-common` looks like an id: in the `ecs security-group` commands, address it by its id.

### SSH keys

`ecs instance ssh-key list|add|remove` (shared behaviour in [Instances](../instances.md#managing-ssh-keys)) edits `~/.ssh/authorized_keys` over SSH or Cloud Assistant; the instance must be running.

- **Login users**: `ecs-user` for an instance created to log in as `ecs-user` (it cannot log in as `root`), otherwise `root`, then `ecs-user`. A user you added by hand needs `--login-user`.
- **Key pair**: the one bound to the instance; it is never changed (only `authorized_keys` is edited, no restart needed). No key pair, or one that cannot be read, goes to Cloud Assistant.
- **Cloud Assistant**: used when its agent is online (preinstalled on public images released since 2017-12-01). No network path to the instance is needed. An invocation that does not finish is exit code 1 with its error code; a RAM denial of `ecs:RunCommand` is exit code 3. A command whose result cannot be read was sent and may have run.
- **RAM actions**: `ecs:DescribeInstances`, `ecs:DescribeKeyPairs`; for Cloud Assistant `ecs:DescribeCloudAssistantStatus`, `ecs:RunCommand` (with `ecs:CommandRunAs`) and `ecs:DescribeInvocationResults`.

### Windows password

`ecs instance password <name|id> [--region <r>]` reads the login polyctl stored when it created the instance (see [Instances](../instances.md#windows-passwords)). Alibaba Cloud never shows an instance password: for an instance polyctl did not create (exit code 4), reset it in the ECS console. `ensure` on an existing instance never changes its password.

## Instance sizes

`--type` of `create`, `ensure` and `resize` (and `defaults.aliyun.ecs_instance_type`) accepts a size `<cores>H<memory>G`, e.g. `2H2G`, `2H4G`, `4H8G`, `1H0.5G`. Anything else is a type id.

- A size is resolved on every run (also in `--dry-run`) to the cheapest x86 pay-as-you-go type in stock with exactly that many vCPUs and GiB, in the zones the instance may use. Ties go to the type name, then the zone.
- The choice is printed on stderr, e.g. `2H4G -> ecs.e-c1m2.large (cn-hongkong-b, 0.0123 CNY/hour)`.
- Memory must match exactly: some types have 3.5 or 7.5 GiB, so write `2H3.5G` for those.
- If the type does not offer `--disk-category`, the first offered of `cloud_essd_entry`, `cloud_essd`, `cloud_auto`, `cloud_efficiency`, `cloud_ssd` is used (with a note), unless you gave `--disk-category` explicitly.
- Nothing in stock is exit code 4 (the message lists zones that have it). A size of 0 is exit code 2.

## Security groups

Groups belong to one region and one VPC. polyctl only creates VPC groups and never sends a create without a VPC.

- **Rules** use the common firewall format `<protocol>:<port|from-to|alias|all>:<source>`, e.g. `icmp:all:0.0.0.0/0`, `tcp:http:0.0.0.0/0`, `tcp:8000-8999:10.0.0.0/8`, `tcp:1-65535:203.0.113.7`. They are written as `accept` rules on the `intranet` NIC with `--priority` (1-100, default 1). A single IPv4 address is sent as `/32`. Malformed rules are exit code 2.
- Rules are compared by protocol, ports, source and policy (priority and description never count). Only ingress rules are managed.
- `list` shows `NAME`, `ID`, `VPC`, `RULES`, `DESCRIPTION`; `--vpc` takes a VPC id.
- `get` shows the group and its ingress rules. JSON: `{"name", "id", "vpc_id", "region", "type", "description", "profile", "rules": [{"id", "direction", "protocol", "port", "source", "policy", "priority", "description"}]}`.
- `create <name>` needs `--vpc`. A group of that name in the VPC is exit code 1. Names: up to 128 characters, not starting with `sg-`.
- `ensure <name>` creates the group if missing and adds missing `--rule` rules (never removes any). The VPC is the instance's with `--instance`, else `--vpc`, else `naming.aliyun_vpc` (must exist, else exit code 2). `--instance` joins the instance to the group, keeping its other groups. A group in another VPC is exit code 1.
- `rule add <sg>` adds rules to an existing group. `rule remove <sg>` removes rules given by `--rule` or `--rule-id <sgr-...>` (not both) and asks first.
- `delete` asks first. A group still used by instances or referenced by another group's rule is exit code 1.

## Key pairs

Key pairs are regional: a key used in several regions is imported in each. ECS accepts RSA, ECDSA and ED25519 keys and compares them by MD5 fingerprint.

- `--ssh-key` takes the public key line, `--ssh-key-file` a file (`~` expanded). Both together, a private key, a DSA key or non-key text are exit code 2. Only the key, not its comment, is sent.
- Names: 2 to 128 characters, no `*`.
- `list` shows `NAME`, `FINGERPRINT`, `CREATED`. JSON: `{"name", "fingerprint", "created", "region"}`.
- `import <name>` imports a key. A taken name is exit code 2 (never replaced). On a terminal a missing key is picked from `~/.ssh/*.pub`, a path or typed in.
- `ensure [<name>]` reuses a key pair that already holds the key (`unchanged`, `matched by fingerprint`); otherwise imports it as `<name>`. No name is ever chosen for you: without `<name>` a terminal asks, the non-interactive flow exits with code 2. If several key pairs hold the key and no `<name>` is given, the non-interactive flow exits with code 5. A `<name>` that holds another key is exit code 2.
- There is no `key-pair delete`.

## Images

`ecs image latest` prints the id of the newest public image of `--os` for `--arch` (default `x86_64`) in the region.

- `alibaba-cloud-linux` (default): the standard Alibaba Cloud Linux LTS images (no pro, container, GPU or other variants).
- `windows`: Windows Server Datacenter, Chinese edition. There is no arm64 image (exit code 2).
- Other systems are not supported by `--os` (exit code 2): pass their image id to `--image`.
- New versions are picked up as soon as Alibaba Cloud publishes them.
- Table output is the id alone, for `$(polyctl aliyun ecs image latest)`. JSON: `{"image_id", "image_name", "os_name", "architecture", "creation_time", "region"}`.
- No match is exit code 4. `--offline` is exit code 6.

## VPCs and vSwitches

Always read live. Names: up to 128 characters, not starting with `vpc-` / `vsw-`, `http://` or `https://`.

- `vpc list` shows `NAME`, `ID`, `CIDR`, `STATUS`, `DEFAULT`. The default VPC is hidden unless `--all`. `vpc get` adds its vSwitches.
- `vpc create <name>` uses `--cidr` (default `172.16.0.0/12`; cannot be changed later). An existing name is exit code 1.
- `vpc ensure [<name>]` (default `naming.aliyun_vpc`, `{region}-vpc`) creates the VPC if missing, waits until it is `Available` (`--timeout`, default 60s) and ensures a vSwitch in each of `--zones`. An existing VPC is used as it is (its CIDR is not compared). With `--no-wait`, vSwitches of a VPC that is not ready yet are `skipped`.
- `vswitch list` shows `NAME`, `ID`, `VPC`, `ZONE`, `CIDR`, `STATUS`, `AVAILABLE IPS`.
- `vswitch create <name>` needs `--vpc` and `--zone` (a suffix such as `b` or a zone id). Without `--cidr` the first free `/22` is used.
- `vswitch ensure` makes sure the VPC (`--vpc`, default `naming.aliyun_vpc`, must exist) has a vSwitch in each of `--zones` (default `b,c`). Names are `<prefix>-<suffix>` with `--prefix`, else `naming.aliyun_vswitch` (`{region}-switch-{zone}`). New ones get the first free `/--netmask` block (default 22, range 16-29).
- An overlapping, out-of-range or misaligned CIDR is exit code 1. A zone the region does not have is exit code 7.

## Elastic IP addresses

EIPs are given by allocation id (`eip-...`) or address. **An EIP is billed while it exists, bound or not.** polyctl has no release command; `list --unused` shows idle ones.

- New EIPs: `--bandwidth` Mbps (`defaults.aliyun.eip.bandwidth`, else 200), `--isp` (`defaults.aliyun.eip.isp`, else `BGP_PRO`), pay by traffic, in `--resource-group` (a name or `rg-` id; default `defaults.aliyun.resource_group`, else `default`). A missing resource group is exit code 4; an ISP the region does not offer is exit code 7.
- `list` shows `ALLOCATION_ID`, `IP`, `STATUS`, `BOUND_TO`, `NAME / DESC`, `BANDWIDTH`, `ISP`. `--unused` and `--bound` filter (not both). JSON: `{"allocation_id", "ip", "status", "instance_id", "instance_type", "name", "description", "bandwidth", "isp", "charge_type", "internet_charge_type", "service_managed", "resource_group_id", "region"}`.
- `allocate` allocates one EIP.
- `associate <eip> --instance <name|id>` binds an EIP to an instance in the instance's region. An EIP bound elsewhere, or an instance that already has an EIP or is not in a VPC, is exit code 1.
- `ensure` makes sure `--count` EIPs exist (default 1), reusing idle EIPs of the account first (any idle one of the right ISP), then allocating. `--exclude` skips allocation ids. `--instance` (with `--count 1`) binds the EIP; an instance that already has one is `unchanged`. JSON adds `"result": {"eips": [{"allocation_id", "ip"}]}`.

## Application Load Balancer (ALB)

Always read live, except `load-balancer list` (inventory, every region). A listener or ACL still changing, or a full ACL, is exit code 1. Missing ALB permissions are exit code 3 (in `sync`, a warning).

**Load balancers**

- `list` shows `ID`, `NAME`, `STATUS`, `VPC`, `REGION`, `DNS_NAME`; `--name` matches a substring.
- `get` finds the load balancer through the inventory (or `--region` directly). JSON: `{"id", "name", "status", "region", "vpc_id", "dns_name", "address_type", "edition", "resource_group_id", "deletion_protection", "addresses": [{"zone", "vswitch_id", "allocation_id", "ip"}], "profile", "listeners": [{"id", "protocol", "port", "status", "certificate_id"}]}`.
- `create <name>` creates an Internet-facing IPv4 Standard load balancer in `--vpc` with exactly two `--zone-mapping <zone-id>:<vswitch-id>:<eip-allocation-id>`. It creates nothing else (use `ensure`). The EIPs must share one ISP.
- `update` renames (`--name`) or toggles `--deletion-protection`. It asks nothing.
- `delete` asks first. One with listeners needs `--force`. Deletion protection is exit code 1 (turn it off with `update --deletion-protection=false`). Server groups are kept; EIPs are unbound but stay billed.

**`load-balancer ensure <domain> --service <ecs>`** makes sure a dual-zone load balancer with HTTP and HTTPS listeners serves the instance.

- The instance and (for HTTPS) the certificate are checked first; a missing one is exit code 4 and nothing is created.
- Name: `naming.aliyun_alb_load_balancer` (`lb-{name}`, dots of the domain become hyphens; a wildcard domain is exit code 2). An existing one is used as it is.
- A new one goes into the instance's VPC, in two zones (`--zones`, else the first two offering ALB; fewer than two is exit code 7), each with a `naming.aliyun_vswitch` vSwitch (created if missing) and an EIP (an idle unnamed EIP of `defaults.aliyun.eip.isp` is reused, else one is allocated). `--eips` only accepts 2.
- Server group `naming.aliyun_alb_server_group` (`{service}-http`, or `--server-group`) gets the instance on port 80 if it has no servers. With `--https-backend` the HTTPS listener forwards to its own HTTPS group on port 443 (`{service}-https`).
- Listeners: `--listener <protocol>:<port>` (default `http:80` and `https:443`). An existing HTTPS listener's default certificate is replaced if it differs.
- Certificate: `--cert`, else the latest valid certificate uploaded for the domain's root (named `upload_<root>_<date>`, or whose common name matches). `ensure` never issues one: run `polyctl cert ensure` and `aliyun cas certificate upload` first.
- DNS is not written: the last row `dns/addresses  skipped` names the addresses to point the domain to (use `polyctl dns ensure`).
- JSON adds `"load_balancer": {"id", "name", "dns_name"}` and `"addresses"`.

**Listeners**

- Certificate ids: in `cn-hongkong` listeners need `<id>-ap-southeast-1`; elsewhere the bare id. `--cert` takes either form. `defaults.aliyun.cas_region` overrides the store.
- `list --lb` (required) shows `ID`, `PROTOCOL`, `PORT`, `STATUS`, `SERVER_GROUPS`; `get` adds certificates.
- `create` needs `--lb`, `--listener` and `--server-group`; HTTPS needs `--cert`. A port already in use is exit code 1.
- `update` changes `--server-group` and/or `--cert`. `cert set` sets the default certificate of an HTTPS listener. `delete` asks first.

**Server groups**

- `create <name> --vpc --protocol HTTP|HTTPS` (health check and session persistence off). `delete` asks first; a group a listener uses is exit code 1.
- `server add <group> --instance <ecs> --port <n>`: the instance must be in the group's VPC.
- `update` changes `--name`, `--scheduler` (`Wrr`, `Wlc`, `Sch`), `--health-check[=false]`, `--health-check-path` (starts with `/`; needs the health check on) and `--sticky-session[=false]`. Other settings are left to the console.

**ACLs**

- `create`, `delete` (asks first), `entry add <acl> <cidr>...`, `entry remove <acl> <cidr>...`. Entries are IPv4 addresses or CIDR blocks (a bare address becomes `/32`; IPv6 or host bits set is exit code 2).
- polyctl does not bind an ACL to a listener; it takes effect only once bound.

## Certificates (CAS)

An account has two separate certificate stores. polyctl uses the Singapore store (`cas.ap-southeast-1.aliyuncs.com`) for a `cn-hongkong` profile and the central store otherwise; override with `defaults.aliyun.cas_region` / `defaults.aliyun.cas_endpoint`. An endpoint that refuses every call is exit code 7. Only uploaded certificates are handled.

- `list` shows `ID`, `NAME`, `COMMON_NAME`, `START`, `END`, `DAYS` (UTC). `--expired`, `--expires-within <days>` (includes expired) and `--name` filter. JSON: `{"id", "name", "common_name", "start_date", "end_date", "days_to_expire", "expired", "fingerprint_sha1", "sans"}`.
- `upload <name> --cert <fullchain.pem> --key <privkey.pem>` (`-` reads stdin). An encrypted or mismatched key, or an expired certificate, is exit code 2. A certificate of the same name is reused as it is (`unchanged`). Name certificates `upload_<root domain>_<YYYY-MM-DD of expiry>` so a renewal is a new upload.
- `delete <cert-id>` or `delete --expired` asks first. polyctl refuses to delete a certificate an ALB HTTPS/QUIC listener uses (exit code 1, naming the listener); with `--expired` such ones are `skipped`. Without `--region` every region of the account that ALB offers (ALB's own region list) is checked, and one of them that cannot be read, a DNS failure of its endpoint included, fails the check (exit code 1) instead of being taken as unused; `cert deploy --prune-expired` checks the same way and then deletes nothing. `--region` limits the regions checked; `--force` skips the check. Only ALB listeners are checked, not other products.

## Inventory types

`zone` (Alidns domains), `dns_record`, `domain`, `instance`, `security_group`, `key_pair`, `eip`, `load_balancer` (ALB), `certificate` (uploaded CAS certificates).
