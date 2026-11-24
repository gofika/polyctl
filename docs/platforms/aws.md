# AWS

Commands of the `polyctl aws` tree: Route 53, Route 53 Domains, EC2 (instances, key pairs, security groups, EBS volumes and snapshots), Elastic Load Balancing v2, Certificate Manager and RDS.

- [Login and permissions](#login-and-permissions)
- [Common behavior](#common-behavior)
- [Command overview](#command-overview)
- [Route 53 and Route 53 Domains](#route-53-and-route-53-domains)
- [EC2 instances](#ec2-instances)
- [Instance sizes](#instance-sizes)
- [EC2 key pairs](#ec2-key-pairs)
- [EC2 security groups](#ec2-security-groups)
- [EBS volumes and snapshots](#ebs-volumes-and-snapshots)
- [Elastic Load Balancing v2](#elastic-load-balancing-v2)
- [Certificate Manager (ACM)](#certificate-manager-acm)
- [RDS database instances](#rds-database-instances)

## Login and permissions

Log in with `polyctl auth login aws` using IAM Identity Center (`--set method=sso`), access keys (`keys`) or a profile of `~/.aws/config` (`profile`); see [Login flows per platform](../accounts.md#aws). `--set region=` sets the default region of regional services; Route 53 and Route 53 Domains are global.

A denied call exits with code 3 and names the IAM action it needed (for example `ec2:RunInstances`, `elasticloadbalancing:CreateLoadBalancer`, `acm:RequestCertificate`, `rds:CreateDBInstance`). Permissions worth knowing in advance:

| Permission | Used by |
| --- | --- |
| `sts:GetCallerIdentity` | `aws whoami` |
| `ssm:GetParameter`, `ssm:GetParametersByPath` | picking the default Amazon Linux / Windows image of `ec2 instance create` (without them polyctl falls back to searching the Amazon images) |
| `iam:CreateServiceLinkedRole` | creating the first load balancer of an account |
| `acm:RequestCertificate`, `acm:DescribeCertificate`, `acm:ListCertificates`, `acm:ImportCertificate` | the `acm certificate` commands |

## Common behavior

- **Profile**: `--profile` (must have an AWS account, else exit code 3) > the current profile if it has one > the only profile that has one > an error listing the candidates (exit code 5).
- **Region**: regional commands use the profile's region; `--region` picks another. Commands that take a name or id of an instance, volume, load balancer, certificate or database find the account and region themselves through the inventory (every enabled region is cached), so `--region` is rarely needed there.
- **Cache**: list commands read the local inventory and honour `--refresh` / `--offline`; writes always go to AWS. Inventory types: `zone`, `dns_record`, `domain`, `instance`, `key_pair`, `security_group`, `load_balancer`, `eip`, `db_instance`, `certificate`, `volume`. Snapshots are not cached.
- **Waiting**: commands with `--wait` also accept `--no-wait`; `--timeout <duration>` bounds the wait. A wait that runs out of time is exit code 1 with the resource's last status.
- **Confirmations**: destructive commands show what they will do and ask (default no). `--yes` skips the question; the non-interactive flow needs `--yes` (exit code 2 without). A declined confirmation is exit code 0. See [Confirmations](../interactive.md#confirmations).
- **Dry runs and reports**: write commands print a change report and support `--dry-run`; see [Dry runs and change reports](../configuration.md#dry-runs-and-change-reports). `ensure` commands are idempotent: they create or change only what differs, report `unchanged` for the rest, and never delete.
- **Empty results**: a list with no match prints an empty list (`[]` with `-o json`), a note on stderr, and exits 0. Nothing found by a `get` or by name is exit code 4; several matches are exit code 5 (pass `--profile`, `--region` or the id).
- Tags of `defaults.aws.tags` go on every resource polyctl creates.

## Command overview

```text
aws whoami                                        # account, ARN, user id
aws route53 zone list | zone get <zone-id|name>
aws route53 record list <zone> [--type] [--name]
aws route53 record upsert <zone> --type A --name www --value 203.0.113.10 [--value ...] [--ttl 300] [--priority <n>]
aws route53 record delete <zone> --type A --name www      # deletes the whole record set
aws route53domains list | get <domain> | ns get <domain> | ns set <domain> <nameserver>...

aws ec2 instance list [--state <s>,...] [--type <t>,...] [--name <substring|pattern>] [--region <r>]
aws ec2 instance get <name|id> [--field <name>] [--include-terminated]
aws ec2 instance create <name> [--type <type|size>] [--ami <id> | --os al2023|windows] [--arch x86_64|arm64]
                        [--subnet <id>] [--sg <id>]... [--key-pair <name>] [--ssh-key <key> | --ssh-key-file <path>]
                        [--disk <GB> [--disk-device /dev/sdb] [--disk-type gp3] [--disk-iops 3000] [--disk-throughput 125]]
                        [--public-ip[=false]] [--tag k=v]... [--key-file <rsa key>] [--password-timeout 20m]
                        [--no-wait] [--timeout 5m]
aws ec2 instance start|stop|reboot <name|id> [--wait [--timeout 5m]]      # stop: [--force]
aws ec2 instance resize <name|id> --type <type|size> [--start[=false]] [--wait-port <n>] [--timeout 5m]
aws ec2 instance delete <name|id> [--wait [--timeout 5m]]                 # alias: terminate
aws ec2 instance password <name|id> [--key-file <path>]                   # Windows login
aws ec2 instance ssh-key list|add|remove <name|id> ...                    # authorized_keys
aws ec2 key-pair list | import <name> | ensure [<name>]   [--ssh-key <key> | --ssh-key-file <path>]
aws ec2 security-group list|get|create|delete|ensure ...
aws ec2 security-group rule add|remove <sg-id|name> --rule <rule>...
aws ec2 volume list|get|create|resize|attach|detach|delete ...
aws ec2 snapshot list|create ...

aws elbv2 load-balancer list|get|create|update|delete|ensure ...
aws elbv2 target-group list|get|create|update|delete ...
aws elbv2 listener list|get|create|update|delete ...

aws acm certificate list|get|request|import ...

aws rds instance list|get|create|start|stop|resize|delete|ensure ...
```

Every regional command takes `--region <r>`. Run `polyctl aws <command> --help` for the full flag list of each command.

## Route 53 and Route 53 Domains

Route 53 stores a record set (name + type) with several values. polyctl shows **one record per value**, in the inventory and in `dns list`, with the id `<zone-id>|<TYPE>|<name>|<set-identifier>|<value>` (each part URL-encoded). Updating or deleting one such record rewrites the whole set with that value changed or removed.

- `record upsert` replaces the whole set; repeat `--value` to write several values in one call. `--ttl 0` keeps the existing TTL (300 for a new set). `--priority` applies to MX/SRV values that do not start with one. `--name` defaults to the zone apex.
- `record delete` deletes the whole record set of `--name` / `--type`.
- `route53domains` is the registrar group: `list`, `get`, `ns get`, `ns set`.

## EC2 instances

Instances are named by their Name tag or id. `get`, `start`, `stop`, `reboot`, `resize` and `delete` find the account and region themselves; terminated instances are never picked. Several live instances of one name: exit code 5 (pass `--profile` or the id). None: exit code 4.

**list** shows the profile's region from the inventory; `--region` and any filter ask AWS. `--state` (`running`, `stopped`, `stopping`, `pending`, `terminated`, `shutting-down`) and `--type` take comma-separated values; `--name` matches Name tags containing the value (`*` / `?` make it an EC2 wildcard pattern). All filters must match.

**get** shows the instance with addresses, network, key pair and volumes. `--field <name>` prints one raw value for scripts (field names in `--help`); an empty value (no public IP on a stopped instance) is exit code 1. `--include-terminated` also finds a terminated instance.

**create `<name>`**

```sh
polyctl aws ec2 instance create site-new --type 2H4G --ssh-key-file ~/.ssh/id_ed25519.pub --key-pair ops
polyctl aws ec2 instance create win-1 --os windows --type t3.large
polyctl aws ec2 instance create site-new --type c6a.xlarge --disk 400 --dry-run
```

- A name used by a non-terminated instance in the region is exit code 1.
- Defaults: `--type`, `--subnet`, `--sg`, `--key-pair` come from `defaults.aws.instance_type`, `subnet_id`, `security_group_ids`, `key_name`. A terminal asks for a missing name, subnet and type; the non-interactive flow is exit code 2. No security group means the VPC's default group.
- **A key pair is required for Linux**: polyctl never sets a password. Give `--key-pair`, `--ssh-key` or `--ssh-key-file` (or set `defaults.aws.key_name`); a terminal otherwise offers the region's key pairs or importing one, the non-interactive flow is exit code 2. `--ssh-key` / `--ssh-key-file` reuse the key pair holding that key, or import it under `--key-pair` (the rules of `key-pair ensure`).
- Image: `--ami`, or the latest Amazon Linux 2023 for `--arch` (x86_64 by default; arm64 only for types that run nothing else, such as `t4g.small`). `--os windows` uses the newest Windows Server English Full Base (x86_64; arm64 is exit code 2). Mac types need `--ami` (exit code 7). No suitable image is exit code 4.
- Windows: polyctl creates an RSA key pair, waits up to `--password-timeout` for the password and stores the login (see [Instance login credentials](../instances.md)). `--key-file` launches with your own RSA key pair instead (with `--key-pair`). `--ssh-key`, `--ssh-key-file`, and `--key-pair` without `--key-file` are exit code 2 for Windows; `--key-file` is exit code 2 for Linux; `defaults.aws.key_name` is ignored.
- `--disk <GB>` adds a data disk (`/dev/sdb`, gp3, 3000 IOPS, 125 MiB/s; io1/io2 need `--disk-iops`). **The data disk is kept when the instance is deleted.** Encryption follows the account's EBS default.
- One network interface, public IP unless `--public-ip=false`. Tags: Name, `defaults.aws.tags`, `--tag`, on the instance and its volumes.
- Waits until running and prints public and private IP. `--dry-run` resolves image and type and reports `would create`.

**start / stop** — an instance already in the target state is `unchanged`. `stop` asks for confirmation; `--force` skips the clean shutdown. `--wait` waits for running (and prints addresses) or stopped.

**reboot** reboots a running instance and starts a stopped one (other states: exit code 1). A started instance gets a new public IP unless it has an Elastic IP.

**resize `--type <type|size>`** — checks the type first (unknown: exit code 2; other architecture or not offered in the zone: exit code 1), then stops a running instance (after confirmation), changes the type and starts it again. The instance ends in its previous power state; `--start` / `--start=false` override that. Without an Elastic IP the public IP changes (shown as `public ip <old> -> <new>`). `--wait-port <n>` waits until the port accepts connections (22 for SSH, 3389 for RDP). If the type change fails, the instance stays stopped with its old type; run the command again to continue.

**delete** (alias `terminate`) — shows which volumes go with the instance (the root volume) and which stay (data volumes, which keep costing money), then asks. Termination protection is exit code 1 with the command to switch it off; polyctl never switches it off. Elastic IPs and snapshots are not deleted. The stored Windows login and the key pair polyctl created for the instance are removed.

**password `<name|id>` `[--key-file <path>]`** (Windows; shared behaviour in [Instances](../instances.md#windows-passwords)) shows the stored login. With nothing stored it asks AWS again (`GetPasswordData`) and decrypts with the stored private key or `--key-file`, then stores the password. `--key-file` also works for a Windows instance polyctl did not create. A password AWS has not generated yet is exit code 4 ("try again in a few minutes"); nothing stored and no `--key-file` (or a key pair of yours without `--key-file`) is exit code 4 with a hint. ED25519 key pairs cannot decrypt Windows passwords.

**ssh-key list|add|remove** (shared behaviour in [Instances](../instances.md#managing-ssh-keys)) edits `~/.ssh/authorized_keys` over SSH or AWS temporary access; the instance must be running.

- **Login users** follow the image (`ec2:DescribeImages`): `ec2-user` for Amazon Linux, Oracle Linux, FreeBSD and macOS; `ubuntu` for Ubuntu; `admin` for Debian; `centos` then `ec2-user` for CentOS; `fedora` then `ec2-user` for Fedora; `ec2-user` then `root` for RHEL and SUSE; `rocky` for Rocky Linux; `bitnami` for Bitnami. Other or unreadable images try `ec2-user`, `ubuntu`, `admin`, `centos`, `rocky`, `fedora`, `bitnami`, `root` in turn. `--login-user` skips this.
- **Key pair**: the instance's `KeyName`. If that key pair was deleted, no local key is tried.
- **Temporary access**, in this order:
  - **Systems Manager Run Command** (`AWS-RunShellScript`): needs the SSM Agent online (preinstalled on Amazon Linux 2/2023 and Ubuntu Server images) and an instance profile that allows Systems Manager (such as `AmazonSSMManagedInstanceCore`, or Default Host Management Configuration). No network path to the instance is needed. A command whose result cannot be read was sent and may have run.
  - **EC2 Instance Connect**: pushes a one-time key valid for 60 seconds, then logs in over SSH, so the security group must let you reach port 22. Needs EC2 Instance Connect on the image (Amazon Linux 2023, Amazon Linux 2 since 2019-06, Ubuntu 20.04+; minimal and ECS-optimized Amazon Linux, Debian, RHEL and SUSE need it installed).
  - Both denied: exit code 3. One denied and the other unusable: exit code 1, with both reasons.
- **IAM actions**: `ec2:DescribeInstances`, `ec2:DescribeImages`, `ec2:DescribeKeyPairs`; for temporary access `ssm:DescribeInstanceInformation`, `ssm:SendCommand` (on the instance and on `arn:aws:ssm:<region>::document/AWS-RunShellScript`), `ssm:GetCommandInvocation` and `ec2-instance-connect:SendSSHPublicKey` (on the instance).

Errors: missing capacity (`InsufficientInstanceCapacity`) and exhausted quotas (`VcpuLimitExceeded`, `InstanceLimitExceeded`) are exit code 1 with advice.

## Instance sizes

`--type` of `create` and `resize` (and `defaults.aws.instance_type`) accepts a size `<cores>H<memory>G`, such as `2H4G`, `4H8G` or `2H0.5G`. A size is resolved on every run (also with `--dry-run`) in the subnet's or instance's availability zone:

1. The T3 type of exactly that shape, if offered: `t3.nano` (2H0.5G), `t3.micro` (2H1G), `t3.small` (2H2G), `t3.medium` (2H4G), `t3.large` (2H8G), `t3.xlarge` (4H16G), `t3.2xlarge` (8H32G).
2. Otherwise a current-generation x86_64 type with exactly that vCPU count and memory, by family: `t3`, `t3a`, `m7i`, `m6i`, `c7i`, `c6i`, `r7i`, `r6i`, `m5`, `c5`, `r5`, then the rest alphabetically. Prices are not compared.

The choice is printed on stderr (`2H4G -> t3.medium (ap-east-1a, T3 preset)`). Sizes always resolve to x86_64; arm64 needs an exact type (a size with `--arch arm64` is exit code 2). No fit is exit code 4. On `resize`, an instance that already has that shape is `unchanged`.

## EC2 key pairs

Key pairs belong to one region (`--region`, default the profile's). AWS accepts RSA and ED25519 public keys only; others are exit code 2.

- `--ssh-key` takes the public key line itself, `--ssh-key-file` a file holding it (`~` expanded). A path in `--ssh-key`, both flags, a private key or invalid text are exit code 2. Public keys are never printed in full.
- `key-pair list` shows name, type, fingerprint and creation time. `fingerprint` in JSON is what AWS reports (base64 SHA-256 for ED25519; hex MD5 for imported RSA, SHA-1 for AWS-generated RSA); the table prefixes ED25519 fingerprints with `SHA256:`.
- `key-pair import <name>` imports a key. A taken name is exit code 2; existing key pairs are never replaced. On a terminal a missing key is picked from `~/.ssh/*.pub`, a path or typed in.
- `key-pair ensure [<name>]` reuses a key pair that already holds the key (`unchanged`, under its own name), otherwise imports it as `<name>`. Without `<name>` a terminal asks for one; the non-interactive flow is exit code 2 (no name is ever invented). The same key under several names: `<name>` picks one, else a terminal asks, else exit code 5. A `<name>` that exists with another key is exit code 2.
- There is no `key-pair delete`.

## EC2 security groups

Groups belong to one region and VPC. A group is named by id (`sg-...`) or name; a name is looked up in `--vpc`, else `defaults.aws.vpc_id`, else every VPC of the region (a name in several VPCs is exit code 5). A malformed id is exit code 2.

**Rule format**: `<protocol>:<port|from-to|alias|all>:<source>`

- protocol: `tcp`, `udp`, `icmp`, `all`
- port: a number, a range (`8000-8999`, `ssh-http`), `all`, or an alias: `ssh`, `telnet`, `smtp`, `dns`, `http`, `pop3`, `imap`, `https`, `smb`, `mssql`, `mysql`, `rdp`, `postgresql`/`postgres`, `redis`, `elasticsearch`/`elastic`, `mongodb`/`mongo`
- source: an IPv4/IPv6 CIDR (a bare address gets `/32` or `/128`) or a security group id of the same account. ICMP from an IPv6 source is ICMPv6.

Examples: `tcp:https:0.0.0.0/0`, `tcp:22:10.0.0.0/8`, `icmp:all:::/0`. Rules are compared by protocol, ports and source, not description. Only ingress rules are managed; new groups keep the AWS default allow-all egress.

- `list` reads the inventory; `--region`, `--vpc`, `--name` (`*` wildcard) and `--instance` ask AWS.
- `get` shows the group, its ingress rules and the instances using it.
- `create <name>` creates the group in `--vpc` (default `defaults.aws.vpc_id`; neither: exit code 2) with `--description` (default `auto created <name>`; AWS cannot change it later) and the `--rule` rules, each with `--rule-description`. An existing name is exit code 1 (use `ensure`). Names may not start with `sg-`; names and descriptions are ASCII, at most 255 characters. New groups are tagged `Name=<name>` and `polyctl:managed=true`.
- `ensure <name> [--instance <name|id>]` creates the group if missing, adds missing rules and attaches the group to the instance, keeping the instance's other groups. Rules are never removed. VPC: `--vpc`, else the instance's, else `defaults.aws.vpc_id`. An instance with 5 groups already (the default quota) is exit code 1; one with several network interfaces exit code 7.
- `rule add` adds rules to an existing group; `rule remove` removes the listed rules after confirmation.
- `delete` asks for confirmation. A group still attached or referenced by another group's rule is exit code 1 (`DependencyViolation`); a VPC's default group is refused.

Quotas (`RulesPerSecurityGroupLimitExceeded`: 60 ingress rules per group by default, IPv4 and IPv6 counted apart; `SecurityGroupsPerInstanceLimitExceeded`) are exit code 1.

## EBS volumes and snapshots

Volumes are named by id (`vol-...`) or Name tag.

- `volume list` reads the profile's region live (`--offline`: from the inventory). Filters: `--instance`, `--state` (`available` lists unattached volumes, such as data disks left by deleted instances), `--az`, `--name` (`*` / `?`).
- `volume get` shows a volume, its attachments and its latest modification.
- `volume create [<name>]` — `--size <GB>` for an empty volume, or `--from-snapshot <snap-id>` (`--size` may only grow it). One of `--az` or `--instance` is required (the volume must be in the instance's zone). Type `gp3` (3000 IOPS, 125 MiB/s) by default; `io1` / `io2` need `--iops`; `gp2`, `st1`, `sc1` take neither IOPS nor throughput. A name already used in the region is exit code 1.
- `volume resize` — `--size` (grow only), `--type`, `--iops`, `--throughput`; only given fields change. Pick the volume by id/name or by `--instance [--device]` (default: the root device). Waits until `optimizing` (`--wait-complete`: until `completed`, which can take hours; timeout then defaults to 6h). AWS allows one modification about every six hours (`VolumeModificationRateExceeded`, exit code 1); a modification still in progress is exit code 1. **polyctl does not grow the partition or file system**: it prints the commands to run inside the instance, such as `sudo growpart /dev/nvme0n1 1 && sudo xfs_growfs /`.
- `volume attach <vol> --instance <name|id> [--device /dev/sdb]` — same account, region and zone required (exit code 1). A device already in use is exit code 2. Inside a Nitro instance the volume appears as `/dev/nvme1n1` or similar; mounting is up to you.
- `volume detach <vol>` — unmount it first; asks for confirmation. Root volumes are exit code 1. `--force` can lose data and needs `--yes`.
- `volume delete <vol>` — shows the latest snapshot (or warns there is none) and asks. Attached volumes are exit code 1. Snapshots are kept.
- `snapshot list` lists snapshots the account owns in the region, newest first. Filters: `--volume` (also a deleted volume's id), `--state`, `--name`, `--latest` (newest completed). `--offline` is exit code 6.
- `snapshot create <vol>` — named `<volume-name>-<UTC time>` unless `--tag Name=...`. Snapshots are crash-consistent: stop writes or unmount first for a clean copy. One pending snapshot per volume at a time (exit code 1). `--wait` waits until completed (default timeout 30m). Deleting and copying snapshots are not supported.

Read a snapshot on a temporary instance:

```sh
polyctl aws ec2 instance create tmp --wait
polyctl aws ec2 volume create data --from-snapshot snap-0aaa --instance tmp --wait
polyctl aws ec2 volume attach data --instance tmp
# ... work ...
polyctl aws ec2 instance delete tmp --yes --wait
polyctl aws ec2 volume delete data --yes
```

Errors: AWS parameter errors are exit code 2; `VolumeLimitExceeded`, `InvalidVolume.ZoneMismatch`, `VolumeInUse` and `IncorrectState` are exit code 1.

## Elastic Load Balancing v2

Covers Network and Application Load Balancers, target groups and listeners. A load balancer is named by name, ARN or DNS name and found across accounts and regions; a listener is its ARN or `<lb>:<port>`.

### Put a Network Load Balancer in front of an instance

```sh
polyctl aws elbv2 load-balancer ensure site-xz7 --instance site-xz7 --dry-run
polyctl aws elbv2 load-balancer ensure site-xz7 --instance site-xz7 --listener tcp:80 --listener tcp:443
```

`load-balancer ensure <name> --instance <name|id>` makes sure that for every `--listener tcp:<port>` (default `tcp:80` and `tcp:443`; `--skip-https` means `tcp:80` only) a TCP target group holds the instance and a Network Load Balancer forwards that port to it. A second run changes nothing.

- Names come from `naming.aws_elbv2_load_balancer` (`{name}-lb`) and `naming.aws_elbv2_target_group` (`{name}-{port}-target`). Names are at most 32 letters, digits and hyphens, so with the defaults `<name>` can have at most 21 characters. Changing a template makes `ensure` build a new set.
- The instance must be running. Target groups are created in its VPC; `--target-type ip` registers its private address instead of its id. An existing target group with another protocol, port, VPC or target type is exit code 1.
- A new load balancer is internet-facing, in the instance's subnet or `--subnet` (which must include the instance's zone), with `--sg` or `defaults.aws.elb_security_group_ids`. **A Network Load Balancer created without security groups can never get any.** An existing one must be a network load balancer in the instance's VPC and zone.
- Listeners pointing elsewhere are modified in place, never deleted.
- Nothing is rolled back on failure; run `ensure` again to continue.
- Prints the DNS name and its addresses (`# load balancer` block). `--wait-healthy` also waits until the instance is healthy.
- Client addresses reach the instance unchanged: open the listener ports in the instance's security group (`aws ec2 security-group ensure ... --rule tcp:80:0.0.0.0/0`). TLS on 443 passes through to the instance.
- `--type application` and protocols other than `tcp` are exit code 7; build Application Load Balancers with `create`, `target-group` and `listener`.

### Load balancers

- `list` reads the inventory (`--region` asks AWS); `--type`, `--name` (`*` / `?`) filter.
- `get` shows zones, security groups, attributes, listeners, target groups and target health.
- `create <name> --type network|application --subnet <id>...` — `--scheme` (default `internet-facing`), `--ip-address-type` (default `ipv4`), `--sg`. An existing name is exit code 1. New resources are tagged `polyctl:managed=true`. `--wait` waits until active (about 2-3 minutes).
- `update` changes only what its flags name: `--sg` and `--subnet` replace the lists, `--ip-address-type`, `--deletion-protection[=false]`, `--cross-zone[=false]`. No flag is exit code 2.
- `delete` asks for confirmation. Listeners go with it; target groups stay unless `--cascade` (groups still used by another load balancer are skipped). Deletion protection is exit code 1; polyctl never switches it off.

### Target groups and listeners

- `target-group list [--lb] [--vpc]`, `target-group get`.
- `target-group create <name> --protocol <p> --port <n>` — VPC from `--vpc` or `defaults.aws.vpc_id`; `--target-type instance|ip`; health check via `--health-check-protocol`, `--health-check-port`, `--health-check-interval` (5-300 s); `--target <id>[:<port>]` registers targets (`[2001:db8::1]:80` for IPv6).
- `target-group update` — `--add-target`, `--remove-target`, or `--set-target` (exactly these targets on the ports named; not combinable with the other two); health check protocol and interval. Protocol, port, VPC and target type cannot change. Deregistered targets drain first (300 s by default).
- `target-group delete` asks; a group still in use is exit code 1.
- `listener create <lb> --protocol <p> --port <n> --target-group <name|arn>` — `TLS` / `HTTPS` need `--cert <acm-arn>`. An existing port is exit code 1 (use `update`).
- `listener update` changes target group and protocol in place; `listener delete` asks (the target group stays).

Errors: AWS `ValidationError` is exit code 2 (exit code 1 for target registration and IP address type); resources in use, deletion protection, `InvalidConfigurationRequest` and quotas (`TooManyLoadBalancers`, `TooManyTargets`, ...) are exit code 1.

## Certificate Manager (ACM)

ACM certificates belong to one region of one account. CloudFront uses `us-east-1`; a load balancer uses its own region.

**Key types**: ACM lists only RSA certificates unless key types are named, so `list` and `get` take `--key-type` (repeatable or comma-separated; default `EC_prime256v1,RSA_2048` from `defaults.aws.acm.default_key_types`). Values: `RSA_1024`, `RSA_2048`, `RSA_3072`, `RSA_4096`, `EC_prime256v1`, `EC_secp384r1`, `EC_secp521r1`, `ML_DSA_44`, `ML_DSA_65`, `ML_DSA_87`.

- `certificate list` reads the inventory of the profile's region; `--region <r>` asks AWS, `--region all` lists every cached region. Filters: `--status` (`PENDING_VALIDATION`, `ISSUED`, `INACTIVE`, `EXPIRED`, `VALIDATION_TIMED_OUT`, `REVOKED`, `FAILED`), `--domain`.
- `certificate get <domain|arn>` — a domain matches certificates whose primary name is the domain or its wildcard (other names are not matched); of several, the best (issued, latest expiry) is shown. `--validation-records` adds the DNS validation records; they are always shown for `PENDING_VALIDATION`, with the hours left of ACM's 72-hour window and the `dns ensure` command to write them.
- `certificate request <domain>` requests a DNS-validated public certificate:

  ```sh
  polyctl aws acm certificate request example.com --region us-east-1
  ```

  - Default `*.<domain>` plus `<domain>` (`--wildcard`, `defaults.aws.acm.wildcard`); `--wildcard=false` requests `<domain>` alone. `--san` adds names (10 per certificate by default).
  - `--key-algorithm` (default `defaults.aws.acm.default_key_algorithm`, built-in `EC_prime256v1`).
  - An existing certificate with the same names and key algorithm (pending or issued) is reused (`unchanged`); it never creates duplicates.
  - Waits for the validation records (`--timeout 5m`) and prints the `polyctl dns ensure <domain> --record <name>:CNAME:<value>:300:false` command that writes them. **`request` does not write DNS** and does not wait for issuance. Keep the records while the certificate is in use: ACM renews through them.
  - Names ACM refuses (such as under `example.com`) fail with the reason (exit code 1). EMAIL validation is not supported.
- `certificate import <domain>` imports the certificate from the local store (see [Certificates](../commands.md#certificates)), `--staging` from the staging store, or from `--cert-file`, `--key-file` (unencrypted) and `--chain-file`. An imported certificate of the same domain in the region is **re-imported in place, keeping its ARN**, so load balancers and CloudFront need no change. `--arn` names the target; `--new` imports a new certificate (tagged `polyctl:domain=<domain>`). A different key algorithm, an expired certificate or an Amazon-issued target is exit code 1. The same serial number is `unchanged`; several candidates are exit code 5.

## RDS database instances

`create` supports MySQL only (other engines: exit code 7). The other commands work for any engine except Aurora (exit code 7). Instances are named by identifier or endpoint DNS name and found across accounts and regions.

- `list` reads the inventory of the profile's region (`--region <r>` or `all`); filters `--state`, `--class`, `--name` (glob).
- `get` reads the instance live.

**create `<id>`**

```sh
printf '%s\n' "$PW" | polyctl aws rds instance create db-test-01 --size 20 --az eu-west-1a --password-stdin
RDS_PW=... polyctl aws rds instance create db-test-01 --size 50 --az eu-west-1a --password-env RDS_PW --class db.t3.medium
```

- Required: `--size <GB>`, `--az` (use the zone of the instances that use the database: cross-zone traffic costs money), and the master password from `--password-stdin` or `--password-env <VAR>` (at least 8 characters; never taken as an argument, never printed or stored).
- Identifier: starts with a letter, ASCII letters, digits and hyphens, at most 63 characters.
- Version: `--engine-version`, or `latest` (default) = newest of `--major` (default `8.0` or `defaults.aws.rds.default_major`).
- Defaults: `--class` (`defaults.aws.rds.default_class`, else `db.m5.large`), `--master-user admin`, `--storage-type` (`defaults.aws.rds.default_storage_type`, else `gp3`; minimum 5 GB for gp2/standard, 20 GB for gp3, 100 GB for io1/io2), `--max-size 1000` (autoscaling limit; 0 turns it off), `--subnet-group`, `--security-group`, `--parameter-group` (from `defaults.aws.rds.subnet_group`, `security_group_ids`, `parameter_group`; without them AWS uses the default VPC), `--backup-retention 7`, `--backup-window 03:00-04:00`, `--maintenance-window sun:04:00-sun:05:00` (UTC), not public unless `--public`.
- Tags: `Name=<id>`, `defaults.aws.tags`, `defaults.aws.rds.default_tags`, `--tag`.
- An existing identifier is exit code 1. Waits until available (`--timeout 30m`; about 7 minutes for a small instance) and prints `RDS_ENDPOINT=` and `RDS_PORT=`. A failed wait keeps the instance.

**start / stop** — work on `available` / `stopped` instances; one already there (or on its way) is `unchanged`. `stop` takes no snapshot. AWS cannot stop read replicas, instances with replicas, or SQL Server Multi-AZ.

**AWS restarts a stopped instance after 7 days.** Keep instances stopped with a daily `ensure`:

```sh
0 3 * * * polyctl aws rds instance ensure db-test-01 db-test-02 --state stopped >>/var/log/polyctl-rds.log 2>&1
```

`ensure <id>... --state stopped|running` (`available` is an alias of `running`) waits for instances in transition, then stops or starts them. Instances being created, deleted or broken are `skipped` and count as failures. All instances are handled even when one fails (`--continue-on-error=false` stops at the first). Exit code 0 when all are as asked, 4 when every failure is a missing instance, 1 otherwise; failures are sent to `hooks.on_failure` as `aws.rds.instance.ensure.failed`.

**resize `--class <c>`** applies at once: **the instance restarts** (a few minutes of downtime; a failover for Multi-AZ). A stopped instance is exit code 1. Waits until the new class is in place (`--timeout 60m`).

**delete** — takes a final snapshot `<id>-final-snapshot` unless `--final-snapshot <name>` or `--skip-final-snapshot` (data gone for good). An existing snapshot name is exit code 1. Automated backups are deleted with the instance. Asks `Delete RDS instance <id>? (y/N)`. Deletion protection is switched off first unless `--keep-protection` (then exit code 1). `--wait` waits until gone (`--timeout 60m`).

Errors: `DBInstanceNotFound` is exit code 4; other RDS errors are exit code 1 with the AWS code, message and a hint (for example a zone missing from the subnet group, or `InsufficientDBInstanceCapacity`).
