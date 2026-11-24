# Development

How the code is organised, what the local inventory stores, and how to check and release changes.

- [Project layout](#project-layout)
- [Adding a platform](#adding-a-platform)
- [`inventory.db` schema](#inventorydb-schema)
- [Local CI](#local-ci)
- [Releasing](#releasing)
- [Roadmap](#roadmap)

## Project layout

```text
cmd/polyctl/            main(): calls internal/cli.Main and exits with its code
internal/cli/           Cobra command tree (root, auth, dns, domain, cert, find, sync/inventory, platform mounts),
                        exit-code mapping
internal/app/           Runtime shared by all commands: config, credential store, inventory, profile selection,
                        domain and resource routing, cache policy, sync, --dry-run and change reports, --wait flags,
                        defaults and naming, hooks.on_failure, domain ns check, find
internal/platform/      Provider-neutral contracts (Provider, Client, DNSService, RegistrarService,
                        LoadBalancerService, certificate deployers), resource types, sentinel errors, registry,
                        DNS helpers, the change plan of ensure commands, waits and retries, shared parsers
internal/providers/
  cloudflare/ namecom/ godaddy/ aws/ gcp/ aliyun/
                        One package per platform: provider.go (login, client, sync), commands.go (command tree),
                        a client file and a command file per service, certdeploy.go and find.go where present
internal/cert/          Certificate store, ACME account and issuance (lego), DNS-01 records, propagation check,
                        cert ensure and cert deploy flows
internal/config/        config.yaml loading/saving, TTL defaults, defaults / naming / hooks / cert / dns settings
internal/creds/         Keyring store, 0600 file store, Multi (read from any, write to primary)
internal/secrets/       Instance logins sealed with AES-256-GCM in inventory.db, Windows password generator
internal/inventory/     SQLite schema, Replace/Upsert/Delete, Purge/RenameProfile, domain lookup, IP index, stats
internal/output/        table / json / yaml rendering
internal/sshremote/     SSH login to instances and the authorized_keys edit script; sshtest/ is a test server
internal/dnstest/       Fake DNS resolvers on 127.0.0.1 for tests
internal/httpx/         JSON REST client with retries (Cloudflare, name.com, GoDaddy)
internal/prompt/        Line / secret / confirm prompts and the arrow-key Picker, drawn on stderr
internal/browser/       Open a URL in the default browser
internal/loopback/      127.0.0.1 listener for the redirect of a browser login (GCP, Cloudflare)
```

## Adding a platform

1. Implement `platform.Provider` (and `DNSService` / `RegistrarService` as applicable) in a new `internal/providers/<name>` package.
2. Register it in `init()`.
3. Mount its Cobra subtree in `internal/cli/platforms.go`.

Neutral commands, routing, caching and output need no changes.

## `inventory.db` schema

A WAL-mode SQLite database. `polyctl inventory path` prints the file in use (`POLYCTL_INVENTORY_DB`, otherwise `<config dir>/inventory.db`).

```sql
CREATE TABLE resources (
  platform      TEXT    NOT NULL,     -- cloudflare, aws, ...
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,     -- see the resource types in docs/configuration.md
  resource_id   TEXT    NOT NULL,     -- platform-native id (domain name for type domain)
  name          TEXT    NOT NULL,
  parent_id     TEXT    NOT NULL DEFAULT '',   -- zone id for dns_record
  domain        TEXT    NOT NULL DEFAULT '',   -- apex / zone name used for routing
  data          TEXT    NOT NULL,     -- JSON, the platform-native object
  updated_at    INTEGER NOT NULL,     -- unix seconds
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, resource_id)
);

CREATE TABLE domain_index (            -- domain -> owning zone / registered domain
  domain        TEXT NOT NULL,
  platform      TEXT NOT NULL,
  profile       TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   TEXT NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (domain, platform, profile, resource_type, resource_id)
);

CREATE TABLE ip_index (                -- address / prefix / DNS name -> resource (polyctl find)
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,     -- instance, load_balancer, eip, db_instance
  resource_id   TEXT    NOT NULL,
  ip            TEXT    NOT NULL,     -- canonical address, masked prefix ("10.1.2.0/24") or DNS name
  kind          TEXT    NOT NULL,     -- internal, external, dns, reserved
  prefix_bits   INTEGER NOT NULL DEFAULT 0,   -- prefix length of a prefix, 0 otherwise
  PRIMARY KEY (platform, profile, resource_type, resource_id, ip, kind)
);

CREATE TABLE instance_secrets (        -- Windows logins of created instances, sealed
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  location      TEXT    NOT NULL,     -- region, or zone where instances live in one
  instance_id   TEXT    NOT NULL,
  name          TEXT    NOT NULL,     -- instance name when stored
  user          TEXT    NOT NULL,     -- login user name (not secret)
  nonce         BLOB    NOT NULL,     -- AES-GCM nonce, fresh for every write
  secret        BLOB    NOT NULL,     -- AES-256-GCM ciphertext of the password (and an AWS private key)
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, location, instance_id)
);

CREATE TABLE sync_state (              -- freshness of each synced set
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  scope         TEXT    NOT NULL DEFAULT '',   -- '' = whole type, or a zone id for per-zone record sets
  synced_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, scope)
);
```

- `resources.data` keeps the platform-native object, so `-o json` on a cached read shows the same fields as a live read. The JSON version is SQLite's `user_version`; DNS records written by 0.1.x have their `content` field renamed to `value` when the database is opened.
- `domain_index` is rebuilt from `zone` and `domain` resources on every sync. DNS records are not indexed; they are looked up through their zone.
- `ip_index` is written with every resource that carries addresses (all interface, secondary and alias addresses of an instance, load balancer addresses and DNS names, elastic / static addresses, database endpoints). A prefix matches every address it contains. Older databases get the table on first use and fill it on the next sync.
- Everything except `instance_secrets` is a cache: deleting the file is safe, polyctl re-fetches on demand.
- `instance_secrets` is not a cache. Sync and `--refresh` leave it alone, `auth rename` moves its rows, `auth logout` detaches them (profile column set to `<profile>/detached`, readable by instance id only), and deleting the file loses stored Windows passwords, which no platform can show again.

## Local CI

Run before every push:

```sh
scripts/ci-local.sh
```

It runs locally, in parallel, what `.github/workflows/ci.yml` runs on GitHub, and exits non-zero when any check fails:

| Check | What it does |
| --- | --- |
| `host` | `gofmt -l`, `go vet ./...`, `go test ./...` on this machine |
| `linux`, `darwin`, `windows` | `go vet` and compiled (not run) tests for each OS; on windows also fails a test that sets `HOME` without `USERPROFILE` |
| `crlf` | `go test ./...` in a temporary worktree checked out with CRLF line endings, as on `windows-latest` (tests `HEAD`, not uncommitted changes) |
| `release` | Builds the binary for every `.goreleaser.yaml` target with `CGO_ENABLED=0` |
| `scripts` | `shellcheck` of `install.sh` and `scripts/*.sh`; parses `install.ps1` when `pwsh` is installed |

Other `make` targets: `build` (writes `bin/polyctl`), `install`, `test`, `vet`, `fmt`, `lint`, `clean`.

## Releasing

See [RELEASING.md](../RELEASING.md).

## Roadmap

Current coverage is the common operations, not each cloud's whole surface:

- **Alibaba Cloud**: ECS instance lifecycle, security groups, key pairs and latest system image (`aliyun ecs`), VPCs and vSwitches (`aliyun vpc`), elastic IPs (`aliyun eip`), ALB load balancers, listeners, server groups and ACLs (`aliyun alb`), Certificate Management Service (`aliyun cas`).
- **AWS**: EC2 instance lifecycle, key pairs, security groups, EBS volumes and snapshots, ELBv2 load balancers, target groups and listeners, ACM certificates (list, get, request, import), RDS instances (MySQL create, start, stop, resize, delete, ensure).
- **GCP**: Compute Engine instance lifecycle, VPC firewall rules, read-only VPC networks and subnetworks, SSL certificates, regional external load balancers and their components.
- **`cert deploy`**: ALB listeners, GCP HTTPS proxies and ACM imported certificates; no deployer for Tencent Cloud or other CDN platforms yet.
- **Cloudflare**: zones, DNS, cache purge, cache rules, redirect rules, development mode, SSL mode and R2 bucket custom domains. Workers, Pages, Access and R2 contents are not exposed.
- **Registrars** (GoDaddy, name.com): nameservers, lock, auto-renew and availability. Transfers, contacts and purchases are not planned for the first releases.
- **Out of scope for now**: object storage, IAM, Alibaba Cloud CDN / ESA.

Planned: record import/export (zone file and bulk JSON), `polyctl domain expiring` across registrars, an encrypted file fallback for the credential store, and `--watch` for `inventory stats`.
