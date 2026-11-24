# polyctl

`polyctl` is one command-line tool for the accounts small teams juggle: cloud platforms (AWS, GCP, Alibaba Cloud), CDN/DNS (Cloudflare) and domain registrars (name.com, GoDaddy).

Platform-neutral commands (`dns`, `domain`, `cert`, `find`) find the account that owns a domain or address and route the call there; platform-specific commands (`cloudflare`, `aws`, ...) expose each platform's native features. What polyctl learns about your accounts is cached in a local SQLite inventory, so reads are fast and work offline.

## Features

- Six platforms: Cloudflare, name.com, GoDaddy, AWS, GCP, Alibaba Cloud.
- Profiles: one profile holds one account per platform a project uses; keep as many profiles as you have projects or customers.
- Secrets in the OS keyring (macOS Keychain, Windows Credential Manager, Secret Service), falling back to a `0600` file; `config.yaml` never holds a secret.
- Domain routing: `polyctl dns list example.com` picks the right zone and account. A domain found in two accounts is reported, not guessed; `--profile` and `--platform` pick one.
- Reverse lookup: `polyctl find 203.0.113.10` lists the instances, load balancers, elastic / static IPs and database endpoints holding an address or DNS name, in every account.
- Certificates: `polyctl cert ensure` issues and renews Let's Encrypt certificates through DNS-01; `polyctl cert deploy` puts them on Alibaba Cloud ALB and CAS, GCP HTTPS proxies and AWS ACM.
- Cloud resources: instances (EC2, Compute Engine, ECS), security groups and firewalls, load balancers, EBS volumes and snapshots, RDS, key pairs, elastic IPs, VPCs and platform certificates.
- Idempotent `ensure` commands that change only what differs and print a change report; `--dry-run` on any write command; destructive commands ask first (`--yes` in scripts).
- `table`, `json` and `yaml` output; distinct exit codes; shell completion for bash, zsh, fish and PowerShell.

## Install

Prebuilt binaries for macOS, Linux and Windows (x86-64 and ARM64); no Go toolchain needed.

### Homebrew (macOS, Linux)

```sh
brew install --cask gofika/tap/polyctl
```

Installs bash, zsh and fish completions too. Upgrade with `brew upgrade --cask polyctl`.

### Scoop (Windows)

```powershell
scoop bucket add gofika https://github.com/gofika/scoop-bucket
scoop install polyctl
```

Upgrade with `scoop update polyctl`.

### Install script

```sh
# macOS, Linux: installs into ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/gofika/polyctl/main/install.sh | sh
```

```powershell
# Windows: installs into %LOCALAPPDATA%\polyctl\bin and adds it to your user PATH
irm https://raw.githubusercontent.com/gofika/polyctl/main/install.ps1 | iex
```

The scripts verify the SHA-256 checksum of the download. Run the same command again to upgrade.

| Variable | Effect |
| --- | --- |
| `POLYCTL_VERSION` | Install this version (for example `0.1.2`) instead of the latest release. |
| `POLYCTL_INSTALL_DIR` | Install the binary into this directory. |

```sh
curl -fsSL https://raw.githubusercontent.com/gofika/polyctl/main/install.sh | POLYCTL_VERSION=0.1.2 POLYCTL_INSTALL_DIR="$HOME/bin" sh
```

### Manual download

Download the archive for your platform from the [releases page](https://github.com/gofika/polyctl/releases), check it against `checksums.txt`, and put `polyctl` on your `PATH`.

### Build from source

Requires Go.

```sh
git clone https://github.com/gofika/polyctl.git
cd polyctl
make build        # writes bin/polyctl
```

### Shell completion

Homebrew installs completions, and release archives ship them under `completions/`. To generate them:

```sh
polyctl completion bash > /etc/bash_completion.d/polyctl        # or: source <(polyctl completion bash)
polyctl completion zsh > "${fpath[1]}/_polyctl"                 # then restart the shell
polyctl completion fish > ~/.config/fish/completions/polyctl.fish
polyctl completion powershell | Out-String | Invoke-Expression
```

Completion knows your profiles (`--profile`, `auth use`, `auth rename`), platform names (`auth login`, `auth logout`, `--platform`) and the indexed domains (the `<domain>` argument of `dns`, `domain` and `cert`). A bad setting (an unknown `POLYCTL_OUTPUT`, a broken `config.yaml`) does not break it: the script is still printed, and only the candidates read from the configuration are left out.

## Quick start

```sh
# 1. Log in (secrets go to the keyring). The first login creates the profile
#    "default" and makes it current; later logins add their platform to it.
polyctl auth login cloudflare
polyctl auth login namecom
polyctl auth login aws --set method=sso --set start_url=https://acme.awsapps.com/start --set sso_region=us-east-1

#    A second project gets its own profile
polyctl auth login cloudflare --profile acme
polyctl auth login godaddy    --profile acme

# 2. Check the logins
polyctl auth status

# 3. Build the domain index (which account owns which domain / zone)
polyctl domain index

# 4. Platform-neutral commands route automatically
polyctl domain which example.com
polyctl dns list example.com
polyctl dns set example.com --type A --name www --value 203.0.113.10
polyctl dns ensure example.com -r www:A:203.0.113.10:300 -r @:MX:"10 mail.example.com"
polyctl domain ns set example.com ns1.cloudflare.com ns2.cloudflare.com

#    When several accounts know the domain, say which one
polyctl dns list example.com --profile acme --platform cloudflare

# 5. Or use one platform directly
polyctl aws ec2 instance list
polyctl cloudflare zone list --profile acme
```

Status lines go to stderr and results to stdout, so `polyctl dns list example.com -o json | jq` works.

## Documentation

| Page | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Environment variables, global flags, `config.yaml`, credential storage, caching, output formats, dry runs, exit codes, security notes |
| [Accounts and profiles](docs/accounts.md) | Profiles, interactive profile management, login flows per platform, upgrading from 0.1.x |
| [Interactive and non-interactive use](docs/interactive.md) | Interactive and non-interactive flows, missing input, the list of confirmations |
| [Commands](docs/commands.md) | Platform-neutral commands (DNS, domains, certificates, `find`), routing rules, conventions of the platform commands |
| [Instance login](docs/instances.md) | Windows login credentials and SSH keys of Linux instances |
| [Cloudflare](docs/platforms/cloudflare.md) | Cloudflare commands and token permissions |
| [name.com](docs/platforms/namecom.md) | name.com commands and API access |
| [GoDaddy](docs/platforms/godaddy.md) | GoDaddy commands and API access |
| [AWS](docs/platforms/aws.md) | AWS commands and IAM permissions |
| [GCP](docs/platforms/gcp.md) | Google Cloud commands and roles |
| [Alibaba Cloud](docs/platforms/aliyun.md) | Alibaba Cloud commands and RAM permissions |
| [Development](docs/development.md) | Project layout, inventory schema, local CI, releasing, roadmap |

## License

[MIT](LICENSE)
