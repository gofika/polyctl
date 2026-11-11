# Releasing polyctl

For maintainers. End users do not need this.

## Cutting a release

```sh
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` then runs the tests and GoReleaser
(`.goreleaser.yaml`), which:

1. builds `polyctl` for macOS, Linux and Windows on amd64 and arm64 with the
   version baked in;
2. publishes a GitHub Release with `polyctl_<version>_<os>_<arch>.tar.gz`
   (`.zip` on Windows) and `checksums.txt`;
3. commits `Casks/polyctl.rb` to `gofika/homebrew-tap`;
4. commits `bucket/polyctl.json` to `gofika/scoop-bucket`.

The tag is the only source of the version. `install.sh` and `install.ps1`
resolve the latest release at run time, so they need no change per release.

Tags with a pre-release suffix (`v0.2.0-rc1`) are published as GitHub
pre-releases and do not touch the tap or the bucket.

## One-time setup

The default `GITHUB_TOKEN` can only write to `gofika/polyctl`. Pushing to the
tap and the bucket needs tokens stored as Actions secrets (repository or
organization level):

| Secret | Needs |
| --- | --- |
| `HOMEBREW_TAP_GITHUB_TOKEN` | Contents: read and write on `gofika/homebrew-tap` |
| `SCOOP_BUCKET_GITHUB_TOKEN` | Contents: read and write on `gofika/scoop-bucket` |

One fine-grained personal access token covering both repositories can be
stored under both names. When a secret is missing the release still
publishes; only that package manager is skipped.

Both repositories must exist before the first tag, be public, and have at
least one commit (a README is enough) so that the default branch exists.
GoReleaser does not create them: with a token set and the repository missing,
the GitHub Release is published first and the run then fails, and the same
tag cannot simply be re-run because its assets already exist. A fine-grained
token also cannot be granted access to a repository that does not exist yet.

## Dry run

```sh
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```

The archives, the generated cask (`dist/homebrew/Casks/polyctl.rb`) and the
Scoop manifest (`dist/scoop/bucket/polyctl.json`) land in `dist/`.
