#!/bin/sh
# Generates shell completion scripts into ./completions for release archives.
set -eu

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

rm -rf completions
mkdir -p completions
for shell in bash zsh fish; do
	POLYCTL_CONFIG_DIR="$tmp" POLYCTL_CREDENTIAL_STORE=file \
		go run ./cmd/polyctl completion "$shell" >"completions/polyctl.$shell"
done
