#!/usr/bin/env bash
# Runs locally what .github/workflows/ci.yml runs on GitHub, before a push.
#
# - gofmt, go vet and go test on this machine;
# - go vet and compiled (not run) tests for linux, darwin and windows,
#   so code that does not build on another platform fails here;
# - go test in a temporary worktree checked out with CRLF line endings,
#   as actions/checkout does on windows-latest (core.autocrlf=true);
# - shellcheck of the install scripts, and a parse of install.ps1 when
#   pwsh is installed.
#
# The checks run in parallel; the script exits non-zero when any fails.
# Usage: scripts/ci-local.sh
set -u

root=$(git rev-parse --show-toplevel)
cd "$root" || exit 1
logs=$(mktemp -d)
crlf=""
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
	if [ -n "$crlf" ]; then
		git worktree remove --force "$crlf" >/dev/null 2>&1
	fi
	rm -rf "$logs"
}
trap cleanup EXIT

check_host() {
	local out
	out=$(gofmt -l .)
	if [ -n "$out" ]; then
		echo "gofmt: files need formatting:"
		echo "$out"
		return 1
	fi
	go vet ./... && go test ./...
}

check_cross() {
	local goos=$1 pkg
	GOOS=$goos GOARCH=amd64 go vet ./... || return 1
	for pkg in $(go list ./...); do
		GOOS=$goos GOARCH=amd64 go test -c -o /dev/null "$pkg" || return 1
	done
}

check_crlf() {
	git -c core.autocrlf=true worktree add --quiet --detach "$crlf" HEAD || return 1
	(cd "$crlf" && go test ./...)
}

check_scripts() {
	shellcheck install.sh scripts/*.sh || return 1
	if command -v pwsh >/dev/null 2>&1; then
		# shellcheck disable=SC2016 # $e and $null are PowerShell variables
		pwsh -NoProfile -Command '$e = $null; [System.Management.Automation.Language.Parser]::ParseFile("'"$root"'/install.ps1", [ref]$null, [ref]$e) | Out-Null; if ($e) { $e; exit 1 }'
	else
		echo "pwsh not installed: install.ps1 not parsed"
	fi
}

# The CRLF worktree tests the committed HEAD; warn when the tree differs.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	echo "note: uncommitted changes are not in the CRLF worktree check (it tests HEAD)"
fi
crlf="$logs/crlf"

names=(host linux darwin windows crlf scripts)
check_host >"$logs/host.log" 2>&1 &
pids=($!)
for goos in linux darwin windows; do
	check_cross "$goos" >"$logs/$goos.log" 2>&1 &
	pids+=($!)
done
check_crlf >"$logs/crlf.log" 2>&1 &
pids+=($!)
check_scripts >"$logs/scripts.log" 2>&1 &
pids+=($!)

failed=0
for i in "${!names[@]}"; do
	if wait "${pids[$i]}"; then
		echo "ok    ${names[$i]}"
	else
		echo "FAIL  ${names[$i]}"
		sed 's/^/      /' "$logs/${names[$i]}.log" | tail -40
		failed=1
	fi
done
exit "$failed"
