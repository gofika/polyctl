#!/bin/sh
# polyctl installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/gofika/polyctl/main/install.sh | sh
#
# Environment:
#   POLYCTL_VERSION      version to install (e.g. 0.3.0 or v0.3.0); default: latest release
#   POLYCTL_INSTALL_DIR  directory for the binary; default: ~/.local/bin
set -eu

REPO="gofika/polyctl"
BASE_URL="${POLYCTL_BASE_URL:-https://github.com/${REPO}}"

say() { printf '%s\n' "$*"; }
fail() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# fetch <url> <output file>
fetch() {
	if have curl; then
		curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
	elif have wget; then
		# Only options that both GNU and BusyBox wget understand.
		wget -q -O "$2" "$1"
	else
		fail "curl or wget is required"
	fi
}

# latest_version prints the newest release tag by following the
# /releases/latest redirect (no API rate limit involved).
latest_version() {
	if have curl; then
		url=$(curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "${BASE_URL}/releases/latest") || url=""
	elif have wget; then
		url=$(wget -q -S --spider "${BASE_URL}/releases/latest" 2>&1 |
			awk '/^ *[Ll]ocation: /{u=$2} END{print u}' | tr -d '\r')
	else
		fail "curl or wget is required"
	fi
	case "$url" in
	*/releases/tag/*) printf '%s\n' "${url##*/}" ;;
	*) fail "could not determine the latest release (is one published at ${BASE_URL}/releases?)" ;;
	esac
}

sha256_of() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		fail "sha256sum, shasum or openssl is required to verify the download"
	fi
}

main() {
	case "$(uname -s)" in
	Darwin) os=darwin ;;
	Linux) os=linux ;;
	*) fail "unsupported operating system $(uname -s); on Windows use install.ps1" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) fail "unsupported architecture $(uname -m)" ;;
	esac
	# A translated (Rosetta) shell on Apple silicon still wants the arm64 build.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
		[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
		arch=arm64
	fi

	tag="${POLYCTL_VERSION:-}"
	if [ -z "$tag" ]; then
		tag=$(latest_version)
	fi
	case "$tag" in
	v*) ;;
	*) tag="v${tag}" ;;
	esac
	version="${tag#v}"

	install_dir="${POLYCTL_INSTALL_DIR:-}"
	if [ -z "$install_dir" ]; then
		[ -n "${HOME:-}" ] || fail "HOME is not set; set POLYCTL_INSTALL_DIR to choose an install directory"
		install_dir="${HOME}/.local/bin"
	fi
	archive="polyctl_${version}_${os}_${arch}.tar.gz"
	url="${BASE_URL}/releases/download/${tag}"

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	# Exit on a signal instead of carrying on; the EXIT trap still cleans up.
	trap 'exit 130' INT
	trap 'exit 143' TERM

	say "Downloading polyctl ${version} (${os}/${arch})..."
	fetch "${url}/${archive}" "${tmp}/${archive}" ||
		fail "download failed: ${url}/${archive}"
	fetch "${url}/checksums.txt" "${tmp}/checksums.txt" ||
		fail "download failed: ${url}/checksums.txt"

	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f {print $1}' "${tmp}/checksums.txt")
	[ -n "$want" ] || fail "${archive} is not listed in checksums.txt"
	got=$(sha256_of "${tmp}/${archive}")
	[ "$want" = "$got" ] || fail "checksum mismatch for ${archive} (expected ${want}, got ${got})"

	tar -xzf "${tmp}/${archive}" -C "$tmp" polyctl
	if ! mkdir -p "$install_dir" 2>/dev/null || [ ! -w "$install_dir" ]; then
		fail "cannot write to ${install_dir}; set POLYCTL_INSTALL_DIR to a writable directory or run the installer with sudo"
	fi
	# Install via rename so a running polyctl is never truncated in place.
	cp "${tmp}/polyctl" "${install_dir}/.polyctl.new.$$"
	chmod 755 "${install_dir}/.polyctl.new.$$"
	mv -f "${install_dir}/.polyctl.new.$$" "${install_dir}/polyctl"

	say "Installed ${install_dir}/polyctl"
	"${install_dir}/polyctl" --version || true

	case ":${PATH}:" in
	*":${install_dir}:"*) ;;
	*)
		say ""
		say "${install_dir} is not on your PATH. Add it with:"
		case "${SHELL:-}" in
		*/fish) say "  fish_add_path ${install_dir}" ;;
		*/zsh) say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.zshrc && exec zsh" ;;
		*/bash)
			# Terminal on macOS starts login shells, which skip ~/.bashrc.
			if [ "$os" = darwin ]; then
				say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.bash_profile && exec bash -l"
			else
				say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.bashrc && exec bash"
			fi
			;;
		*)
			say "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.profile"
			say "then log in again (or run '. ~/.profile') for it to take effect."
			;;
		esac
		;;
	esac
}

# Wrapped in main so a truncated download never runs a partial script.
main "$@"
