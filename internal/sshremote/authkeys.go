package sshremote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
)

// SSHDConfig is the sshd configuration the script reads for a custom
// AuthorizedKeysFile (a variable for tests).
var SSHDConfig = "/etc/ssh/sshd_config"

// header starts every answer of the script, so that output that is not its
// own (a forced command, a login banner of sudo) is never mistaken for it.
const header = "polyctl-sshkey 1"

// Exit codes of the script.
const (
	exitNoUser   = 3
	exitChanged  = 4
	exitSymlink  = 5
	exitWrite    = 6
	exitNoHome   = 7
	exitBadUsage = 8
)

// script is the POSIX sh program run on the instance as the target user:
// the login user, or another user through `sudo -n -u <user>`. It never
// runs as root on the files of another user, so a user who controls their
// home directory cannot make it write elsewhere (a symbolic link swapped in
// for ~/.ssh or for the temporary file). Its arguments are the operation
// and the target user:
//
//	list <user>                                prints both files after a header
//	apply <user> <file> <sum> <lines> <line>   deletes the line numbers <lines>
//	                                           (space-separated) of <file>
//	                                           (authorized_keys or
//	                                           authorized_keys2) and appends
//	                                           <line> (when not empty),
//	                                           provided the file still has
//	                                           the checksum <sum>
//
// list also prints the AuthorizedKeysFile sshd uses: from `sshd -T` when it
// runs (root), else from sshd_config and the files it includes (the first
// setting outside a Match block, as sshd takes it), else OpenSSH's default
// (.ssh/authorized_keys .ssh/authorized_keys2). authorized_keys2, when it
// exists, comes first in the output, exactly <size2> bytes followed by a
// line "---", then authorized_keys.
//
// apply writes a temporary file in ~/.ssh, gives it the mode of the file it
// replaces (0600 for a new file), and renames it over the file: the change
// is atomic, and every line it does not delete is kept byte for byte (a
// last line without a newline gets one). ~/.ssh (0700) and the file are
// created, owned by the user, when missing. A symbolic link is never
// replaced.
const script = `set -u
die() { c=$1; shift; echo "polyctl-error: $*" >&2; exit "$c"; }
[ $# -ge 2 ] || die 8 "usage: list|apply <user> ..."
op=$1; user=$2
umask 077
uid=$(id -u "$user" 2>/dev/null) || die 3 "there is no user $user on the instance"
[ "$(id -u)" = "$uid" ] || die 8 "the key script runs as $(id -un), not as $user"
home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
[ -n "$home" ] || home=$(awk -F: -v u="$user" '$1 == u { print $6; exit }' /etc/passwd 2>/dev/null)
[ -n "$home" ] || { [ "$(id -un)" = "$user" ] && home=${HOME:-}; }
[ -n "$home" ] && [ -d "$home" ] || die 7 "the home directory of $user (${home:-unknown}) does not exist"
dir=$home/.ssh
f=$dir/authorized_keys
sum() { if [ -f "$f" ]; then cksum < "$f" | awk '{ print $1 "-" $2 }'; else echo none; fi; }
cfg=@SSHD_CONFIG@
cfgdir=$(dirname "$cfg")
# akf_scan <file> <depth> prints "V <value>" for an AuthorizedKeysFile
# outside a Match block, "M" for one inside, following Include in place.
akf_scan() {
	[ "$2" -lt 8 ] && [ -r "$1" ] || return 0
	awk '{ sub(/\r$/, ""); l = $0; sub(/^[ \t]+/, "", l)
		if (l == "" || substr(l, 1, 1) == "#") next
		k = l; sub(/[ \t=].*/, "", k); v = substr(l, length(k) + 1)
		sub(/^[ \t]*=?[ \t]*/, "", v); sub(/[ \t]+$/, "", v); k = tolower(k)
		if (k == "match") { m = (tolower(v) != "all"); next }
		if (k == "authorizedkeysfile") { if (m) print "M"; else print "V " v; next }
		if (k == "include") { if (m) print "M"; else print "I " v } }' "$1" 2>/dev/null |
	while IFS= read -r l; do
		case $l in
		I\ *)
			set -f
			for p in ${l#I }; do
				set +f
				case $p in /*) ;; *) p=$cfgdir/$p ;; esac
				for g in $p; do [ -f "$g" ] && akf_scan "$g" $(($2 + 1)); done
				set -f
			done
			set +f
			;;
		*) echo "$l" ;;
		esac
	done
}
case $op in
list)
	akf=; from=unknown; match=
	sshd=$(command -v sshd 2>/dev/null) || sshd=/usr/sbin/sshd
	if [ -x "$sshd" ] && t=$("$sshd" -T -C "user=$user,host=localhost,addr=127.0.0.1" 2>/dev/null); then
		akf=$(printf '%s\n' "$t" | awk 'tolower($1) == "authorizedkeysfile" { $1 = ""; sub(/^ +/, ""); print; exit }')
		[ -n "$akf" ] && from=sshd
	fi
	if [ -z "$akf" ] && [ -r "$cfg" ]; then
		scan=$(akf_scan "$cfg" 0)
		akf=$(printf '%s\n' "$scan" | awk '$1 == "V" { sub(/^V /, ""); print; exit }')
		from=config
		[ -n "$akf" ] || { akf=".ssh/authorized_keys .ssh/authorized_keys2"; from=default; }
		printf '%s\n' "$scan" | grep -q '^M' && match=1
	fi
	f2=$dir/authorized_keys2
	echo @HEADER@
	echo "user $user"
	echo "path $f"
	[ -n "$akf" ] && echo "authorizedkeysfile $akf"
	echo "authorizedkeysfilefrom $from"
	[ -n "$match" ] && echo "authorizedkeysfilematch"
	[ -L "$f" ] && echo "symlink"
	echo "sum $(sum)"
	[ -f "$f" ] && echo "size $(wc -c < "$f" | awk '{ print $1 }')"
	echo "path2 $f2"
	[ -L "$f2" ] && echo "symlink2"
	echo "sum2 $(f=$f2; sum)"
	[ -f "$f2" ] && echo "size2 $(wc -c < "$f2" | awk '{ print $1 }')"
	echo "---"
	if [ -f "$f2" ]; then cat "$f2" || die 6 "cannot read $f2"; echo; echo "---"; fi
	if [ -f "$f" ]; then cat "$f" || die 6 "cannot read $f"; fi
	exit 0
	;;
apply)
	[ $# -ge 6 ] || die 8 "usage: apply <user> <file> <sum> <lines> <line>"
	case $3 in
	authorized_keys|authorized_keys2) f=$dir/$3 ;;
	*) die 8 "cannot edit $3" ;;
	esac
	want=$4; DEL=$5; ADD=$6
	export DEL ADD
	[ "$(sum)" = "$want" ] || die 4 "$f changed while polyctl was reading it"
	[ -L "$f" ] && die 5 "$f is a symbolic link; polyctl does not replace it"
	if [ ! -d "$dir" ]; then
		mkdir -m 700 "$dir" || die 6 "cannot create $dir"
	fi
	if [ -f "$f" ]; then
		src=$f
		mode=$(ls -ln "$f" | awk '{ p = substr($1, 2, 9); m = 0; for (i = 1; i <= 9; i++) { m = m * 2; if (substr(p, i, 1) != "-") m++ } printf "%o", m }')
	else
		src=/dev/null
		mode=600
	fi
	tmp=$(mktemp "$dir/.$3.XXXXXX" 2>/dev/null) || {
		tmp=$dir/.$3.polyctl.$$
		(set -C; : > "$tmp") 2>/dev/null || die 6 "cannot create a temporary file in $dir"
	}
	awk 'BEGIN { d = " " ENVIRON["DEL"] " " } index(d, " " NR " ") == 0 { print } END { if (ENVIRON["ADD"] != "") print ENVIRON["ADD"] }' "$src" > "$tmp" || { rm -f "$tmp"; die 6 "cannot write $tmp"; }
	chmod "$mode" "$tmp" || { rm -f "$tmp"; die 6 "cannot set the mode of $tmp"; }
	[ "$(sum)" = "$want" ] || { rm -f "$tmp"; die 4 "$f changed while polyctl was writing it"; }
	mv -f "$tmp" "$f" || { rm -f "$tmp"; die 6 "cannot replace $f"; }
	command -v restorecon > /dev/null 2>&1 && restorecon "$dir" "$f" > /dev/null 2>&1
	echo @HEADER@
	echo "ok"
	exit 0
	;;
*)
	die 8 "unknown operation $op"
	;;
esac
`

// shellQuote quotes s for a POSIX shell: in single quotes, with each single
// quote written as '\”.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// userNameRe is what polyctl accepts as a user name on an instance (the
// portable POSIX user names, plus upper case and a trailing $ of Samba
// machine accounts).
var userNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$`)

// CheckUser refuses a malformed user name (flag names the option).
func CheckUser(user, flag string) error {
	if !userNameRe.MatchString(user) {
		return fmt.Errorf("%w: %s: %q is not a valid user name (a letter or _, then letters, digits, '.', '_' or '-'; at most 32 characters)", platform.ErrInvalidInput, flag, user)
	}
	return nil
}

// NeedsSudo reports whether editing the keys of user needs sudo: it is not
// the login user. root goes through `sudo -u` too, so that the script runs
// as the owner of the files it writes.
func (c *Client) NeedsSudo(user string) bool { return user != c.User }

// command is the shell command that runs the script for user with args,
// and the script itself, which goes to the command's standard input: the
// command line is then one line of single-quoted words, which a csh, tcsh
// or fish login shell runs as a POSIX shell does (a multi-line quoted
// script is an error in csh).
func (c *Client) command(user string, args ...string) (cmd, stdin string) {
	var b strings.Builder
	if c.NeedsSudo(user) {
		b.WriteString("sudo -n -u " + shellQuote(user) + " ")
	}
	b.WriteString("sh -s --")
	for _, a := range args {
		b.WriteString(" " + shellQuote(a))
	}
	return b.String(), keyScript()
}

// keyScript is the script with its placeholders filled in.
func keyScript() string {
	return strings.NewReplacer("@HEADER@", shellQuote(header), "@SSHD_CONFIG@", shellQuote(SSHDConfig)).Replace(script)
}

// runScript runs the script for user with args.
func (c *Client) runScript(ctx context.Context, user string, args ...string) (stdout, stderr []byte, code int, err error) {
	cmd, prog := c.command(user, args...)
	return c.RunInput(ctx, cmd, prog)
}

// The files of ~/.ssh the key script lists: sshd reads both by default.
const (
	KeysFile  = "authorized_keys"
	KeysFile2 = "authorized_keys2"
)

// Entry is a line of authorized_keys (or authorized_keys2) that holds a key.
type Entry struct {
	// File is the file it is in: KeysFile or KeysFile2.
	File string
	// Line is the line number (from 1).
	Line    int
	Key     ssh.PublicKey
	Comment string
	// Options are the options before the key (command="...", from="...").
	Options []string
}

// AuthorizedKeys is the authorized_keys file of a user, with its
// authorized_keys2 file.
type AuthorizedKeys struct {
	User string
	Path string
	// Sum is the checksum of the file when it was read ("none" when it
	// does not exist): a write is refused if it changed since.
	Sum string
	// Entries are the keys of both files, authorized_keys first.
	Entries []Entry
	// Symlink says the file is a symbolic link, which is never replaced.
	Symlink bool
	// Path2, Sum2 and Symlink2 are those of authorized_keys2.
	Path2    string
	Sum2     string
	Symlink2 bool
	// AuthorizedKeysFile is the AuthorizedKeysFile sshd uses ("" when it
	// is unknown), and AuthorizedKeysFileFrom where it comes from: "sshd"
	// (sshd -T), "config" (sshd_config and its includes), "default"
	// (OpenSSH's built-in value, none being set) or "unknown".
	AuthorizedKeysFile     string
	AuthorizedKeysFileFrom string
	// AuthorizedKeysFileMatch says a Match block of sshd_config sets
	// AuthorizedKeysFile too, which may apply to the user instead.
	AuthorizedKeysFileMatch bool
}

// Has returns the entries that hold key (compared by type and key data;
// comments and options do not matter), in every file.
func (a *AuthorizedKeys) Has(key ssh.PublicKey) []Entry {
	var out []Entry
	for _, e := range a.Entries {
		if SameKey(e.Key, key) {
			out = append(out, e)
		}
	}
	return out
}

// Reads reports whether sshd reads keys from ~/.ssh/<file>: true when the
// AuthorizedKeysFile setting is unknown.
func (a *AuthorizedKeys) Reads(file string) bool {
	v := strings.TrimSpace(a.AuthorizedKeysFile)
	if v == "" {
		return true
	}
	for _, f := range strings.Fields(v) {
		if homeFile(f) == file {
			return true
		}
	}
	return false
}

// homeFile is the name of a file of ~/.ssh an AuthorizedKeysFile entry
// names ("authorized_keys" for .ssh/authorized_keys, %h/... or ~/...), ""
// for another path.
func homeFile(f string) string {
	f = strings.TrimPrefix(strings.TrimPrefix(f, "%h/"), "~/")
	if name, ok := strings.CutPrefix(f, ".ssh/"); ok && (name == KeysFile || name == KeysFile2) {
		return name
	}
	return ""
}

// OtherFiles are the files of the AuthorizedKeysFile setting that are not
// ~/.ssh/authorized_keys or authorized_keys2: polyctl neither lists nor
// edits them.
func (a *AuthorizedKeys) OtherFiles() []string {
	var out []string
	for _, f := range strings.Fields(a.AuthorizedKeysFile) {
		if homeFile(f) == "" && strings.ToLower(f) != "none" {
			out = append(out, f)
		}
	}
	return out
}

// Restrictions returns the options of an authorized_keys line that may stop
// the key from logging in to a shell: a forced command (command=), restrict,
// a source address limit (from=) or an expiry (expiry-time=).
func Restrictions(options []string) []string {
	var out []string
	for _, o := range options {
		name, _, _ := strings.Cut(o, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "command", "restrict", "from", "expiry-time":
			out = append(out, o)
		}
	}
	return out
}

// CustomFile reports whether sshd does not read ~/.ssh/authorized_keys,
// the file polyctl adds keys to: an AuthorizedKeysFile without that path.
func (a *AuthorizedKeys) CustomFile() bool {
	return !a.Reads(KeysFile)
}

// SameKey compares two public keys by type and key data.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// ErrChanged is a file that changed between the read and the write.
var ErrChanged = errors.New("authorized_keys changed while polyctl was editing it")

// scriptMessage is the last "polyctl-error: " message of the script's
// standard error, "" when there is none.
func scriptMessage(stderr []byte) string {
	msg := ""
	for _, l := range strings.Split(string(stderr), "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(l), "polyctl-error: "); ok {
			msg = m
		}
	}
	return msg
}

// scriptError turns a failed run of the script into an error.
func (c *Client) scriptError(user string, stdout, stderr []byte, code int) error {
	msg := scriptMessage(stderr)
	sudoFailed := msg == "" && c.NeedsSudo(user) && bytes.Contains(stderr, []byte("sudo"))
	switch {
	case sudoFailed && bytes.Contains(stderr, []byte("unknown user")):
		return fmt.Errorf("%w: there is no user %s on the instance", platform.ErrNotFound, user)
	case sudoFailed && bytes.Contains(stderr, []byte("password")):
		return fmt.Errorf("editing the keys of %s needs sudo, and sudo on the instance asks %s for a password (%s); polyctl only runs `sudo -n`: log in as %s (--login-user %s), or allow %s passwordless sudo",
			user, c.User, firstLine(string(stderr)), user, user, c.User)
	case sudoFailed:
		return fmt.Errorf("editing the keys of %s runs `sudo -n -u %s` as %s, which failed (%s): log in as %s (--login-user %s), or allow %s to run commands as %s with sudo",
			user, user, c.User, firstLine(string(stderr)), user, user, c.User, user)
	case code == exitNoUser:
		return fmt.Errorf("%w: %s", platform.ErrNotFound, msg)
	case code == exitChanged:
		return fmt.Errorf("%w: %s", ErrChanged, msg)
	case msg != "":
		return fmt.Errorf("%s: %s", c.Addr, msg)
	}
	detail := firstLine(string(stderr))
	if detail == "" {
		detail = firstLine(string(stdout))
	}
	if detail == "" {
		detail = fmt.Sprintf("exit status %d", code)
	}
	return fmt.Errorf("%s: the key script failed as %s: %s", c.Addr, c.User, detail)
}

// KeyEditor lists and edits the authorized_keys files of an instance: over
// SSH (*Client) or through a command run as root by the platform
// (*RootEditor).
type KeyEditor interface {
	// ListKeys reads the authorized_keys file of user.
	ListKeys(ctx context.Context, user string) (*AuthorizedKeys, error)
	// AddKey ensures user's authorized_keys holds key: false when it
	// already did and nothing was written.
	AddKey(ctx context.Context, user string, key ssh.PublicKey, comment string) (bool, error)
	// RemoveKeys ensures user's authorized_keys and authorized_keys2 hold
	// none of keys and returns how many lines were deleted; guard sees the
	// files right before the write and may refuse it.
	RemoveKeys(ctx context.Context, user string, keys []ssh.PublicKey, guard func(*AuthorizedKeys, []Entry) error) (int, error)
}

// keyRunner runs the key script on an instance as user.
type keyRunner interface {
	runScript(ctx context.Context, user string, args ...string) (stdout, stderr []byte, code int, err error)
	scriptError(user string, stdout, stderr []byte, code int) error
}

// ListKeys reads the authorized_keys file of user.
func (c *Client) ListKeys(ctx context.Context, user string) (*AuthorizedKeys, error) {
	return listKeys(ctx, c, user)
}

// AddKey ensures user's authorized_keys holds key: it returns false when it
// already did (under any comment or options) and nothing was written. A
// file that changed while it was edited is read again, once.
func (c *Client) AddKey(ctx context.Context, user string, key ssh.PublicKey, comment string) (bool, error) {
	return addKey(ctx, c, user, key, comment)
}

// RemoveKeys ensures user's authorized_keys and authorized_keys2 hold none
// of keys: every line holding one of them is deleted, the others are kept as they are. It
// returns how many lines were deleted (0: nothing was written). guard, when
// set, sees the file before the write and may refuse it.
func (c *Client) RemoveKeys(ctx context.Context, user string, keys []ssh.PublicKey, guard func(*AuthorizedKeys, []Entry) error) (int, error) {
	return removeKeys(ctx, c, user, keys, guard)
}

func listKeys(ctx context.Context, r keyRunner, user string) (*AuthorizedKeys, error) {
	out, errb, code, err := r.runScript(ctx, user, "list", user)
	if err != nil {
		return nil, err
	}
	if code != 0 || !bytes.HasPrefix(out, []byte(header+"\n")) {
		return nil, r.scriptError(user, out, errb, code)
	}
	return parseList(user, out)
}

func parseList(user string, out []byte) (*AuthorizedKeys, error) {
	ak := &AuthorizedKeys{User: user}
	rest := string(out[len(header)+1:])
	size, size2 := -1, -1
	for {
		line, tail, ok := strings.Cut(rest, "\n")
		if !ok {
			return nil, errors.New("the key script printed no file separator")
		}
		rest = tail
		if line == "---" {
			break
		}
		k, v, _ := strings.Cut(line, " ")
		switch k {
		case "path":
			ak.Path = v
		case "sum":
			ak.Sum = v
		case "symlink":
			ak.Symlink = true
		case "path2":
			ak.Path2 = v
		case "sum2":
			ak.Sum2 = v
		case "symlink2":
			ak.Symlink2 = true
		case "size2":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("the key script printed a malformed size %q", v)
			}
			size2 = n
		case "authorizedkeysfile":
			ak.AuthorizedKeysFile = v
		case "authorizedkeysfilefrom":
			ak.AuthorizedKeysFileFrom = v
		case "authorizedkeysfilematch":
			ak.AuthorizedKeysFileMatch = true
		case "size":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("the key script printed a malformed size %q", v)
			}
			size = n
		}
	}
	if ak.Sum == "" {
		return nil, errors.New("the key script printed no checksum")
	}
	var entries2 []Entry
	if size2 >= 0 {
		// authorized_keys2 comes first: exactly size2 bytes, then a line
		// "---" (after a newline the script adds).
		const sep = "\n---\n"
		if len(rest) < size2+len(sep) {
			return nil, fmt.Errorf("%w: the listing of %s is incomplete (%d of %d bytes came back); the file is too large to be read this way", platform.ErrNotSupported, ak.Path2, len(rest), size2)
		}
		if rest[size2:size2+len(sep)] != sep {
			return nil, fmt.Errorf("the listing of %s does not have the size the key script printed (it changed while it was read)", ak.Path2)
		}
		entries2 = parseEntries(rest[:size2], KeysFile2)
		rest = rest[size2+len(sep):]
	}
	if size >= 0 && !completeOutput(rest, size) {
		// Output cut short (a platform that runs commands keeps only
		// the first kilobytes) would hide keys: refuse it rather than
		// add a key twice or miss one to remove.
		return nil, fmt.Errorf("%w: the listing of %s is incomplete (%d of %d bytes came back); the file is too large to be read this way", platform.ErrNotSupported, ak.Path, len(rest), size)
	}
	ak.Entries = append(parseEntries(rest, KeysFile), entries2...)
	return ak, nil
}

// completeOutput reports whether content is the whole file of size bytes.
// A final newline or two lost on the way (some platforms trim the output
// of a command) is tolerated; anything else missing is not.
func completeOutput(content string, size int) bool {
	n := len(content)
	return n == size || n < size && size-n <= 2 && !strings.HasSuffix(content, "\n")
}

// parseEntries parses the lines of an authorized_keys file; lines that hold
// no key (blank, comments, malformed) are left out.
func parseEntries(content, file string) []Entry {
	lines := strings.Split(content, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out []Entry
	for i, l := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, comment, opts, _, err := ssh.ParseAuthorizedKey([]byte(t))
		if err != nil {
			continue
		}
		out = append(out, Entry{File: file, Line: i + 1, Key: key, Comment: comment, Options: opts})
	}
	return out
}

// apply runs the write of the script on authorized_keys: delete lines,
// append line.
func apply(ctx context.Context, r keyRunner, ak *AuthorizedKeys, del []int, line string) error {
	return applyFile(ctx, r, ak, KeysFile, del, line)
}

// applyFile runs the write of the script on file (KeysFile or KeysFile2).
func applyFile(ctx context.Context, r keyRunner, ak *AuthorizedKeys, file string, del []int, line string) error {
	nums := make([]string, 0, len(del))
	for _, n := range del {
		nums = append(nums, strconv.Itoa(n))
	}
	sum := ak.Sum
	if file == KeysFile2 {
		sum = ak.Sum2
	}
	out, errb, code, err := r.runScript(ctx, ak.User, "apply", ak.User, file, sum, strings.Join(nums, " "), line)
	if err != nil {
		return err
	}
	if code != 0 || !bytes.HasPrefix(out, []byte(header+"\n")) {
		return r.scriptError(ak.User, out, errb, code)
	}
	return nil
}

// KeyLine is the authorized_keys line of key: "type base64 comment".
func KeyLine(key ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if c := strings.Join(strings.Fields(comment), " "); c != "" {
		line += " " + c
	}
	return line
}

func addKey(ctx context.Context, r keyRunner, user string, key ssh.PublicKey, comment string) (bool, error) {
	for attempt := 0; ; attempt++ {
		ak, err := listKeys(ctx, r, user)
		if err != nil {
			return false, err
		}
		present := false
		for _, e := range ak.Has(key) {
			// A key in authorized_keys2 counts when sshd reads that file.
			if e.File == KeysFile || ak.Reads(e.File) {
				present = true
			}
		}
		if present {
			return false, nil
		}
		if ak.Symlink {
			return false, fmt.Errorf("%s is a symbolic link; polyctl does not replace it", ak.Path)
		}
		err = apply(ctx, r, ak, nil, KeyLine(key, comment))
		if errors.Is(err, ErrChanged) && attempt == 0 {
			continue
		}
		return err == nil, err
	}
}

func removeKeys(ctx context.Context, r keyRunner, user string, keys []ssh.PublicKey, guard func(*AuthorizedKeys, []Entry) error) (int, error) {
	// total counts the lines deleted by every attempt: a retry after
	// authorized_keys2 changed must not forget the lines already deleted
	// from authorized_keys.
	total := 0
	for attempt := 0; ; attempt++ {
		ak, err := listKeys(ctx, r, user)
		if err != nil {
			return total, err
		}
		var del []Entry
		for _, k := range keys {
			del = append(del, ak.Has(k)...)
		}
		if len(del) == 0 {
			return total, nil
		}
		lines := map[string][]int{}
		for _, e := range del {
			lines[e.File] = append(lines[e.File], e.Line)
		}
		if ak.Symlink && len(lines[KeysFile]) > 0 {
			return total, fmt.Errorf("%s is a symbolic link; polyctl does not replace it", ak.Path)
		}
		if ak.Symlink2 && len(lines[KeysFile2]) > 0 {
			return total, fmt.Errorf("%s is a symbolic link; polyctl does not replace it", ak.Path2)
		}
		if guard != nil {
			if err := guard(ak, del); err != nil {
				return total, err
			}
		}
		// Both files: a key left in authorized_keys2 still logs in.
		for _, file := range []string{KeysFile, KeysFile2} {
			if len(lines[file]) == 0 {
				continue
			}
			err = applyFile(ctx, r, ak, file, lines[file], "")
			if err != nil {
				break
			}
			total += len(lines[file])
		}
		if errors.Is(err, ErrChanged) && attempt == 0 {
			continue
		}
		if err != nil && total > 0 {
			return total, fmt.Errorf("%d line(s) holding the key were deleted, but not all: %w", total, err)
		}
		return total, err
	}
}
