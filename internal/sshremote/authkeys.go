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

// script is the POSIX sh program run on the instance, as the login user or,
// for another user, through `sudo -n`. Its arguments are the operation and
// the target user:
//
//	list <user>                         prints the file after a header
//	apply <user> <sum> <lines> <line>   deletes the line numbers <lines>
//	                                    (space-separated) and appends <line>
//	                                    (when not empty), provided the file
//	                                    still has the checksum <sum>
//
// apply writes a temporary file in ~/.ssh, gives it the mode and owner of
// the file it replaces (0600 and the user for a new file), and renames it
// over authorized_keys: the change is atomic, and every line it does not
// delete is kept byte for byte (a last line without a newline gets one).
// ~/.ssh (0700) and authorized_keys are created, owned by the user, when
// missing. A symbolic link is never replaced.
const script = `set -u
die() { c=$1; shift; echo "polyctl-error: $*" >&2; exit "$c"; }
[ $# -ge 2 ] || die 8 "usage: list|apply <user> ..."
op=$1; user=$2
umask 077
uid=$(id -u "$user" 2>/dev/null) || die 3 "there is no user $user on the instance"
gid=$(id -g "$user" 2>/dev/null) || die 3 "there is no user $user on the instance"
home=$(getent passwd "$user" 2>/dev/null | cut -d: -f6)
[ -n "$home" ] || home=$(awk -F: -v u="$user" '$1 == u { print $6; exit }' /etc/passwd 2>/dev/null)
[ -n "$home" ] || { [ "$(id -un)" = "$user" ] && home=${HOME:-}; }
[ -n "$home" ] && [ -d "$home" ] || die 7 "the home directory of $user (${home:-unknown}) does not exist"
dir=$home/.ssh
f=$dir/authorized_keys
sum() { if [ -f "$f" ]; then cksum < "$f" | awk '{ print $1 "-" $2 }'; else echo none; fi; }
case $op in
list)
	akf=$(awk 'tolower($1) == "authorizedkeysfile" { $1 = ""; sub(/^ +/, ""); print; exit }' @SSHD_CONFIG@ 2>/dev/null)
	echo @HEADER@
	echo "user $user"
	echo "path $f"
	[ -n "$akf" ] && echo "authorizedkeysfile $akf"
	[ -L "$f" ] && echo "symlink"
	echo "sum $(sum)"
	echo "---"
	if [ -f "$f" ]; then cat "$f" || die 6 "cannot read $f"; fi
	exit 0
	;;
apply)
	[ $# -ge 5 ] || die 8 "usage: apply <user> <sum> <lines> <line>"
	want=$3; DEL=$4; ADD=$5
	export DEL ADD
	[ "$(sum)" = "$want" ] || die 4 "$f changed while polyctl was reading it"
	[ -L "$f" ] && die 5 "$f is a symbolic link; polyctl does not replace it"
	root=no
	[ "$(id -u)" = 0 ] && root=yes
	if [ ! -d "$dir" ]; then
		mkdir -m 700 "$dir" || die 6 "cannot create $dir"
		[ $root = yes ] && { chown "$uid:$gid" "$dir" || die 6 "cannot give $dir to $user"; }
	fi
	if [ -f "$f" ]; then
		src=$f
		mode=$(ls -ln "$f" | awk '{ p = substr($1, 2, 9); m = 0; for (i = 1; i <= 9; i++) { m = m * 2; if (substr(p, i, 1) != "-") m++ } printf "%o", m }')
		owner=$(ls -ln "$f" | awk '{ print $3 ":" $4 }')
	else
		src=/dev/null
		mode=600
		owner=$uid:$gid
	fi
	tmp=$(mktemp "$dir/.authorized_keys.XXXXXX" 2>/dev/null) || {
		tmp=$dir/.authorized_keys.polyctl.$$
		(set -C; : > "$tmp") 2>/dev/null || die 6 "cannot create a temporary file in $dir"
	}
	awk 'BEGIN { d = " " ENVIRON["DEL"] " " } index(d, " " NR " ") == 0 { print } END { if (ENVIRON["ADD"] != "") print ENVIRON["ADD"] }' "$src" > "$tmp" || { rm -f "$tmp"; die 6 "cannot write $tmp"; }
	chmod "$mode" "$tmp" || { rm -f "$tmp"; die 6 "cannot set the mode of $tmp"; }
	if [ $root = yes ]; then chown "$owner" "$tmp" || { rm -f "$tmp"; die 6 "cannot set the owner of $tmp"; }; fi
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
// the login user, and the login user is not root.
func (c *Client) NeedsSudo(user string) bool { return user != c.User && c.User != "root" }

// command is the shell command that runs the script for user with args.
func (c *Client) command(user string, args ...string) string {
	var b strings.Builder
	if c.NeedsSudo(user) {
		b.WriteString("sudo -n ")
	}
	prog := strings.NewReplacer("@HEADER@", shellQuote(header), "@SSHD_CONFIG@", shellQuote(SSHDConfig)).Replace(script)
	b.WriteString("sh -c ")
	b.WriteString(shellQuote(prog))
	b.WriteString(" polyctl-sshkey")
	for _, a := range args {
		b.WriteString(" " + shellQuote(a))
	}
	return b.String()
}

// Entry is a line of authorized_keys that holds a key.
type Entry struct {
	// Line is the line number (from 1).
	Line    int
	Key     ssh.PublicKey
	Comment string
	// Options are the options before the key (command="...", from="...").
	Options []string
}

// AuthorizedKeys is the authorized_keys file of a user.
type AuthorizedKeys struct {
	User string
	Path string
	// Sum is the checksum of the file when it was read ("none" when it
	// does not exist): a write is refused if it changed since.
	Sum     string
	Entries []Entry
	// Symlink says the file is a symbolic link, which is never replaced.
	Symlink bool
	// AuthorizedKeysFile is the AuthorizedKeysFile setting of sshd, when
	// the configuration could be read and sets one.
	AuthorizedKeysFile string
}

// Has returns the entries that hold key (compared by type and key data;
// comments and options do not matter).
func (a *AuthorizedKeys) Has(key ssh.PublicKey) []Entry {
	var out []Entry
	for _, e := range a.Entries {
		if SameKey(e.Key, key) {
			out = append(out, e)
		}
	}
	return out
}

// CustomFile reports whether sshd reads keys from somewhere else than
// ~/.ssh/authorized_keys: an AuthorizedKeysFile without that path, which
// polyctl does not edit.
func (a *AuthorizedKeys) CustomFile() bool {
	v := strings.TrimSpace(a.AuthorizedKeysFile)
	if v == "" {
		return false
	}
	for _, f := range strings.Fields(v) {
		f = strings.TrimPrefix(f, "%h/")
		if f == ".ssh/authorized_keys" || f == "~/.ssh/authorized_keys" {
			return false
		}
	}
	return true
}

// SameKey compares two public keys by type and key data.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && bytes.Equal(a.Marshal(), b.Marshal())
}

// ErrChanged is a file that changed between the read and the write.
var ErrChanged = errors.New("authorized_keys changed while polyctl was editing it")

// scriptError turns a failed run of the script into an error.
func (c *Client) scriptError(user string, stdout, stderr []byte, code int) error {
	msg := ""
	for _, l := range strings.Split(string(stderr), "\n") {
		if m, ok := strings.CutPrefix(strings.TrimSpace(l), "polyctl-error: "); ok {
			msg = m
		}
	}
	switch {
	case msg == "" && c.NeedsSudo(user) && bytes.Contains(stderr, []byte("sudo")):
		return fmt.Errorf("editing the keys of %s needs sudo, and sudo on the instance asks %s for a password (%s); polyctl only runs `sudo -n`: log in as %s (--login-user %s), or allow %s passwordless sudo",
			user, c.User, firstLine(string(stderr)), user, user, c.User)
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

// ListKeys reads the authorized_keys file of user.
func (c *Client) ListKeys(ctx context.Context, user string) (*AuthorizedKeys, error) {
	out, errb, code, err := c.Run(ctx, c.command(user, "list", user))
	if err != nil {
		return nil, err
	}
	if code != 0 || !bytes.HasPrefix(out, []byte(header+"\n")) {
		return nil, c.scriptError(user, out, errb, code)
	}
	return parseList(user, out)
}

func parseList(user string, out []byte) (*AuthorizedKeys, error) {
	ak := &AuthorizedKeys{User: user}
	rest := string(out[len(header)+1:])
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
		case "authorizedkeysfile":
			ak.AuthorizedKeysFile = v
		}
	}
	if ak.Sum == "" {
		return nil, errors.New("the key script printed no checksum")
	}
	ak.Entries = parseEntries(rest)
	return ak, nil
}

// parseEntries parses the lines of an authorized_keys file; lines that hold
// no key (blank, comments, malformed) are left out.
func parseEntries(content string) []Entry {
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
		out = append(out, Entry{Line: i + 1, Key: key, Comment: comment, Options: opts})
	}
	return out
}

// apply runs the write of the script: delete lines, append line.
func (c *Client) apply(ctx context.Context, ak *AuthorizedKeys, del []int, line string) error {
	nums := make([]string, 0, len(del))
	for _, n := range del {
		nums = append(nums, strconv.Itoa(n))
	}
	out, errb, code, err := c.Run(ctx, c.command(ak.User, "apply", ak.User, ak.Sum, strings.Join(nums, " "), line))
	if err != nil {
		return err
	}
	if code != 0 || !bytes.HasPrefix(out, []byte(header+"\n")) {
		return c.scriptError(ak.User, out, errb, code)
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

// AddKey ensures user's authorized_keys holds key: it returns false when it
// already did (under any comment or options) and nothing was written. A
// file that changed while it was edited is read again, once.
func (c *Client) AddKey(ctx context.Context, user string, key ssh.PublicKey, comment string) (bool, error) {
	for attempt := 0; ; attempt++ {
		ak, err := c.ListKeys(ctx, user)
		if err != nil {
			return false, err
		}
		if len(ak.Has(key)) > 0 {
			return false, nil
		}
		if ak.Symlink {
			return false, fmt.Errorf("%s is a symbolic link; polyctl does not replace it", ak.Path)
		}
		err = c.apply(ctx, ak, nil, KeyLine(key, comment))
		if errors.Is(err, ErrChanged) && attempt == 0 {
			continue
		}
		return err == nil, err
	}
}

// RemoveKeys ensures user's authorized_keys holds none of keys: every line
// holding one of them is deleted, the others are kept as they are. It
// returns how many lines were deleted (0: nothing was written). guard, when
// set, sees the file before the write and may refuse it.
func (c *Client) RemoveKeys(ctx context.Context, user string, keys []ssh.PublicKey, guard func(*AuthorizedKeys, []Entry) error) (int, error) {
	for attempt := 0; ; attempt++ {
		ak, err := c.ListKeys(ctx, user)
		if err != nil {
			return 0, err
		}
		var del []Entry
		for _, k := range keys {
			del = append(del, ak.Has(k)...)
		}
		if len(del) == 0 {
			return 0, nil
		}
		if ak.Symlink {
			return 0, fmt.Errorf("%s is a symbolic link; polyctl does not replace it", ak.Path)
		}
		if guard != nil {
			if err := guard(ak, del); err != nil {
				return 0, err
			}
		}
		lines := make([]int, 0, len(del))
		for _, e := range del {
			lines = append(lines, e.Line)
		}
		err = c.apply(ctx, ak, lines, "")
		if errors.Is(err, ErrChanged) && attempt == 0 {
			continue
		}
		if err != nil {
			return 0, err
		}
		return len(lines), nil
	}
}
