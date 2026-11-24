package sshremote

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
)

// RunCommand runs command, one line of POSIX sh, as root on an instance
// without SSH (AWS Systems Manager Run Command, Alibaba Cloud Cloud
// Assistant) and returns its standard output and standard error as the
// command wrote them (not trimmed), and its exit status. err is for a run
// that did not take place or whose result is unknown.
type RunCommand func(ctx context.Context, command string) (stdout, stderr []byte, code int, err error)

// RootEditor lists and edits authorized_keys files through a RunCommand.
// The command runs as root, which never writes into the home directory of
// another user: the key script runs as the target user (runuser -u, else
// sudo -n -u), as it does over SSH, so a user who controls their home
// directory cannot make it write elsewhere.
type RootEditor struct {
	Run RunCommand
	// Via names the way the command runs, for messages ("SSM Run
	// Command").
	Via string
}

var _ KeyEditor = (*RootEditor)(nil)

// scriptDelimiter ends the here-document that holds the key script.
const scriptDelimiter = "POLYCTL_KEY_SCRIPT"

// rootWrapper is the program root runs: it checks the user, then runs the
// key script (a here-document, on standard input) with its arguments as
// that user. @USER@ and @ARGS@ are replaced by single-quoted words.
const rootWrapper = `set -u
die() { c=$1; shift; echo "polyctl-error: $*" >&2; exit "$c"; }
u=@USER@
uid=$(id -u "$u" 2>/dev/null) || die 3 "there is no user $u on the instance"
if [ "$(id -u)" = "$uid" ]; then
	set --
elif command -v runuser > /dev/null 2>&1; then
	set -- runuser -u "$u" --
elif command -v sudo > /dev/null 2>&1; then
	set -- sudo -n -u "$u"
else
	die 8 "neither runuser nor sudo is installed to run the key script as $u"
fi
"$@" sh -s -- @ARGS@ <<'` + scriptDelimiter + `'
@SCRIPT@
` + scriptDelimiter + `
`

// rootCommand is the one-line command that runs prog with sh: prog is
// base64-encoded, so no quoting of the platform (nor its {{ }} parameter
// syntax) can change it, and any value in it is safe.
func rootCommand(prog string) string {
	return `sh -c "$(echo ` + base64.StdEncoding.EncodeToString([]byte(prog)) + ` | base64 -d)"`
}

func (r *RootEditor) runScript(ctx context.Context, user string, args ...string) (stdout, stderr []byte, code int, err error) {
	quoted := make([]string, 0, len(args))
	for _, a := range args {
		quoted = append(quoted, shellQuote(a))
	}
	prog := strings.NewReplacer("@USER@", shellQuote(user), "@ARGS@", strings.Join(quoted, " "),
		"@SCRIPT@", strings.TrimRight(keyScript(), "\n")).Replace(rootWrapper)
	return r.Run(ctx, rootCommand(prog))
}

func (r *RootEditor) scriptError(user string, stdout, stderr []byte, code int) error {
	msg := scriptMessage(stderr)
	switch {
	case code == exitNoUser:
		return fmt.Errorf("%w: %s", platform.ErrNotFound, msg)
	case code == exitChanged:
		return fmt.Errorf("%w: %s", ErrChanged, msg)
	case msg != "":
		return fmt.Errorf("%s: %s", r.Via, msg)
	}
	detail := firstLine(string(stderr))
	if detail == "" {
		detail = firstLine(string(stdout))
	}
	if detail == "" {
		detail = fmt.Sprintf("exit status %d", code)
	}
	return fmt.Errorf("%s: the key script failed as %s: %s", r.Via, user, detail)
}

// ListKeys reads the authorized_keys file of user.
func (r *RootEditor) ListKeys(ctx context.Context, user string) (*AuthorizedKeys, error) {
	return listKeys(ctx, r, user)
}

// AddKey ensures user's authorized_keys holds key (see Client.AddKey).
func (r *RootEditor) AddKey(ctx context.Context, user string, key ssh.PublicKey, comment string) (bool, error) {
	return addKey(ctx, r, user, key, comment)
}

// RemoveKeys ensures user's authorized_keys holds none of keys (see
// Client.RemoveKeys).
func (r *RootEditor) RemoveKeys(ctx context.Context, user string, keys []ssh.PublicKey, guard func(*AuthorizedKeys, []Entry) error) (int, error) {
	return removeKeys(ctx, r, user, keys, guard)
}

// FirstUser runs a read-only command that returns the first of users that
// exists on the instance ("" when none does). It is also the check that the
// command runs at all: an error means it did not.
func (r *RootEditor) FirstUser(ctx context.Context, users []string) (string, error) {
	quoted := make([]string, 0, len(users))
	for _, u := range users {
		quoted = append(quoted, shellQuote(u))
	}
	prog := "echo " + probeMarker + "\nfor u in " + strings.Join(quoted, " ") +
		"; do if id -u \"$u\" > /dev/null 2>&1; then echo \"$u\"; exit 0; fi; done\necho\n"
	if len(users) == 0 {
		prog = "echo " + probeMarker + "\necho\n"
	}
	out, errb, code, err := r.Run(ctx, rootCommand(prog))
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if code != 0 || len(lines) == 0 || strings.TrimSpace(lines[0]) != probeMarker {
		detail := firstLine(string(errb))
		if detail == "" {
			detail = firstLine(string(out))
		}
		if detail == "" {
			detail = fmt.Sprintf("exit status %d", code)
		}
		return "", fmt.Errorf("%s: the check command failed: %s", r.Via, detail)
	}
	if len(lines) < 2 {
		return "", nil
	}
	got := strings.TrimSpace(lines[1])
	for _, u := range users {
		if u == got {
			return got, nil
		}
	}
	return "", nil
}
