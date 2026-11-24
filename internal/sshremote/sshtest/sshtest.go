// Package sshtest runs an in-process SSH server for tests of the
// authorized_keys commands: it accepts the public keys it is told to, per
// login user, and runs commands with /bin/sh in a fake system (fake id,
// getent, sudo and chown backed by files in a temporary directory), so that
// the real key script runs against real files without touching the
// machine's users. It never listens on anything but 127.0.0.1.
package sshtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Server is the test SSH server.
type Server struct {
	// Host and Port are where it listens (127.0.0.1).
	Host string
	Port int
	// HostKey is its host key.
	HostKey ssh.Signer
	// System, when set, runs commands with /bin/sh in that fake system;
	// otherwise only the login probe is answered.
	System *System

	t  testing.TB
	ln net.Listener

	mu         sync.Mutex
	authorized map[string][]ssh.PublicKey
	forced     map[string]string
	commands   []Command
}

// Command is a command the server ran.
type Command struct {
	User, Cmd string
}

// New starts a server on 127.0.0.1; it stops when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hk, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{t: t, ln: ln, HostKey: hk, Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port,
		authorized: map[string][]ssh.PublicKey{}, forced: map[string]string{}}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

// Addr is host:port.
func (s *Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Authorize lets user log in with keys.
func (s *Server) Authorize(user string, keys ...ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorized[user] = append(s.authorized[user], keys...)
}

// Force makes every session of user print msg and exit 142, as the forced
// command AWS puts on root does ("Please login as the user ...").
func (s *Server) Force(user, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forced[user] = msg
}

// Commands lists the commands run so far.
func (s *Server) Commands() []Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Command(nil), s.commands...)
}

func (s *Server) serve() {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, k := range s.authorized[md.User()] {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, fmt.Errorf("key not authorized for %s", md.User())
		},
	}
	cfg.AddHostKey(s.HostKey)
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(nc, cfg)
	}
}

func (s *Server) handle(nc net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go s.session(conn.User(), ch, creqs)
	}
}

func (s *Server) session(user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		_ = req.Reply(true, nil)
		var payload struct{ Cmd string }
		_ = ssh.Unmarshal(req.Payload, &payload)
		// The client sends its whole standard input, then EOF.
		stdin, _ := io.ReadAll(ch)
		s.mu.Lock()
		s.commands = append(s.commands, Command{User: user, Cmd: payload.Cmd})
		msg, forced := s.forced[user]
		s.mu.Unlock()
		var stdout, stderr string
		code := 0
		switch {
		case forced:
			stdout, code = msg+"\n", 142
		case s.System != nil:
			stdout, stderr, code = s.System.Run(user, payload.Cmd, string(stdin))
		case payload.Cmd == "echo polyctl-login-ok; id -un":
			stdout = "polyctl-login-ok\n" + user + "\n"
		default:
			stderr, code = "sshtest: no system to run "+payload.Cmd+"\n", 127
		}
		_, _ = ch.Write([]byte(stdout))
		_, _ = ch.Stderr().Write([]byte(stderr))
		status := make([]byte, 4)
		binary.BigEndian.PutUint32(status, uint32(code))
		_, _ = ch.SendRequest("exit-status", false, status)
		return
	}
}

// User is a user of the fake system.
type User struct {
	Name     string
	UID, GID int
	// Home is created by NewSystem.
	Home string
}

// System is a fake Unix system: users with home directories under a
// temporary directory, and fake id, getent, sudo and chown commands ahead
// of the real ones in PATH. chown only records its arguments in ChownLog
// (tests cannot change owners).
type System struct {
	Dir      string
	Users    map[string]*User
	ChownLog string
	// SudoPassword makes sudo -n fail as it does when sudo needs a
	// password.
	SudoPassword bool
	// Shell, when set, is the shell that runs commands, also as the sh
	// of PATH (/bin/dash, to run the script as Debian's sh would).
	Shell string
	// LoginShell, when set, is the login shell that runs commands (as
	// sshd runs them with the user's shell), while sh of PATH stays the
	// system's (/bin/tcsh, to check a csh login shell).
	LoginShell string

	bin, passwd string
}

// NewSystem builds the fake system with the given user names (uid from
// 1000; "root" gets uid 0). It skips the test on Windows, which has no
// /bin/sh.
func NewSystem(t testing.TB, names ...string) *System {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the key script needs a POSIX sh")
	}
	dir := t.TempDir()
	sys := &System{Dir: dir, Users: map[string]*User{}, bin: filepath.Join(dir, "bin"), passwd: filepath.Join(dir, "passwd"), ChownLog: filepath.Join(dir, "chown.log")}
	if err := os.MkdirAll(sys.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	var passwd strings.Builder
	for i, n := range append([]string{"root"}, names...) {
		if _, ok := sys.Users[n]; ok {
			continue
		}
		u := &User{Name: n, UID: 1000 + i - 1, GID: 1000 + i - 1, Home: filepath.Join(dir, "home", n)}
		if n == "root" {
			u.UID, u.GID = 0, 0
		}
		if err := os.MkdirAll(u.Home, 0o755); err != nil {
			t.Fatal(err)
		}
		sys.Users[n] = u
		fmt.Fprintf(&passwd, "%s:x:%d:%d::%s:/bin/sh\n", n, u.UID, u.GID, u.Home)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(sys.bin, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(sys.passwd, []byte(passwd.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	write("id", `field() { awk -F: -v u="$1" -v f="$2" '$1 == u { print $f; found = 1 } END { exit !found }' "$FAKE_PASSWD"; }
case "$1" in
-un) echo "$FAKE_USER" ;;
-u) field "${2:-$FAKE_USER}" 3 ;;
-g) field "${2:-$FAKE_USER}" 4 ;;
*) echo "fake id: $*" >&2; exit 2 ;;
esac
`)
	write("getent", `[ "$1" = passwd ] || exit 2
awk -F: -v u="$2" '$1 == u { print; found = 1 } END { exit !found }' "$FAKE_PASSWD"
`)
	write("sudo", `[ "$1" = -n ] || { echo "fake sudo: -n expected" >&2; exit 2; }
shift
to=root
if [ "${1:-}" = -u ]; then to=$2; shift 2; fi
if [ -n "${FAKE_SUDO_PASSWORD:-}" ]; then echo "sudo: a password is required" >&2; exit 1; fi
HOME=$(awk -F: -v u="$to" '$1 == u { print $6 }' "$FAKE_PASSWD")
[ -n "$HOME" ] || { echo "sudo: unknown user $to" >&2; echo "sudo: error initializing audit plugin sudoers_audit" >&2; exit 1; }
FAKE_USER=$to
export FAKE_USER HOME
exec "$@"
`)
	write("chown", `echo "$*" >> "$FAKE_CHOWN_LOG"
`)
	return sys
}

// Home is the home directory of user.
func (s *System) Home(user string) string { return s.Users[user].Home }

// Run runs cmd as user with /bin/sh in the fake system, stdin as its
// standard input.
func (s *System) Run(user, cmd, stdin string) (stdout, stderr string, code int) {
	u, ok := s.Users[user]
	if !ok {
		return "", "no such user\n", 1
	}
	shell := "/bin/sh"
	if s.Shell != "" {
		shell = s.Shell
		link := filepath.Join(s.bin, "sh")
		if _, err := os.Lstat(link); err != nil {
			if err := os.Symlink(s.Shell, link); err != nil {
				return "", err.Error(), 127
			}
		}
	}
	if s.LoginShell != "" {
		shell = s.LoginShell
	}
	c := exec.Command(shell, "-c", cmd)
	env := []string{
		"PATH=" + s.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + u.Home, "FAKE_USER=" + user, "FAKE_PASSWD=" + s.passwd, "FAKE_CHOWN_LOG=" + s.ChownLog,
		"LC_ALL=C",
	}
	if s.SudoPassword {
		env = append(env, "FAKE_SUDO_PASSWORD=1")
	}
	c.Env = env
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	c.Stdin = strings.NewReader(stdin)
	err := c.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return out.String(), errb.String(), ee.ExitCode()
	} else if err != nil {
		return out.String(), err.Error(), 127
	}
	return out.String(), errb.String(), 0
}
