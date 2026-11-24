package sshremote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultTimeout bounds the TCP connection and the SSH handshake of one
// attempt.
const DefaultTimeout = 20 * time.Second

// probeMarker is what the probe command prints first: a login whose session
// does not print it (a forced command such as the "Please login as the user
// ec2-user rather than the user root" of AWS images) does not count.
const probeMarker = "polyctl-login-ok"

// ProbeCommand is the command run right after authentication to check the
// login works and learn the user name the instance sees.
const ProbeCommand = "echo " + probeMarker + "; id -un"

// Options describe a connection.
type Options struct {
	// Address is the host name or IP address; Port defaults to 22.
	Address string
	Port    int
	// Users are the login users to try, in order: the first that
	// authenticates (and whose session works) is used.
	Users []string
	// Keys are the private keys offered.
	Keys *KeySet
	// HostKeys verifies the host key.
	HostKeys *HostKeys
	// Passphrase, when set, unlocks the encrypted default keys of Keys
	// once nothing else authenticated, and every user is tried again.
	Passphrase func(path string) (string, error)
	// Timeout bounds the connection and handshake of one attempt
	// (DefaultTimeout when zero).
	Timeout time.Duration
}

// Addr is host:port of the options.
func (o Options) Addr() string {
	port := o.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(o.Address, strconv.Itoa(port))
}

// Attempt is a login user that did not work, and why.
type Attempt struct {
	User   string
	Reason string
}

// AuthError is returned by Dial when no login user worked: no key was
// accepted for any of them, or their sessions were refused.
type AuthError struct {
	Addr  string
	Tried []Attempt
	// Keys describes the keys offered ("~/.ssh/id_ed25519, 2 keys of the
	// SSH agent").
	Keys string
}

func (e *AuthError) Error() string {
	parts := make([]string, 0, len(e.Tried))
	for _, a := range e.Tried {
		parts = append(parts, a.User+" ("+a.Reason+")")
	}
	keys := e.Keys
	if keys == "" {
		keys = "no private key"
	}
	return fmt.Sprintf("could not log in to %s as %s with %s", e.Addr, strings.Join(parts, ", "), keys)
}

// Client is an authenticated SSH connection.
type Client struct {
	conn *ssh.Client
	// User is the login user; Addr is host:port.
	User string
	Addr string
	// Key is the public key that authenticated, and KeySource where its
	// private key came from.
	Key       ssh.PublicKey
	KeySource string
	// Tried are the login users tried before User, and why they failed.
	Tried []Attempt
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Dial connects to the address of o as the first of o.Users that
// authenticates with one of o.Keys and whose session runs the probe. A
// host key refusal, a network error or a cancelled context stops at once;
// an authentication failure goes on with the next user. When none worked
// the error is an *AuthError.
func Dial(ctx context.Context, o Options) (*Client, error) {
	if len(o.Users) == 0 {
		return nil, errors.New("no login user to try")
	}
	if o.Keys == nil || len(o.Keys.Signers) == 0 && (len(o.Keys.Locked) == 0 || o.Passphrase == nil) {
		return nil, &AuthError{Addr: o.Addr(), Tried: tried(o.Users, "no private key to offer"), Keys: describeKeys(o.Keys)}
	}
	var attempts []Attempt
	for round := 0; round < 2; round++ {
		attempts = attempts[:0]
		for _, u := range o.Users {
			if len(o.Keys.Signers) == 0 {
				attempts = append(attempts, Attempt{User: u, Reason: "no private key to offer"})
				continue
			}
			c, reason, err := dialUser(ctx, o, u)
			if err != nil {
				return nil, err
			}
			if c != nil {
				c.Tried = append([]Attempt(nil), attempts...)
				return c, nil
			}
			attempts = append(attempts, Attempt{User: u, Reason: reason})
		}
		if round > 0 || len(o.Keys.Locked) == 0 || o.Passphrase == nil {
			break
		}
		added, err := o.Keys.Unlock(o.Passphrase)
		if err != nil {
			return nil, err
		}
		if added == 0 {
			break
		}
	}
	return nil, &AuthError{Addr: o.Addr(), Tried: attempts, Keys: describeKeys(o.Keys)}
}

func tried(users []string, reason string) []Attempt {
	out := make([]Attempt, 0, len(users))
	for _, u := range users {
		out = append(out, Attempt{User: u, Reason: reason})
	}
	return out
}

func describeKeys(ks *KeySet) string {
	if ks == nil || len(ks.Signers) == 0 {
		return ""
	}
	var parts []string
	agentKeys := 0
	for _, s := range ks.Signers {
		if s.Source == "SSH agent" {
			agentKeys++
			continue
		}
		parts = append(parts, s.Source)
	}
	switch agentKeys {
	case 0:
	case 1:
		parts = append(parts, "1 key of the SSH agent")
	default:
		parts = append(parts, fmt.Sprintf("%d keys of the SSH agent", agentKeys))
	}
	return strings.Join(parts, ", ")
}

// dialUser makes one attempt as user. It returns the client, or the reason
// the user did not work (no key accepted, session refused), or an error
// that ends the trial.
func dialUser(ctx context.Context, o Options, user string) (*Client, string, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	addr := o.Addr()
	rec := &usedKey{}
	signers := make([]ssh.Signer, 0, len(o.Keys.Signers))
	for _, s := range o.Keys.Signers {
		signers = append(signers, record(s, rec))
	}
	cfg := &ssh.ClientConfig{
		User:              user,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback:   o.HostKeys.Callback(),
		HostKeyAlgorithms: o.HostKeys.Algorithms(addr),
		Timeout:           timeout,
	}
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		return nil, "", fmt.Errorf("cannot connect to %s: %w", addr, err)
	}
	_ = nc.SetDeadline(time.Now().Add(timeout))
	stop := context.AfterFunc(ctx, func() { _ = nc.Close() })
	conn, chans, reqs, err := ssh.NewClientConn(nc, addr, cfg)
	stop()
	if err != nil {
		_ = nc.Close()
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if herr := o.HostKeys.LastError(); herr != nil {
			return nil, "", herr
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, "no key accepted", nil
		}
		return nil, "", fmt.Errorf("ssh %s: %w", addr, err)
	}
	_ = nc.SetDeadline(time.Time{})
	c := &Client{conn: ssh.NewClient(conn, chans, reqs), User: user, Addr: addr}
	c.Key, c.KeySource = rec.get()
	out, _, code, err := c.Run(ctx, ProbeCommand)
	if err != nil {
		_ = c.Close()
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		return nil, "session refused: " + err.Error(), nil
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if code != 0 || len(lines) < 2 || strings.TrimSpace(lines[0]) != probeMarker {
		_ = c.Close()
		msg := firstLine(string(out))
		if msg == "" {
			msg = fmt.Sprintf("exit status %d", code)
		}
		return nil, "login refused: " + msg, nil
	}
	if seen := strings.TrimSpace(lines[1]); seen != "" {
		c.User = seen
	}
	return c, "", nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}

// Run runs cmd in a new session and returns its stdout, stderr and exit
// status. A cancelled context closes the connection.
func (c *Client) Run(ctx context.Context, cmd string) (stdout, stderr []byte, code int, err error) {
	sess, err := c.conn.NewSession()
	if err != nil {
		return nil, nil, -1, err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	sess.Stdin = strings.NewReader("")
	stop := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	defer stop()
	err = sess.Run(cmd)
	if ctx.Err() != nil {
		return out.Bytes(), errb.Bytes(), -1, ctx.Err()
	}
	var ee *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case err == nil:
		return out.Bytes(), errb.Bytes(), 0, nil
	case errors.As(err, &ee):
		return out.Bytes(), errb.Bytes(), ee.ExitStatus(), nil
	case errors.As(err, &missing):
		// The session ended without an exit status (a forced command
		// that closed the channel): a failure the caller judges by the
		// output.
		return out.Bytes(), errb.Bytes(), -1, nil
	}
	return out.Bytes(), errb.Bytes(), -1, err
}

// usedKey records the last key whose private half signed: the client signs
// only after the server accepted the key, so after a successful
// authentication it is the key that authenticated.
type usedKey struct {
	mu     sync.Mutex
	key    ssh.PublicKey
	source string
}

func (u *usedKey) set(k ssh.PublicKey, src string) {
	u.mu.Lock()
	u.key, u.source = k, src
	u.mu.Unlock()
}

func (u *usedKey) get() (ssh.PublicKey, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.key, u.source
}

// record wraps s so that signing is recorded in u. The wrapper keeps the
// interface level of s (Signer, AlgorithmSigner or MultiAlgorithmSigner),
// which the ssh package inspects to choose the signature algorithm.
func record(s Signer, u *usedKey) ssh.Signer {
	base := recSigner{s: s.Signer, src: s.Source, u: u}
	switch inner := s.Signer.(type) {
	case ssh.MultiAlgorithmSigner:
		return recMulti{recAlgo{base, inner}, inner}
	case ssh.AlgorithmSigner:
		return recAlgo{base, inner}
	}
	return base
}

type recSigner struct {
	s   ssh.Signer
	src string
	u   *usedKey
}

func (r recSigner) PublicKey() ssh.PublicKey { return r.s.PublicKey() }

func (r recSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	r.u.set(r.s.PublicKey(), r.src)
	return r.s.Sign(rand, data)
}

type recAlgo struct {
	recSigner
	a ssh.AlgorithmSigner
}

func (r recAlgo) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	r.u.set(r.s.PublicKey(), r.src)
	return r.a.SignWithAlgorithm(rand, data, algorithm)
}

type recMulti struct {
	recAlgo
	m ssh.MultiAlgorithmSigner
}

func (r recMulti) Algorithms() []string { return r.m.Algorithms() }
