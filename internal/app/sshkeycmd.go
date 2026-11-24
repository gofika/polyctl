package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/sshremote"
)

// The `<tree> ssh-key list|add|remove <instance>` commands manage the SSH
// public keys a Linux instance accepts, with the same shape on every
// platform. Compute Engine keeps them in metadata, which the platform API
// edits (SSHKeyStore); on AWS and Alibaba Cloud an instance binds one key
// pair at creation, so further keys are managed by editing
// ~/.ssh/authorized_keys of the user (package sshremote): over SSH with the
// local private key of that key pair, else through a temporary way in the
// platform offers (a one-time key pushed for the login, or a command the
// platform runs as root).

// SSHKeyCommand describes the ssh-key commands of a platform.
type SSHKeyCommand struct {
	Platform platform.ID
	// Tree is the instance group ("aws ec2 instance").
	Tree string
	// Detail is the platform's paragraph of the help.
	Detail string
	// Flags registers the platform's own flags (--region, --zone) on each
	// command.
	Flags func(cmd *cobra.Command)
	// Resolve finds the instance arg names (a name or an id). With arg ""
	// (the interactive flow only) it asks for one with the platform's
	// instance picker: the running Linux instances (any Linux instance
	// for a platform with Metadata).
	Resolve func(ctx context.Context, arg string) (*SSHKeyInstance, error)
	// Metadata says the keys are managed through the platform API
	// (SSHKeyInstance.Metadata): the SSH flags are not registered.
	Metadata bool
	// UserFromKey derives the user of a key when --user is not given (GCP:
	// the user of the user@host that ends the key's comment), "" when it
	// cannot. Nil: the user is the login user (SSH).
	UserFromKey func(*platform.PublicKey) string
	// AllowedTypes are the key types accepted (AnyKeyTypes when nil).
	AllowedTypes []string
}

// SSHKeyInstance is the instance a platform resolved, with what is needed
// to reach its keys.
type SSHKeyInstance struct {
	Name, ID string
	// Target is the account and location of the change report.
	Target platform.Target
	// Windows instances log in with a password: the commands refuse them
	// (exit code 7).
	Windows bool
	// Metadata manages the keys through the platform API (Compute Engine);
	// the SSH fields below are then unused.
	Metadata SSHKeyStore

	// Running says the instance can be reached; State is its state for
	// the message when it cannot.
	Running bool
	State   string
	// PublicIP and PrivateIP are its addresses: the public one is used,
	// else the private one (with a note), unless --address is given.
	PublicIP, PrivateIP string
	// LoginUsers are the users to try, in order, when --login-user is not
	// given; LoginUsersFrom says what they were derived from (the image,
	// or how the instance was created), for notes.
	LoginUsers     []string
	LoginUsersFrom string
	// LoginUsersNote is printed when LoginUsers are tried (not with
	// --login-user): an image whose default user is unknown, say.
	LoginUsersNote string

	// KeyPairName is the key pair the instance was created with, "" when
	// it has none.
	KeyPairName string
	// KeyPair is that key pair as the platform API returns it (its public
	// key, or a fingerprint KeyPairMatch understands); nil when it cannot
	// be read (deleted, no permission), with KeyPairError saying why.
	// Without --identity-file, only the local private keys of this key
	// pair are offered: an instance whose key pair has none on this
	// machine may have been created for someone else, and no other key is
	// tried on it.
	KeyPair      *platform.KeyPair
	KeyPairError string
	// KeyPairMatch tells whether a local key is the key pair's
	// (platform.MatchByPublicKey when its Match is nil).
	KeyPairMatch platform.KeyMatcher
	// TempAccess are the temporary ways in, tried in order, without
	// asking, when no local key of the key pair logs in.
	TempAccess []SSHKeyAccess
}

// SSHKeyAccess is a temporary way into an instance that needs no local
// private key. Exactly one of PushKey and RunCommand is set.
type SSHKeyAccess struct {
	// Name names it in notes and errors ("EC2 Instance Connect").
	Name string
	// Check, when set, says whether it can work at all (an agent that is
	// online, say) before it is tried; an error is why not.
	Check func(ctx context.Context) error
	// PushKey makes key a valid SSH login of user for a short while (EC2
	// Instance Connect SendSSHPublicKey): a key generated in memory is
	// pushed for each login user in turn and used at once.
	PushKey func(ctx context.Context, user string, key ssh.PublicKey) error
	// RunCommand runs a command as root on the instance without SSH (Run
	// Command, Cloud Assistant): the authorized_keys scripts run through
	// it, as the target user.
	RunCommand sshremote.RunCommand
}

// label names the instance in messages: "name (id)".
func (i *SSHKeyInstance) label() string {
	if i.Name == "" || i.Name == i.ID {
		return i.ID
	}
	return i.Name + " (" + i.ID + ")"
}

// SSHKeyStore manages the keys of an instance through the platform API.
type SSHKeyStore interface {
	// List returns the keys the instance accepts, of every user.
	List(ctx context.Context) (*SSHKeyListing, error)
	// Add ensures the key is listed for user, under any options; false
	// when it already was and nothing was written. A line that restricts
	// the key (command=, restrict, from=, expiry-time=) is reported by the
	// command, never changed.
	Add(ctx context.Context, user string, key *platform.PublicKey) (bool, error)
	// Remove ensures none of keys logs in user (in the keys the store can
	// write); it returns how many entries it removed.
	Remove(ctx context.Context, user string, keys []ssh.PublicKey) (int, error)
}

// SSHKeyListing is what an SSHKeyStore lists.
type SSHKeyListing struct {
	Keys []SSHKeyEntry
	// Notes are remarks for stderr (project keys blocked, OS Login on).
	Notes []string
	// ReadOnly, when set, is why keys cannot be added or removed (OS
	// Login), wrapping platform.ErrNotSupported: add and remove return
	// it, list works.
	ReadOnly error
}

// SSHKeyEntry is one key an instance accepts.
type SSHKeyEntry struct {
	User    string
	Key     ssh.PublicKey
	Comment string
	// Source is where it is kept ("authorized_keys", "instance
	// metadata", "project metadata").
	Source string
	// ReadOnly marks a key these commands do not change (project-wide
	// keys).
	ReadOnly bool
	// Ignored marks a key the instance does not accept although it is
	// listed (project-wide keys of an instance that blocks them): add does
	// not count it as present.
	Ignored bool
	// Options are the authorized_keys options of the line.
	Options []string
}

// SSHKeyRow is a row of `ssh-key list`.
type SSHKeyRow struct {
	User        string `json:"user" yaml:"user"`
	Type        string `json:"type" yaml:"type"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Comment     string `json:"comment" yaml:"comment"`
	Source      string `json:"source" yaml:"source"`
	// InUse marks the key the command logged in with.
	InUse bool `json:"in_use,omitempty" yaml:"in_use,omitempty"`
	// ReadOnly marks a key ssh-key remove does not change.
	ReadOnly bool `json:"read_only,omitempty" yaml:"read_only,omitempty"`
	// Ignored marks a key the instance does not accept (blocked
	// project-wide keys).
	Ignored bool `json:"ignored,omitempty" yaml:"ignored,omitempty"`
	// Options are the authorized_keys options of the line.
	Options []string `json:"options,omitempty" yaml:"options,omitempty"`
	// Restricted marks a line whose options may stop the key from logging
	// in to a shell (command=, restrict, from=, expiry-time=).
	Restricted bool `json:"restricted,omitempty" yaml:"restricted,omitempty"`
}

// sshKeyFlags are the flags of the ssh-key commands.
type sshKeyFlags struct {
	keys         KeyFlags
	user         string
	fingerprints []string
	address      string
	port         int
	identityFile string
	loginUser    string
	acceptNew    bool
}

// SSHKeyCommands builds the `ssh-key` group of a platform's instance tree:
// list, add and remove.
func SSHKeyCommands(rt *Runtime, sc SSHKeyCommand) *cobra.Command {
	group := &cobra.Command{
		Use:   "ssh-key",
		Short: "List, add and remove the SSH public keys a Linux instance accepts",
		Long: "List, add and remove the SSH public keys a Linux instance accepts.\n\n" +
			sshKeyMechanism(sc) + "\n\nWindows instances log in with a password, not a key: the commands refuse\n" +
			"them with exit code 7 (see `polyctl " + sc.Tree + " password`).",
	}
	group.AddCommand(sshKeyListCommand(rt, sc), sshKeyAddCommand(rt, sc), sshKeyRemoveCommand(rt, sc))
	return group
}

func sshKeyMechanism(sc SSHKeyCommand) string {
	if sc.Metadata {
		s := "The keys are the instance's ssh-keys metadata (lines user:key), written\n" +
			"through the platform API; the instance need not be running."
		if sc.Detail != "" {
			s += "\n\n" + sc.Detail
		}
		return s
	}
	s := "An instance binds one key pair when it is created; these commands manage\n" +
		"further keys by editing ~/.ssh/authorized_keys of the user, so the instance\n" +
		"must be running.\n\n" +
		"Login: --identity-file, when given, is the only key (an encrypted one asks\n" +
		"for its passphrase on a terminal, and is exit code 2 in the non-interactive\n" +
		"flow, where an SSH agent (SSH_AUTH_SOCK) is the way). Otherwise only the\n" +
		"local private key of the instance's key pair is offered: the key of the SSH\n" +
		"agent, of ~/.ssh/id_ed25519, id_ecdsa or id_rsa, or of ~/.ssh/<key pair>.pem\n" +
		"or ~/.ssh/<key pair> whose public key is the key pair's (an encrypted file\n" +
		"is matched by its .pub, and only a match asks for its passphrase). No other\n" +
		"key is tried. When there is none (no key pair, one that cannot be read, or\n" +
		"no matching local key: the instance may have been created for someone\n" +
		"else), a note says so and the platform's temporary ways in are tried\n" +
		"instead, without asking (see below); when none works the error names each\n" +
		"one and why.\n\n" +
		"Over SSH: the address is the public IP, else the private IP (with a note);\n" +
		"--address and --port override. Login user: --login-user, else the default\n" +
		"users of the instance (see below), tried in order. Host key: checked\n" +
		"against ~/.ssh/known_hosts; a different key is refused (exit code 1) and\n" +
		"never replaced; an unknown host is asked about on a terminal (default no),\n" +
		"and needs --accept-new-host-key otherwise (exit code 2). No password is ever\n" +
		"used or enabled. Keys of another user than the login user (--user) are\n" +
		"edited as that user through `sudo -n -u`. Through a command the platform\n" +
		"runs as root, the keys are edited as the user (runuser, else sudo -n -u);\n" +
		"the user is --user, else the first default user that exists."
	if sc.Detail != "" {
		s += "\n\n" + sc.Detail
	}
	return s
}

func (sc SSHKeyCommand) addFlags(cmd *cobra.Command, f *sshKeyFlags) {
	if sc.Flags != nil {
		sc.Flags(cmd)
	}
	if sc.Metadata {
		return
	}
	cmd.Flags().StringVar(&f.address, "address", "", "address to connect to (default: the instance's public IP, else its private IP)")
	cmd.Flags().IntVar(&f.port, "port", 22, "SSH port")
	cmd.Flags().StringVar(&f.identityFile, "identity-file", "", "private key to log in with, the only one tried (~ is expanded; never stored); default: the local key of the instance's key pair")
	_ = cmd.MarkFlagFilename("identity-file")
	cmd.Flags().StringVar(&f.loginUser, "login-user", "", "user to log in as (default: the instance's default users, tried in order)")
	cmd.Flags().BoolVar(&f.acceptNew, "accept-new-host-key", false, "trust and record the host key of an instance not in ~/.ssh/known_hosts yet (a changed key is still refused)")
}

func (sc SSHKeyCommand) userHelp() string {
	if sc.Metadata {
		return "user the key logs in as (default: the user of the user@host that ends the key's comment)"
	}
	return "user whose authorized_keys to edit (default: the login user; another user needs sudo)"
}

func (sc SSHKeyCommand) use(verb string) string { return verb + " <name|id>" }

func (sc SSHKeyCommand) args(rt *Runtime) cobra.PositionalArgs {
	return RangeArgsOrInteractive(rt, 1, 1, func(cmd *cobra.Command, args []string) error {
		return UsageErrf("the instance name or id is required: %s", cmd.UseLine())
	})
}

func (sc SSHKeyCommand) event(verb string) string {
	return strings.ReplaceAll(sc.Tree, " ", ".") + ".ssh-key." + verb
}

func (sc SSHKeyCommand) allowed() []string {
	if len(sc.AllowedTypes) > 0 {
		return sc.AllowedTypes
	}
	return platform.AnyKeyTypes
}

// keyUser is the user UserFromKey derives from key, "" when it derives
// none or one that is not a valid user name (a comment is free text, and
// the user ends up in a metadata line or a shell command).
func (sc SSHKeyCommand) keyUser(key *platform.PublicKey) string {
	if sc.UserFromKey == nil {
		return ""
	}
	u := sc.UserFromKey(key)
	if u == "" || sshremote.CheckUser(u, "user") != nil {
		return ""
	}
	return u
}

// checkFlags validates the flags that need nothing read.
func (sc SSHKeyCommand) checkFlags(f *sshKeyFlags) error {
	if f.user != "" {
		if err := sshremote.CheckUser(f.user, "--user"); err != nil {
			return err
		}
	}
	if f.loginUser != "" {
		if err := sshremote.CheckUser(f.loginUser, "--login-user"); err != nil {
			return err
		}
	}
	if !sc.Metadata && (f.port < 1 || f.port > 65535) {
		return UsageErrf("--port %d is not a TCP port", f.port)
	}
	return nil
}

func sshKeyListCommand(rt *Runtime, sc SSHKeyCommand) *cobra.Command {
	f := &sshKeyFlags{}
	cmd := &cobra.Command{
		Use:   sc.use("list"),
		Short: "List the SSH public keys of a Linux instance",
		Long: "List the SSH public keys a Linux instance accepts: USER, TYPE, FINGERPRINT\n" +
			"(SHA256), COMMENT and SOURCE (-o json / -o yaml: user, type, fingerprint,\n" +
			"comment, source, in_use, read_only, ignored). The key the command logged in\n" +
			"with is marked in use. On a terminal, without the instance one is picked.",
		Example: "  polyctl " + sc.Tree + " ssh-key list web-1",
		Args:    sc.args(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := sc.checkFlags(f); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return ErrOffline
			}
			s, err := sc.open(cmd.Context(), rt, f, Arg(args, 0))
			if err != nil {
				return err
			}
			defer s.close()
			entries, err := s.list(cmd.Context(), s.user(f.user))
			if err != nil {
				return err
			}
			rows := make([]SSHKeyRow, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, s.row(e))
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"USER", "TYPE", "FINGERPRINT", "COMMENT", "SOURCE"}}
				for _, r := range rows {
					src := r.Source
					if r.InUse {
						src += " (in use)"
					}
					if r.ReadOnly {
						src += " (read-only)"
					}
					if r.Ignored {
						src += " (ignored)"
					}
					if r.Restricted {
						src += " (restricted)"
					}
					g.Rows = append(g.Rows, []string{r.User, r.Type, r.Fingerprint, r.Comment, src})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&f.user, "user", "", sc.listUserHelp())
	sc.addFlags(cmd, f)
	return cmd
}

func (sc SSHKeyCommand) listUserHelp() string {
	if sc.Metadata {
		return "list only the keys of this user"
	}
	return "user whose authorized_keys to list (default: the login user; another user needs sudo)"
}

func sshKeyAddCommand(rt *Runtime, sc SSHKeyCommand) *cobra.Command {
	f := &sshKeyFlags{}
	cmd := &cobra.Command{
		Use:   sc.use("add"),
		Short: "Add an SSH public key to a Linux instance (ensure: nothing changes when it is there)",
		Long: "Add an SSH public key to a Linux instance. Like ensure, it reads first: a key\n" +
			"the user already has (compared by type and key data, not by comment or\n" +
			"options) is reported unchanged and nothing is written. The report names the\n" +
			"key as key/<user>/<SHA256 fingerprint>; --dry-run reads and reports would\n" +
			"create.\n\n" +
			"The key is --ssh-key (the key itself) or --ssh-key-file; on a terminal,\n" +
			"without either, the ~/.ssh/*.pub keys are offered, with another file and\n" +
			"typing the key. In the non-interactive flow a missing key is exit code 2\n" +
			"before anything is read.",
		Example: "  polyctl " + sc.Tree + " ssh-key add web-1 --ssh-key-file ~/.ssh/id_ed25519.pub\n" +
			"  polyctl " + sc.Tree + " ssh-key add web-1 --ssh-key \"ssh-ed25519 AAAA... alice@laptop\" --user deploy",
		Args: sc.args(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := sc.checkFlags(f); err != nil {
				return err
			}
			key, err := f.keys.PublicKey()
			if err != nil {
				return err
			}
			if key != nil {
				if err := key.CheckType(sc.allowed()); err != nil {
					return err
				}
			} else if !rt.Interactive() {
				return UsageErrf("a public key is required: pass --ssh-key-file <path> or --ssh-key <public key>")
			}
			if key != nil && f.user == "" && sc.UserFromKey != nil && sc.keyUser(key) == "" && !rt.Interactive() {
				return UsageErrf("--user is required: the key's comment ends with no user@host to take the user from")
			}
			if rt.Flags.Offline {
				return ErrOffline
			}
			s, err := sc.open(ctx, rt, f, Arg(args, 0))
			if err != nil {
				return err
			}
			defer s.close()
			if err := s.readOnly(ctx); err != nil {
				return err
			}
			if key == nil {
				present, err := s.list(ctx, s.user(f.user))
				if err != nil {
					return err
				}
				if key, err = s.askKey(present); err != nil {
					return err
				}
			}
			user := s.user(f.user)
			if user == "" {
				user = sc.keyUser(key)
				if user == "" {
					if user, err = rt.AskInput("--user", "User the key logs in as", "", func(v string) error {
						return inlineErr(sshremote.CheckUser(strings.TrimSpace(v), "user"))
					}); err != nil {
						return err
					}
				}
			}
			res := "key/" + user + "/" + key.FingerprintSHA256()
			detail := key.Summary() + " (from " + key.Source + ")" + s.via(user)
			plan := &platform.Plan{}
			plan.Add(platform.Step{Resource: res, Action: platform.Created, Desc: detail, Attrs: s.attrs(user, key.Key),
				Check: func(ctx context.Context) (platform.Change, bool, error) {
					entries, err := s.list(ctx, user)
					if err != nil {
						return platform.Change{}, false, err
					}
					for _, e := range entries {
						if e.User == user && !e.Ignored && sshremote.SameKey(e.Key, key.Key) {
							d := "already present (" + e.Source + ")"
							if e.ReadOnly {
								d = "already present in " + e.Source + " (left as it is)"
							}
							if r := sshremote.Restrictions(e.Options); len(r) > 0 {
								opts := strings.Join(r, ",")
								d = "already present (" + e.Source + ") with options " + opts + "; this line may not allow a shell login, polyctl leaves it as it is"
								s.note(fmt.Sprintf("warning: the key is already in %s of %s with options %s, which may stop it from logging in to a shell; polyctl does not change that line", e.Source, user, opts))
							}
							return platform.Change{Detail: d}, true, nil
						}
					}
					return platform.Change{}, false, nil
				},
				Apply: func(ctx context.Context) (platform.Change, error) {
					added, err := s.add(ctx, user, key)
					if err == nil && !added {
						return platform.Change{Action: platform.Unchanged, Detail: "already present"}, nil
					}
					return platform.Change{}, err
				}})
			return rt.Ensure(ctx, sc.event("add"), s.inst.Target, plan)
		},
	}
	AddPublicKeyFlags(cmd, &f.keys)
	cmd.Flags().StringVar(&f.user, "user", "", sc.userHelp())
	sc.addFlags(cmd, f)
	return cmd
}

func sshKeyRemoveCommand(rt *Runtime, sc SSHKeyCommand) *cobra.Command {
	f := &sshKeyFlags{}
	cmd := &cobra.Command{
		Use:   sc.use("remove"),
		Short: "Remove SSH public keys from a Linux instance (asks for confirmation)",
		Long: "Remove SSH public keys from a Linux instance: every entry of the user that\n" +
			"holds the key (--ssh-key, --ssh-key-file, or --fingerprint SHA256:...,\n" +
			"repeatable) is removed, the others are kept as they are. A key that is not\n" +
			"there is reported unchanged. On a terminal, without a key flag, the keys\n" +
			"are listed to pick from (several may be ticked).\n\n" +
			"It asks for confirmation (default no; --yes answers yes, and the\n" +
			"non-interactive flow needs it). It refuses (exit code 1) to remove the key\n" +
			"the command logged in with (a local key), and the last key of the user,\n" +
			"so that the user is never locked out of the instance.",
		Example: "  polyctl " + sc.Tree + " ssh-key remove web-1 --fingerprint SHA256:abc... --yes\n" +
			"  polyctl " + sc.Tree + " ssh-key remove web-1 --ssh-key-file ~/.ssh/old.pub --user deploy",
		Args: sc.args(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := sc.checkFlags(f); err != nil {
				return err
			}
			var want []sshKeyMatch
			key, err := f.keys.PublicKey()
			if err != nil {
				return err
			}
			if key != nil {
				want = append(want, sshKeyMatch{label: key.Summary(), key: key.Key})
			}
			for _, fp := range f.fingerprints {
				norm, err := normalizeFingerprint(fp)
				if err != nil {
					return err
				}
				want = append(want, sshKeyMatch{label: norm, fingerprint: norm})
			}
			if len(want) == 0 && !rt.Interactive() {
				return UsageErrf("the key to remove is required: pass --fingerprint SHA256:..., --ssh-key-file <path> or --ssh-key <public key>")
			}
			if !rt.DryRun() {
				if err := rt.CanConfirm("remove SSH keys"); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return ErrOffline
			}
			s, err := sc.open(ctx, rt, f, Arg(args, 0))
			if err != nil {
				return err
			}
			defer s.close()
			if err := s.readOnly(ctx); err != nil {
				return err
			}
			listUser := s.user(f.user)
			entries, err := s.list(ctx, listUser)
			if err != nil {
				return err
			}
			if len(want) == 0 {
				if want, err = s.pickRemovals(entries); err != nil {
					return err
				}
			}
			// Each requested key: the entries holding it (of the user, when
			// one is known), or unchanged.
			var steps []platform.Step
			type removal struct {
				user string
				keys []ssh.PublicKey
			}
			byUser := map[string]*removal{}
			var users []string
			for _, w := range want {
				var hit []SSHKeyEntry
				for _, e := range entries {
					if (listUser == "" || e.User == listUser) && !e.ReadOnly && w.matches(e.User, e.Key) {
						hit = append(hit, e)
					}
				}
				if len(hit) == 0 {
					u := listUser
					if u == "" {
						u = "*"
					}
					steps = append(steps, platform.Step{Resource: "key/" + u + "/" + w.label, Action: platform.Unchanged, Desc: "not present"})
					continue
				}
				seen := map[string]bool{}
				for _, e := range hit {
					fp := ssh.FingerprintSHA256(e.Key)
					if seen[e.User+fp] {
						continue
					}
					seen[e.User+fp] = true
					r := byUser[e.User]
					if r == nil {
						r = &removal{user: e.User}
						byUser[e.User] = r
						users = append(users, e.User)
					}
					r.keys = append(r.keys, e.Key)
					steps = append(steps, platform.Step{Resource: "key/" + e.User + "/" + fp, Action: platform.Deleted,
						Desc: keyEntrySummary(e) + s.via(e.User), Attrs: s.attrs(e.User, e.Key)})
				}
			}
			// The guards, before the confirmation and again on the file
			// as it is right before the write.
			for _, u := range users {
				if err := s.guard(u, entries, byUser[u].keys); err != nil {
					return err
				}
			}
			deletes := 0
			for _, st := range steps {
				if st.Action == platform.Deleted {
					deletes++
				}
			}
			if deletes > 0 && !rt.DryRun() {
				for _, st := range steps {
					if st.Action == platform.Deleted {
						rt.Infof("  %s  %s", st.Resource, st.Desc)
					}
				}
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Remove %d SSH key(s) from instance %s?", deletes, s.inst.label()), false)
				if err != nil {
					return err
				}
				if !ok {
					return NothingToDof("cancelled; no key was removed from instance %s", s.inst.label())
				}
			}
			plan := &platform.Plan{}
			done := map[string]bool{}
			for _, st := range steps {
				if st.Action != platform.Deleted {
					plan.Add(st)
					continue
				}
				user := strings.SplitN(strings.TrimPrefix(st.Resource, "key/"), "/", 2)[0]
				r := byUser[user]
				st.Apply = func(ctx context.Context) (platform.Change, error) {
					// One write per user removes all of that user's keys;
					// the later steps of the user report it.
					if done[user] {
						return platform.Change{}, nil
					}
					done[user] = true
					n, err := s.remove(ctx, user, r.keys)
					if err == nil && n == 0 {
						return platform.Change{Action: platform.Unchanged, Detail: "not present any more"}, nil
					}
					return platform.Change{}, err
				}
				plan.Add(st)
			}
			return rt.Ensure(ctx, sc.event("remove"), s.inst.Target, plan)
		},
	}
	AddPublicKeyFlags(cmd, &f.keys)
	cmd.Flags().StringArrayVar(&f.fingerprints, "fingerprint", nil, "SHA256 fingerprint of a key to remove, as ssh-key list shows it; repeatable")
	cmd.Flags().StringVar(&f.user, "user", "", sc.removeUserHelp())
	sc.addFlags(cmd, f)
	return cmd
}

func (sc SSHKeyCommand) removeUserHelp() string {
	if sc.Metadata {
		return "remove the key for this user only (default: for every user that has it)"
	}
	return "user whose authorized_keys to edit (default: the login user; another user needs sudo)"
}

// sshKeyMatch is a key to remove: by public key or by SHA256 fingerprint,
// of user when it is set (a key picked from the list is the entry of one
// user, not the same key of every user).
type sshKeyMatch struct {
	label       string
	key         ssh.PublicKey
	fingerprint string
	user        string
}

func (m sshKeyMatch) matches(user string, k ssh.PublicKey) bool {
	if m.user != "" && m.user != user {
		return false
	}
	if m.key != nil {
		return sshremote.SameKey(m.key, k)
	}
	return ssh.FingerprintSHA256(k) == m.fingerprint
}

// normalizeFingerprint accepts "SHA256:<base64>" or the bare base64 (with
// or without padding).
func normalizeFingerprint(fp string) (string, error) {
	v := strings.TrimRight(strings.TrimPrefix(strings.TrimSpace(fp), "SHA256:"), "=")
	if len(v) != 43 || strings.ContainsFunc(v, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/')
	}) {
		return "", UsageErrf("--fingerprint %q is not a SHA256 key fingerprint (SHA256:... as `ssh-key list` shows it)", fp)
	}
	return "SHA256:" + v, nil
}

func keyEntrySummary(e SSHKeyEntry) string {
	pk := &platform.PublicKey{Key: e.Key, Comment: e.Comment}
	return pk.Summary()
}

// sshKeySession is an opened instance: the backend that lists and edits
// its keys.
type sshKeySession struct {
	rt   *Runtime
	sc   SSHKeyCommand
	inst *SSHKeyInstance
	// editor edits authorized_keys (nil for a metadata store): client
	// over SSH, or a command run as root (access names it).
	editor sshremote.KeyEditor
	client *sshremote.Client
	access string
	// loginUser is the user the command is about without --user: the SSH
	// login user, or the default user found through a run command.
	loginUser string
	// localKey says the SSH session authenticated with a local key (not a
	// one-time key): only that key is guarded against removal.
	localKey bool
	store    *SSHKeyListing
	keys     *sshremote.KeySet
	// noted holds the notes printed, each once.
	noted map[string]bool
}

func (s *sshKeySession) close() {
	if s.client != nil {
		_ = s.client.Close()
	}
	if s.keys != nil {
		s.keys.Close()
	}
}

// user is the user the command is about: --user, else the login user; ""
// for a metadata store without --user.
func (s *sshKeySession) user(flag string) string {
	if flag != "" {
		return flag
	}
	return s.loginUser
}

func (s *sshKeySession) via(user string) string {
	switch {
	case s.client != nil:
		v := " via " + s.client.User + "@" + s.client.Addr
		if s.client.NeedsSudo(user) {
			v += " (sudo)"
		}
		if s.access != "" {
			v += " (" + s.access + ")"
		}
		return v
	case s.editor != nil:
		return " via " + s.access + " (as root)"
	}
	return ""
}

func (s *sshKeySession) attrs(user string, key ssh.PublicKey) map[string]string {
	a := map[string]string{"user": user, "fingerprint": ssh.FingerprintSHA256(key)}
	if s.client != nil {
		a["login_user"] = s.client.User
		a["address"] = s.client.Addr
	}
	if s.access != "" {
		a["access"] = s.access
	}
	return a
}

func (s *sshKeySession) inUse(user string, k ssh.PublicKey) bool {
	return s.localKey && s.client != nil && user == s.client.User && sshremote.SameKey(s.client.Key, k)
}

func (s *sshKeySession) row(e SSHKeyEntry) SSHKeyRow {
	pk := &platform.PublicKey{Key: e.Key}
	return SSHKeyRow{User: e.User, Type: pk.Algorithm(), Fingerprint: pk.FingerprintSHA256(), Comment: e.Comment,
		Source: e.Source, InUse: s.inUse(e.User, e.Key), ReadOnly: e.ReadOnly, Ignored: e.Ignored,
		Options: e.Options, Restricted: len(sshremote.Restrictions(e.Options)) > 0}
}

func (s *sshKeySession) note(msg string) {
	if s.noted == nil {
		s.noted = map[string]bool{}
	}
	if !s.noted[msg] {
		s.noted[msg] = true
		s.rt.Infof("%s", msg)
	}
}

// list returns the keys of user ("" for every user of a metadata store).
func (s *sshKeySession) list(ctx context.Context, user string) ([]SSHKeyEntry, error) {
	if s.editor == nil {
		l, err := s.inst.Metadata.List(ctx)
		if err != nil {
			return nil, err
		}
		s.store = l
		for _, n := range l.Notes {
			s.note(n)
		}
		var out []SSHKeyEntry
		for _, e := range l.Keys {
			if user == "" || e.User == user {
				out = append(out, e)
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].ReadOnly != out[j].ReadOnly {
				return !out[i].ReadOnly
			}
			return out[i].User < out[j].User
		})
		return out, nil
	}
	ak, err := s.editor.ListKeys(ctx, user)
	if err != nil {
		return nil, err
	}
	if ak.CustomFile() {
		s.note(fmt.Sprintf("warning: sshd on the instance sets AuthorizedKeysFile %s: polyctl edits ~/.ssh/authorized_keys only, which sshd may not read", ak.AuthorizedKeysFile))
	}
	out := make([]SSHKeyEntry, 0, len(ak.Entries))
	for _, e := range ak.Entries {
		out = append(out, SSHKeyEntry{User: user, Key: e.Key, Comment: e.Comment, Source: "authorized_keys", Options: e.Options})
	}
	return out, nil
}

// readOnly is why the keys cannot be written (OS Login), if they cannot.
func (s *sshKeySession) readOnly(ctx context.Context) error {
	if s.editor != nil {
		return nil
	}
	if s.store == nil {
		if _, err := s.list(ctx, ""); err != nil {
			return err
		}
	}
	return s.store.ReadOnly
}

func (s *sshKeySession) add(ctx context.Context, user string, key *platform.PublicKey) (bool, error) {
	if s.editor == nil {
		return s.inst.Metadata.Add(ctx, user, key)
	}
	return s.editor.AddKey(ctx, user, key.Key, key.Comment)
}

func (s *sshKeySession) remove(ctx context.Context, user string, keys []ssh.PublicKey) (int, error) {
	if s.editor == nil {
		return s.inst.Metadata.Remove(ctx, user, keys)
	}
	return s.editor.RemoveKeys(ctx, user, keys, func(ak *sshremote.AuthorizedKeys, _ []sshremote.Entry) error {
		entries := make([]SSHKeyEntry, 0, len(ak.Entries))
		for _, e := range ak.Entries {
			entries = append(entries, SSHKeyEntry{User: user, Key: e.Key})
		}
		return s.guard(user, entries, keys)
	})
}

// guard refuses a removal that would lock the user out: the local key the
// command logged in with, or every key the user has in authorized_keys
// (whichever way the file is reached). Keys kept in metadata can always be
// added again through the platform API, so a metadata store has no guard.
func (s *sshKeySession) guard(user string, entries []SSHKeyEntry, remove []ssh.PublicKey) error {
	if s.editor == nil {
		return nil
	}
	gone := func(k ssh.PublicKey) bool {
		for _, r := range remove {
			if sshremote.SameKey(r, k) {
				return true
			}
		}
		return false
	}
	if s.localKey && s.client != nil && s.client.Key != nil && user == s.client.User && gone(s.client.Key) {
		return fmt.Errorf("refusing to remove %s of %s: it is the key this command logged in with, and removing it could lock you out; log in with another key (--identity-file) to remove it",
			(&platform.PublicKey{Key: s.client.Key}).Summary(), user)
	}
	left := 0
	for _, e := range entries {
		if e.User == user && !gone(e.Key) {
			left++
		}
	}
	if left == 0 {
		return fmt.Errorf("refusing to remove the last key of %s on instance %s: the user could no longer log in with a key; add another key first (ssh-key add)", user, s.inst.label())
	}
	return nil
}

// askKey asks for the key to add: the ~/.ssh/*.pub keys (those already
// present marked), another file, or the key typed.
func (s *sshKeySession) askKey(present []SSHKeyEntry) (*platform.PublicKey, error) {
	check := func(k *platform.PublicKey) error { return k.CheckType(s.sc.allowed()) }
	var cands []platform.KeyFileCandidate
	for _, path := range platform.PublicKeyFiles() {
		k, err := platform.LoadPublicKeyFile(path)
		if err != nil || check(k) != nil {
			continue
		}
		c := platform.KeyFileCandidate{Path: path, Key: k}
		var users []string
		for _, e := range present {
			if sshremote.SameKey(e.Key, k.Key) && !contains(users, e.User) {
				users = append(users, e.User)
			}
		}
		if len(users) > 0 {
			c.Note = "already there for " + strings.Join(users, ", ")
		}
		cands = append(cands, c)
	}
	pick := s.rt.Pick()
	choice, err := PickKeyFile(pick, "Public key to add to "+s.inst.label(), cands)
	if err != nil {
		return nil, err
	}
	switch {
	case IsTypedKey(choice):
		return AskTypedKey(pick, "Public key (one line: \"ssh-ed25519 AAAA... comment\")", check)
	case IsOtherKeyFile(choice):
		return AskKeyFile(pick, check)
	}
	k, err := platform.LoadPublicKeyFile(choice)
	if err != nil {
		return nil, err
	}
	return k, check(k)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// pickRemovals asks which of the listed keys to remove; the key the
// command logged in with and read-only keys are not offered.
func (s *sshKeySession) pickRemovals(entries []SSHKeyEntry) ([]sshKeyMatch, error) {
	var opts []prompt.Option
	byValue := map[string]sshKeyMatch{}
	for _, e := range entries {
		if e.ReadOnly || s.inUse(e.User, e.Key) {
			continue
		}
		fp := ssh.FingerprintSHA256(e.Key)
		v := e.User + " " + fp
		if _, ok := byValue[v]; ok {
			continue
		}
		byValue[v] = sshKeyMatch{label: fp, key: e.Key, user: e.User}
		label := e.User + "  " + keyEntrySummary(e) + "  [" + e.Source + "]"
		opts = append(opts, prompt.Option{Label: label, Value: v})
	}
	vs, err := s.rt.ChooseMany(Choice{Title: "Keys to remove from " + s.inst.label(), Options: opts, Arg: "--fingerprint",
		Empty: NothingToDof("no key of instance %s can be removed here", s.inst.label())})
	if err != nil {
		return nil, err
	}
	out := make([]sshKeyMatch, 0, len(vs))
	for _, v := range vs {
		out = append(out, byValue[v])
	}
	return out, nil
}

// open resolves the instance and reaches its keys: the metadata store, or
// an SSH login.
func (sc SSHKeyCommand) open(ctx context.Context, rt *Runtime, f *sshKeyFlags, arg string) (_ *sshKeySession, err error) {
	inst, err := sc.Resolve(ctx, arg)
	if err != nil {
		return nil, err
	}
	s := &sshKeySession{rt: rt, sc: sc, inst: inst}
	defer func() {
		// The caller closes an opened session; a failed one releases the
		// keys (the SSH agent connection) here.
		if err != nil {
			s.close()
		}
	}()
	if inst.Windows {
		return nil, fmt.Errorf("%w: instance %s runs Windows, which logs in with a password, not an SSH key; `polyctl %s password %s` shows it", platform.ErrNotSupported, inst.label(), sc.Tree, inst.ID)
	}
	if inst.Metadata != nil {
		return s, nil
	}
	if !inst.Running {
		state := inst.State
		if state == "" {
			state = "not running"
		}
		return nil, fmt.Errorf("instance %s is %s: its keys are edited over SSH, so it must be running; start it with `polyctl %s start %s`", inst.label(), state, sc.Tree, inst.ID)
	}
	users := inst.LoginUsers
	if f.loginUser != "" {
		users = []string{f.loginUser}
	} else if inst.LoginUsersNote != "" {
		rt.Infof("%s", inst.LoginUsersNote)
	}
	if len(users) == 0 {
		u, err := rt.AskInput("--login-user", "User to log in to "+inst.label()+" as", "", func(v string) error {
			return inlineErr(sshremote.CheckUser(strings.TrimSpace(v), "user"))
		})
		if err != nil {
			if errors.Is(err, ErrUsage) {
				return nil, UsageErrf("--login-user is required: polyctl cannot tell the default user of the image of instance %s", inst.label())
			}
			return nil, err
		}
		users = []string{u}
	}
	var passphrase func(string) (string, error)
	if rt.Interactive() {
		passphrase = func(path string) (string, error) {
			return rt.Prompt().WithContext(ctx).Secret("Passphrase for " + HomeRelative(path) + " (empty to skip)")
		}
	}
	hk := &sshremote.HostKeys{AcceptNew: f.acceptNew, Notef: rt.Infof}
	if rt.DryRun() {
		hk.NoSave = true
	}
	if rt.Interactive() {
		hk.Trust = func(host string, key ssh.PublicKey) (bool, error) {
			rt.Infof("The host key of %s is not in ~/.ssh/known_hosts.\n%s key fingerprint: %s", host, strings.ToUpper((&platform.PublicKey{Key: key}).Algorithm()), ssh.FingerprintSHA256(key))
			return rt.Pick().Confirm("Trust this host key and record it in ~/.ssh/known_hosts?", false)
		}
	}
	addr, addrErr := f.address, error(nil)
	addrDone := addr != ""
	dial := func(ks *sshremote.KeySet, users []string, pass func(string) (string, error)) (*sshremote.Client, error) {
		if !addrDone {
			addrDone = true
			switch {
			case inst.PublicIP != "":
				addr = inst.PublicIP
			case inst.PrivateIP != "":
				addr = inst.PrivateIP
				rt.Infof("note: instance %s has no public IP; connecting to its private IP %s (pass --address to use another)", inst.label(), addr)
			default:
				addrErr = &noAddressError{inst: inst.label()}
			}
		}
		if addrErr != nil {
			return nil, addrErr
		}
		return sshremote.Dial(ctx, sshremote.Options{Address: addr, Port: f.port, Users: users, Keys: ks, HostKeys: hk, Passphrase: pass})
	}
	loginHint := ""
	if f.loginUser == "" {
		loginHint = ", or name the user with --login-user"
	}

	// --identity-file: that key only, whatever the key pair.
	if f.identityFile != "" {
		ks, err := sshremote.LoadKeys(sshremote.KeyOptions{IdentityFile: f.identityFile, Passphrase: passphrase})
		if err != nil {
			return nil, err
		}
		s.keys = ks
		c, err := dial(ks, users, nil)
		var ae *sshremote.AuthError
		if errors.As(err, &ae) {
			return nil, fmt.Errorf("%w; pass the private key of a key the instance accepts with --identity-file%s", err, loginHint)
		}
		if err != nil {
			return nil, err
		}
		s.useClient(c, true, "", users)
		return s, nil
	}

	// The local private key of the key pair, if this machine has it.
	// reason is why no local key logged in; why it was not even tried,
	// with untried.
	var reason string
	untried := true
	kpName := inst.KeyPairName
	if inst.KeyPair != nil && inst.KeyPair.Name != "" {
		kpName = inst.KeyPair.Name
	}
	switch {
	case inst.KeyPair == nil && kpName == "":
		reason = fmt.Sprintf("instance %s has no key pair", inst.label())
	case inst.KeyPair == nil:
		why := inst.KeyPairError
		if why == "" {
			why = "it cannot be read"
		}
		reason = fmt.Sprintf("the key pair %s of instance %s cannot be read (%s)", kpName, inst.label(), why)
	default:
		ks, err := sshremote.LoadKeys(sshremote.KeyOptions{Passphrase: passphrase, Match: inst.matchKeyPair(), Files: keyPairFiles(kpName)})
		if err != nil {
			return nil, err
		}
		s.keys = ks
		for _, n := range ks.Notes {
			rt.Infof("%s", n)
		}
		if len(ks.Signers) == 0 {
			reason = fmt.Sprintf("the key pair %s of instance %s has no private key on this machine", kpName, inst.label())
			break
		}
		c, err := dial(ks, users, nil)
		if err == nil {
			s.useClient(c, true, "", users)
			return s, nil
		}
		if !canTryOtherAccess(err) {
			return nil, err
		}
		if len(inst.TempAccess) == 0 {
			var ae *sshremote.AuthError
			if !errors.As(err, &ae) {
				// Not reachable: another key would not help.
				return nil, err
			}
			return nil, fmt.Errorf("%w; pass the private key of a key the instance accepts with --identity-file%s", err, loginHint)
		}
		reason, untried = fmt.Sprintf("the key pair %s of instance %s did not log in: %v", kpName, inst.label(), err), false
	}
	if untried {
		reason += ", so no local key is tried (the instance may have been created for someone else)"
	}
	if len(inst.TempAccess) == 0 {
		return nil, fmt.Errorf("%s; pass the private key of a key the instance accepts with --identity-file%s", reason, loginHint)
	}
	names := make([]string, 0, len(inst.TempAccess))
	for _, a := range inst.TempAccess {
		names = append(names, a.Name)
	}
	rt.Infof("note: %s; trying %s", reason, strings.Join(names, ", then "))

	// The temporary ways in, in order.
	failures := []string{reason}
	// denied: the platform refused every temporary way in (a RAM / IAM
	// denial, ErrForbidden, or credentials it does not take,
	// ErrUnauthorized).
	denied, unauthorized := true, false
	for _, a := range inst.TempAccess {
		var err error
		if a.Check != nil {
			err = a.Check(ctx)
		}
		if err == nil {
			switch {
			case a.PushKey != nil:
				var c *sshremote.Client
				c, err = s.pushKey(ctx, a, users, dial)
				if err == nil {
					s.useClient(c, false, a.Name, users)
					return s, nil
				}
				if !canTryOtherAccess(err) && !errors.Is(err, errPushFailed) {
					return nil, err
				}
			case a.RunCommand != nil:
				ed := &sshremote.RootEditor{Run: a.RunCommand, Via: a.Name}
				var u string
				if u, err = ed.FirstUser(ctx, users); err == nil {
					if u == "" {
						u = users[0]
					}
					s.editor, s.access, s.loginUser = ed, a.Name, u
					user := u
					if f.user != "" {
						user = f.user
					}
					rt.Infof("note: editing the keys of %s on instance %s through %s, which runs as root", user, inst.label(), a.Name)
					return s, nil
				}
			default:
				err = errors.New("no way to use it")
			}
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		failures = append(failures, a.Name+": "+err.Error())
		switch {
		case errors.Is(err, platform.ErrUnauthorized):
			unauthorized = true
		case !errors.Is(err, platform.ErrForbidden):
			denied = false
		}
	}
	return nil, &sshKeyAccessError{denied: denied, unauthorized: unauthorized, msg: fmt.Sprintf("cannot reach the keys of instance %s: %s; pass the private key of a key the instance accepts with --identity-file%s",
		inst.label(), strings.Join(failures, "; "), loginHint)}
}

// useClient makes c the session's editor.
func (s *sshKeySession) useClient(c *sshremote.Client, local bool, access string, users []string) {
	s.client, s.editor, s.loginUser, s.localKey, s.access = c, c, c.User, local, access
	if len(c.Tried) > 0 || len(users) > 1 || access != "" {
		from := ""
		if s.inst.LoginUsersFrom != "" && len(users) > 1 {
			from = " (default users of " + s.inst.LoginUsersFrom + ")"
		}
		s.rt.Infof("note: logged in to %s as %s%s with %s", c.Addr, c.User, from, c.KeySource)
	}
}

// noAddressError is an instance with no IP address to connect to.
type noAddressError struct{ inst string }

func (e *noAddressError) Error() string {
	return "instance " + e.inst + " has no IP address to connect to; pass --address"
}

// canTryOtherAccess reports whether an SSH login that failed with err
// leaves room for another way in: the key was not accepted, or the address
// cannot be reached. A host key refusal, a cancelled context and the like
// stop at once.
func canTryOtherAccess(err error) bool {
	var ae *sshremote.AuthError
	var ce *sshremote.ConnectError
	var na *noAddressError
	return errors.As(err, &ae) || errors.As(err, &ce) || errors.As(err, &na)
}

// errPushFailed marks a key the platform refused to push.
var errPushFailed = errors.New("push failed")

// sshKeyAccessError is the failure of every way into an instance; it is an
// authorization failure when the platform denied every temporary way in.
type sshKeyAccessError struct {
	msg    string
	denied bool
	// unauthorized: one of the denials was ErrUnauthorized, not only
	// ErrForbidden.
	unauthorized bool
}

func (e *sshKeyAccessError) Error() string { return e.msg }

func (e *sshKeyAccessError) Unwrap() error {
	switch {
	case !e.denied:
		return nil
	case e.unauthorized:
		return platform.ErrUnauthorized
	}
	return platform.ErrForbidden
}

// pushKey logs in with a one-time key generated in memory, pushed by a for
// each login user in turn and used at once. A push that succeeds proves
// nothing (the image may not use it): a login that fails moves on to the
// next user.
func (s *sshKeySession) pushKey(ctx context.Context, a SSHKeyAccess, users []string,
	dial func(*sshremote.KeySet, []string, func(string) (string, error)) (*sshremote.Client, error)) (*sshremote.Client, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	src := "a one-time " + a.Name + " key"
	var tried []sshremote.Attempt
	addr := ""
	for _, u := range users {
		if err := a.PushKey(ctx, u, signer.PublicKey()); err != nil {
			return nil, &pushError{user: u, err: err}
		}
		ks := &sshremote.KeySet{Signers: []sshremote.Signer{{Signer: signer, Source: src}}}
		c, err := dial(ks, []string{u}, nil)
		var ae *sshremote.AuthError
		if errors.As(err, &ae) {
			tried, addr = append(tried, ae.Tried...), ae.Addr
			continue
		}
		if err != nil {
			return nil, err
		}
		c.Tried = append(tried, c.Tried...)
		return c, nil
	}
	return nil, &sshremote.AuthError{Addr: addr, Tried: tried, Keys: src + " (does the image use it?)"}
}

// pushError is a key the platform did not push.
type pushError struct {
	user string
	err  error
}

func (e *pushError) Error() string { return "pushing a key for " + e.user + ": " + e.err.Error() }

func (e *pushError) Unwrap() []error { return []error{e.err, errPushFailed} }

// matchKeyPair tells the local keys of the instance's key pair.
func (i *SSHKeyInstance) matchKeyPair() func(ssh.PublicKey) bool {
	m := i.KeyPairMatch
	if m.Match == nil {
		m = platform.MatchByPublicKey
	}
	kp := *i.KeyPair
	return func(k ssh.PublicKey) bool { return m.Match(&platform.PublicKey{Key: k}, kp) }
}

// keyPairFiles are the private key files named after a key pair that are
// looked at besides the default keys: ~/.ssh/<name>.pem (as the platform
// downloads it) and ~/.ssh/<name>. A name that is not a plain file name is
// left out.
func keyPairFiles(name string) []string {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".ssh")
	return []string{filepath.Join(dir, name+".pem"), filepath.Join(dir, name)}
}
