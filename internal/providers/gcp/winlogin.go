package gcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // the guest agent encrypts the password with RSA-OAEP and SHA-1
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// computeInstanceTree is the command group of Compute Engine instances, as
// the notes about the password command name it.
const computeInstanceTree = "gcp compute instance"

// defaultWindowsUser is the Windows user create sets the password of when
// --windows-user is not given. Compute Engine Windows images have no
// password of their own: the guest agent creates the user (an
// administrator) and sets its password on request.
const defaultWindowsUser = "polyctl-admin"

// The guest agent answers within a few minutes of the first boot; the wait
// is bounded by defaultPasswordTimeout unless --password-timeout says
// otherwise, and polls the serial port every 10 seconds. Tests shorten
// nothing: they use the fake clock of the instance waits.
var passwordPollInterval = 10 * time.Second

const defaultPasswordTimeout = 10 * time.Minute

// minKeyLifetime is the shortest lifetime of a windows-keys entry: the
// guest agent ignores an entry once its expireOn has passed.
const minKeyLifetime = 5 * time.Minute

// The metadata key the guest agent reads password requests from, and the
// serial port it answers on.
const (
	windowsKeysKey   = "windows-keys"
	windowsAgentPort = 4
)

// windowsKeyEntry is one line of the windows-keys metadata value: the
// password request gcloud compute reset-windows-password writes.
type windowsKeyEntry struct {
	UserName string `json:"userName"`
	Modulus  string `json:"modulus"`
	Exponent string `json:"exponent"`
	Email    string `json:"email"`
	ExpireOn string `json:"expireOn"`
}

// agentAnswer is a line the guest agent writes to serial port 4.
type agentAnswer struct {
	UserName          string `json:"userName"`
	PasswordFound     bool   `json:"passwordFound"`
	EncryptedPassword string `json:"encryptedPassword"`
	Modulus           string `json:"modulus"`
	Exponent          string `json:"exponent"`
	ErrorMessage      string `json:"errorMessage"`
}

// windowsUserForbidden are the characters a Windows user name cannot hold.
const windowsUserForbidden = `"/\[]:;|=,+*?<>@`

// checkWindowsUser validates a Windows user name: 1 to 20 characters, no
// spaces, control characters or `"/\[]:;|=,+*?<>@`, not only periods and
// not ending with one.
func checkWindowsUser(u, flag string) error {
	bad := func(why string) error {
		return app.UsageErrf("%s %q is not a valid Windows user name: %s", flag, u, why)
	}
	switch {
	case u == "":
		return bad("it is empty")
	case len(u) > 20:
		return bad("at most 20 characters")
	case strings.Trim(u, ".") == "":
		return bad("it cannot consist of periods only")
	case strings.HasSuffix(u, "."):
		return bad("it cannot end with a period")
	}
	for _, r := range u {
		if r <= ' ' || r == 0x7f || r > 0x7e {
			return bad("letters, digits and punctuation only, no spaces")
		}
		if strings.ContainsRune(windowsUserForbidden, r) {
			return bad("it cannot contain any of " + windowsUserForbidden)
		}
	}
	return nil
}

// newWindowsKey generates the RSA-2048 key of one password request and its
// windows-keys entry, which expires after lifetime.
func newWindowsKey(user, email string, now time.Time, lifetime time.Duration) (*rsa.PrivateKey, windowsKeyEntry, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, windowsKeyEntry{}, err
	}
	if lifetime < minKeyLifetime {
		lifetime = minKeyLifetime
	}
	if email == "" {
		email = "polyctl"
	}
	return k, windowsKeyEntry{
		UserName: user,
		Modulus:  base64.StdEncoding.EncodeToString(k.N.Bytes()),
		Exponent: base64.StdEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		Email:    email,
		ExpireOn: now.UTC().Add(lifetime).Format(time.RFC3339),
	}, nil
}

// windowsKeysValue returns the windows-keys value with entry added: the
// lines of existing are kept, except entries that expired before now
// (which the guest agent ignores anyway; dropping them keeps the value
// small). A line that is not an entry is kept as it is.
func windowsKeysValue(existing string, entry windowsKeyEntry, now time.Time) (string, error) {
	var lines []string
	for _, line := range strings.Split(existing, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e windowsKeyEntry
		if json.Unmarshal([]byte(line), &e) == nil && e.ExpireOn != "" {
			if t, err := time.Parse(time.RFC3339, e.ExpireOn); err == nil && t.Before(now) {
				continue
			}
		}
		lines = append(lines, line)
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	return strings.Join(append(lines, string(b)), "\n"), nil
}

// decryptAgentPassword decrypts the encryptedPassword of an answer: base64,
// then RSA-OAEP with SHA-1. Errors never quote the ciphertext.
func decryptAgentPassword(k *rsa.PrivateKey, enc string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(enc), ""))
	if err != nil {
		return "", errors.New("the encrypted password the guest agent wrote is not base64")
	}
	plain, err := rsa.DecryptOAEP(sha1.New(), nil, k, ct, nil) //nolint:gosec // see the import
	if err != nil {
		return "", errors.New("the password the guest agent wrote does not decrypt with the key of the request")
	}
	return string(plain), nil
}

// matchAnswer looks through complete serial port lines for the answer to
// the request of modulus. It returns nil when there is none yet.
func matchAnswer(text, modulus string) *agentAnswer {
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var a agentAnswer
		if json.Unmarshal([]byte(line), &a) == nil && a.Modulus == modulus {
			return &a
		}
	}
	return nil
}

// instanceWindows reports a Windows instance: its boot disk carries a
// license of the windows-cloud project or the WINDOWS guest OS feature.
func instanceWindows(in *compute.Instance) bool {
	for _, d := range in.Disks {
		if d == nil || !d.Boot {
			continue
		}
		for _, l := range d.Licenses {
			if strings.Contains(l, "projects/"+osImageProjects["windows"]+"/") {
				return true
			}
		}
		for _, f := range d.GuestOsFeatures {
			if f != nil && strings.EqualFold(f.Type, "WINDOWS") {
				return true
			}
		}
	}
	return false
}

// serialPortOutput reads serial port port of an instance from byte start.
func (c *client) serialPortOutput(ctx context.Context, zone, name string, port, start int64) (*compute.SerialPortOutput, error) {
	out, err := c.compute.Instances.GetSerialPortOutput(c.project, zone, name).Port(port).Start(start).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// setWindowsKey adds entry to the windows-keys metadata of an instance,
// keeping its other metadata (sent back whole with the fingerprint as
// read; a stale fingerprint is read again and retried once), and waits
// for the operation.
func (c *client) setWindowsKey(ctx context.Context, zone, name string, entry windowsKeyEntry, now time.Time) error {
	for attempt := 0; ; attempt++ {
		in, err := c.getInstance(ctx, zone, name)
		if err != nil {
			return err
		}
		md := &compute.Metadata{}
		if in.Metadata != nil {
			md.Fingerprint = in.Metadata.Fingerprint
			md.Items = append(md.Items, in.Metadata.Items...)
		}
		var item *compute.MetadataItems
		for _, it := range md.Items {
			if it != nil && it.Key == windowsKeysKey {
				item = it
			}
		}
		existing := ""
		if item != nil && item.Value != nil {
			existing = *item.Value
		}
		v, err := windowsKeysValue(existing, entry, now)
		if err != nil {
			return err
		}
		if item == nil {
			md.Items = append(md.Items, &compute.MetadataItems{Key: windowsKeysKey, Value: &v})
		} else {
			// A copy: the item belongs to the instance as read.
			for i, it := range md.Items {
				if it == item {
					md.Items[i] = &compute.MetadataItems{Key: windowsKeysKey, Value: &v}
				}
			}
		}
		op, err := c.compute.Instances.SetMetadata(c.project, zone, name, md).Context(ctx).Do()
		if err != nil {
			if attempt == 0 && isFingerprintMismatch(err) {
				continue
			}
			return computeErr(err)
		}
		return c.waitZoneOp(ctx, zone, op)
	}
}

// errNoAnswer is wrapped by the error of a password request the guest agent
// did not answer in time.
var errNoAnswer = errors.New("the guest agent did not answer")

// resetWindowsPassword asks the guest agent of a running Windows instance
// to create (when missing) or update user with a new password, the way
// gcloud compute reset-windows-password does: an RSA key whose public half
// goes into the windows-keys metadata, and the encrypted password read
// back from serial port 4 (polled every passwordPollInterval, from the
// position the port had before the request). limit bounds the wait for
// the answer; running out of time is a WaitTimeoutError that wraps
// errNoAnswer. progress receives status lines for -v.
func (c *client) resetWindowsPassword(ctx context.Context, zone, name, user string, limit time.Duration, progress func(string)) (string, error) {
	now := instanceClock.Now()
	key, entry, err := newWindowsKey(user, c.email, now, limit)
	if err != nil {
		return "", err
	}
	// The position the answer will be written after.
	first, err := c.serialPortOutput(ctx, zone, name, windowsAgentPort, 0)
	if err != nil {
		return "", fmt.Errorf("cannot read serial port %d of instance %s, where the guest agent answers: %w", windowsAgentPort, name, err)
	}
	start := first.Next
	if err := c.setWindowsKey(ctx, zone, name, entry, now); err != nil {
		return "", fmt.Errorf("cannot write the password request into the %s metadata of instance %s: %w", windowsKeysKey, name, err)
	}
	progress(fmt.Sprintf("password request for user %s written into the %s metadata of instance %s; polling serial port %d", user, windowsKeysKey, name, windowsAgentPort))
	var pending string
	var answer *agentAnswer
	err = platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + name, Want: "answered by the guest agent", Timeout: limit, Interval: passwordPollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		out, err := c.serialPortOutput(ctx, zone, name, windowsAgentPort, start)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if out.Start > start {
			// The buffer wrapped: what was between is gone.
			pending = ""
		}
		pending += out.Contents
		if out.Next > 0 {
			start = out.Next
		}
		// Only complete lines; the rest waits for the next read.
		complete := pending
		if i := strings.LastIndexByte(pending, '\n'); i >= 0 {
			complete, pending = pending[:i+1], pending[i+1:]
		} else {
			complete = ""
		}
		if a := matchAnswer(complete, entry.Modulus); a != nil {
			answer = a
			return platform.WaitDone, "answered", nil
		}
		return platform.KeepWaiting, "no answer yet", nil
	})
	if err != nil {
		var te *platform.WaitTimeoutError
		if errors.As(err, &te) {
			return "", fmt.Errorf("%w within %s: %w", errNoAnswer, limit, err)
		}
		return "", err
	}
	if answer.ErrorMessage != "" {
		return "", fmt.Errorf("the guest agent of instance %s could not set the password of user %s: %s", name, user, answer.ErrorMessage)
	}
	if answer.EncryptedPassword == "" {
		return "", fmt.Errorf("the guest agent of instance %s answered without a password for user %s", name, user)
	}
	return decryptAgentPassword(key, answer.EncryptedPassword)
}

// ------------------------------------------------------------ create

// windowsLogin is the login of a Windows instance create makes: the step
// built by step sets the password once the instance runs, finish shows the
// result once the plan has run.
type windowsLogin struct {
	rt      *app.Runtime
	c       *client
	profile string
	zone    string
	name    string
	user    string
	timeout time.Duration
	// wait is false with --no-wait: nothing is set then.
	wait bool

	// created reports that the instance exists (the insert went through).
	created  bool
	id       string
	password string
	// stored reports that the credentials as they are now are stored.
	stored bool
}

func (w *windowsLogin) credentials() secrets.Credentials {
	return secrets.Credentials{Ref: secrets.Ref{Platform: platform.GCP, Profile: w.profile, Location: w.zone, InstanceID: w.id},
		Name: w.name, User: w.user, Password: w.password}
}

// resetLine is the command that sets a new password.
func (w *windowsLogin) resetLine() string {
	ref := w.id
	if ref == "" {
		ref = w.name
	}
	line := app.PasswordCommandLine(computeInstanceTree, ref) + " --reset"
	if w.user != defaultWindowsUser {
		line += " --user " + w.user
	}
	return line
}

// step is the plan step that sets the password of the running instance;
// id is the instance id, known once the instance runs. It never fails:
// the instance exists, and a password that could not be set is a note.
func (w *windowsLogin) step(id func() string) platform.Step {
	desc := "user " + w.user + ": password set by the guest agent (" + windowsKeysKey + " metadata), stored encrypted"
	return platform.Step{Resource: "instance/" + w.name + "/windows-login", Action: platform.Created, Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			w.id = id()
			w.rt.Infof("setting the Windows password of user %s on instance %s (the guest agent answers once Windows has started; up to %s)...", w.user, w.name, w.timeout)
			pw, err := w.c.resetWindowsPassword(ctx, w.zone, w.name, w.user, w.timeout, func(s string) { w.rt.Verbosef("%s", s) })
			switch {
			case errors.Is(err, errNoAnswer):
				w.rt.Infof("note: the guest agent of instance %s did not answer within %s (Windows may still be starting)", w.name, w.timeout)
				return platform.Change{Detail: "user " + w.user + ": password not set yet"}, nil
			case errors.Is(err, context.Canceled):
				return platform.Change{}, err
			case err != nil:
				w.rt.Infof("warning: the Windows password of instance %s was not set: %v", w.name, err)
				return platform.Change{Detail: "user " + w.user + ": password not set"}, nil
			}
			w.password = pw
			w.put(ctx)
			if !w.stored {
				// finish tries again, and says what became of it.
				return platform.Change{Detail: "user " + w.user + ": password set, not stored yet"}, nil
			}
			return platform.Change{Detail: "user " + w.user + ": password set, stored encrypted"}, nil
		}}
}

func (w *windowsLogin) put(ctx context.Context) {
	st, err := w.rt.Secrets()
	if err == nil {
		err = st.Put(ctx, w.credentials())
	}
	if err != nil {
		w.rt.Verbosef("store the Windows login of %s: %v", w.id, err)
	}
	w.stored = err == nil
}

// finish shows the login once the plan has run, whether or not a later
// step failed. Nothing happens when no instance was created (a dry run, an
// earlier failure). A password that was not set is a note naming the
// command that sets one.
func (w *windowsLogin) finish(ctx context.Context) error {
	if w == nil || !w.created || w.rt.DryRun() {
		return nil
	}
	if w.password == "" {
		why := "was not set"
		if !w.wait {
			why = "was not set (--no-wait)"
		}
		w.rt.Infof("note: the Windows password of user %s on instance %s %s: `%s` sets one once the instance runs", w.user, w.name, why, w.resetLine())
		return nil
	}
	if w.stored {
		w.rt.ShowCredentials(w.credentials(), computeInstanceTree)
		return nil
	}
	return w.rt.SaveCredentials(ctx, w.credentials(), computeInstanceTree, passwordResetHint)
}

// windowsCreateFlags refuses the Windows login flags on a Linux create:
// Linux instances log in with an SSH key only, and polyctl never sets a
// password on them.
func windowsCreateFlags(cmd *cobra.Command, what string) error {
	for _, f := range []string{"windows-user", "password-timeout"} {
		if cmd.Flags().Changed(f) {
			return app.UsageErrf("--%s applies to Windows instances only: %s, and Linux instances log in with an SSH key only (polyctl never sets a password on them)", f, what)
		}
	}
	return nil
}

// ------------------------------------------------------------ password

// passwordResetHint is the advice for an instance whose password polyctl
// does not hold (nothing stored, or credentials a create could not store):
// password --reset.
func passwordResetHint(ref string) string {
	return "`" + app.PasswordCommandLine(computeInstanceTree, ref) + " --reset` sets a new password through the guest agent of a running Windows instance (asks first)"
}

func computePasswordCmd(rt *app.Runtime) *cobra.Command {
	var reset bool
	var user string
	var limit time.Duration
	cmd := app.InstancePasswordCommand(rt, app.PasswordCommand{
		Platform:     platform.GCP,
		Tree:         computeInstanceTree,
		LocationFlag: "zone",
		Reset:        true,
		Detail: `Compute Engine: Windows images have no password of their own. create
--os windows asks the guest agent of the instance to create the user
(--windows-user, polyctl-admin by default; an administrator) and set a new
password, the way gcloud compute reset-windows-password does: polyctl
generates an RSA key, writes its public half into the instance's
windows-keys metadata, reads the password the agent encrypted with it
from serial port 4 and decrypts it. The key lives only in memory.

--reset does that again for a running Windows instance (its stored user,
else polyctl-admin, or --user) and stores and shows the new password; the
old password stops working, so it asks for a confirmation first (default
no; --yes skips it, and the non-interactive flow needs --yes, exit code 2;
a declined confirmation is exit code 0). It also works for a Windows
instance polyctl did not create. --password-timeout (10m) bounds the wait
for the agent; running out of time is exit code 1. A Linux instance is
exit code 2: Linux instances log in with an SSH key only, and polyctl
never sets a password on them. A stopped instance is exit code 1. With
--dry-run nothing is generated, written or asked. Without --reset, an
instance with nothing stored is exit code 4 with a hint to use --reset.
Deleting the instance with polyctl removes its stored credentials.`,
		Hint: passwordResetHint,
	})
	cmd.Short = "Show (or with --reset set) the Windows user name and password of an instance"
	cmd.Example += "\n  polyctl " + computeInstanceTree + " password win-1 --reset\n" +
		"  polyctl " + computeInstanceTree + " password win-1 --reset --user ops --yes -o json"
	show := cmd.RunE
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !reset {
			for _, f := range []string{"user", "password-timeout"} {
				if cmd.Flags().Changed(f) {
					return app.UsageErrf("--%s needs --reset", f)
				}
			}
			return show(cmd, args)
		}
		zone, _ := cmd.Flags().GetString("zone")
		return runPasswordReset(cmd.Context(), rt, args[0], zone, user, limit)
	}
	cmd.Flags().BoolVar(&reset, "reset", false, "set a new password through the guest agent of the running instance, store and show it (asks first)")
	cmd.Flags().StringVar(&user, "user", "", "with --reset: the Windows user (created when missing; default: the stored user, else "+defaultWindowsUser+")")
	cmd.Flags().DurationVar(&limit, "password-timeout", defaultPasswordTimeout, "with --reset: upper bound of the wait for the guest agent")
	return cmd
}

// runPasswordReset is `password <ref> --reset`.
func runPasswordReset(ctx context.Context, rt *app.Runtime, ref, zone, user string, limit time.Duration) error {
	if user != "" {
		if err := checkWindowsUser(user, "--user"); err != nil {
			return err
		}
	}
	if limit <= 0 {
		return app.UsageErrf("--password-timeout must be a positive duration, got %s", limit)
	}
	if rt.Flags.Offline {
		return app.ErrOffline
	}
	if !rt.DryRun() {
		if err := rt.CanConfirm("reset the Windows password of instance " + ref); err != nil {
			return err
		}
	}
	l, err := resolveInstance(ctx, rt, ref, zone, false)
	if err != nil {
		return err
	}
	if !instanceWindows(l.inst) {
		return app.UsageErrf("instance %s is not a Windows instance: Linux instances log in with an SSH key only, and polyctl never sets a password on them", l.label())
	}
	id := strconv.FormatUint(l.inst.Id, 10)
	ref2 := secrets.Ref{Platform: platform.GCP, Profile: l.profile, Location: l.zone, InstanceID: id}
	if user == "" {
		// The stored user: a plain column, readable even when the sealed
		// password no longer decrypts (a lost data key), so that the reset
		// does not create another administrator instead.
		user = defaultWindowsUser
		db, err := rt.DB()
		var row *inventory.SecretRow
		if err == nil {
			row, err = db.GetSecret(ctx, inventory.SecretKey{Platform: ref2.Platform, Profile: ref2.Profile, Location: ref2.Location, InstanceID: ref2.InstanceID})
		}
		switch {
		case err != nil:
			rt.Verbosef("read the stored login of %s: %v", id, err)
		case row != nil && row.User != "":
			user = row.User
		}
	}
	if l.inst.Status != statusRunning {
		return fmt.Errorf("instance %s is %s: the guest agent sets a password only while the instance runs; start it first (`polyctl gcp compute instance start %s`)", l.label(), l.inst.Status, l.name())
	}
	rt.Infof("instance %s", l.label())
	rt.Infof("  status  %s", l.inst.Status)
	rt.Infof("  user    %s (created as an administrator when missing)", user)
	change := platform.Change{Resource: l.resource() + "/windows-login", Action: platform.Updated, ID: id,
		Detail: "user " + user + ": new password set by the guest agent (" + windowsKeysKey + " metadata)"}
	if done, err := rt.WouldWrite(l.target(), change); done || err != nil {
		return err
	}
	rt.Infof("The current password of user %s stops working.", user)
	ok, err := rt.Confirm(ctx, fmt.Sprintf("Reset the Windows password of user %s on instance %s?", user, l.label()), false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: cancelled; the password of instance %s was not changed", platform.ErrNothingToDo, l.name())
	}
	if err := rt.PrepareSecrets(); err != nil {
		return fmt.Errorf("the new password could not be stored, nothing was changed: %w", err)
	}
	rt.Infof("setting the Windows password of user %s on instance %s (up to %s)...", user, l.name(), limit)
	pw, err := l.c.resetWindowsPassword(ctx, l.zone, l.name(), user, limit, func(s string) { rt.Verbosef("%s", s) })
	if err != nil {
		if errors.Is(err, errNoAnswer) {
			return fmt.Errorf("instance %s: %w (is the instance a Compute Engine Windows image with its guest agent running?); the request expires on its own, run the command again to retry", l.name(), err)
		}
		return fmt.Errorf("instance %s: %w", l.name(), err)
	}
	cred := secrets.Credentials{Ref: ref2, Name: l.name(), User: user, Password: pw, UpdatedAt: time.Now()}
	st, err := rt.Secrets()
	if err == nil {
		err = st.Put(ctx, cred)
	}
	if err != nil {
		rt.Infof("warning: the new password of instance %s could not be stored (%v): note it now, polyctl cannot show it again", l.name(), err)
	} else if got, gerr := st.Get(ctx, ref2); gerr == nil {
		cred = *got
	}
	return rt.RenderLogin(cred)
}
