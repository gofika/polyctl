package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/sshremote"
)

// `gcp compute instance ssh-key list|add|remove` manage the ssh-keys
// metadata of an instance through the Compute Engine API (no SSH login):
// lines "user:key". Project-wide keys are listed read-only. OS Login makes
// the guest ignore the metadata keys, so add and remove are refused then.

const (
	sourceInstanceMetadata = "instance metadata"
	sourceProjectMetadata  = "project metadata"
)

func computeSSHKeyCmd(rt *app.Runtime) *cobra.Command {
	var zone string
	return app.SSHKeyCommands(rt, app.SSHKeyCommand{
		Platform: platform.GCP,
		Tree:     computeInstanceTree,
		Metadata: true,
		Detail: `Compute Engine: add and remove edit only the instance's own ssh-keys
metadata, keeping every other metadata item and every other line as it is
(sent back with the metadata fingerprint; a fingerprint that changed
meanwhile is read again and retried once). list also shows the
project-wide keys (project metadata, read-only: they reach every instance
of the project), marked ignored when the instance blocks them
(block-project-ssh-keys=TRUE); a key whose google-ssh expireOn has passed
is listed ignored, and add puts it in again without an expiry. When OS
Login is enabled (enable-oslogin=TRUE in the instance metadata, else in
the project metadata), the guest ignores the ssh-keys metadata: list says
so, and add and remove are refused with exit code 7 (OS Login keys belong
to the Google account: gcloud compute os-login ssh-keys add). The user of
a key is --user, else the user of the user@host that ends the key's
comment; on a terminal it is asked.`,
		Flags: func(cmd *cobra.Command) {
			cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used, also one not in the inventory yet")
		},
		Resolve: func(ctx context.Context, arg string) (*app.SSHKeyInstance, error) {
			if arg == "" {
				ref, err := pickInstanceRef(ctx, rt, "<name|id>", zone, "Linux instance", false, func(in Instance) bool { return !in.Windows })
				if err != nil {
					return nil, err
				}
				arg = ref
			}
			l, err := resolveInstance(ctx, rt, arg, zone, true)
			if err != nil {
				return nil, err
			}
			return &app.SSHKeyInstance{Name: l.inst.Name, ID: strconv.FormatUint(l.inst.Id, 10), Target: l.target(),
				Windows: instanceWindows(l.inst), Metadata: &metadataKeyStore{rt: rt, l: l},
				Running: l.inst.Status == statusRunning, State: l.inst.Status}, nil
		},
		UserFromKey: func(k *platform.PublicKey) string { return commentUser(k.Comment) },
	})
}

// metadataKeyStore is the app.SSHKeyStore of a Compute Engine instance.
type metadataKeyStore struct {
	rt *app.Runtime
	l  *locatedInstance
}

// metadataLine is one parsed "user:key comment" line of an ssh-keys item.
type metadataLine struct {
	User    string
	Key     ssh.PublicKey
	Comment string
	// Expired marks a key whose google-ssh expireOn has passed: it stays in
	// the metadata but no longer logs in.
	Expired bool
}

// googleSSHExpired reports whether a key comment `google-ssh {...}` names
// an expireOn in the past. A comment that is not one, or a time that does
// not parse, is not expired.
func googleSSHExpired(comment string, now time.Time) bool {
	rest, ok := strings.CutPrefix(comment, "google-ssh ")
	if !ok {
		return false
	}
	var v struct {
		ExpireOn string `json:"expireOn"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(rest)), &v) != nil || v.ExpireOn == "" {
		return false
	}
	for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339} {
		if t, err := time.Parse(layout, v.ExpireOn); err == nil {
			return now.After(t)
		}
	}
	return false
}

// parseMetadataLine parses a line of an ssh-keys (or legacy sshKeys) item;
// false for a blank line or one that holds no key.
func parseMetadataLine(line string) (metadataLine, bool) {
	user, rest, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || user == "" || strings.ContainsAny(user, " \t") {
		return metadataLine{}, false
	}
	key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(rest))
	if err != nil {
		return metadataLine{}, false
	}
	return metadataLine{User: user, Key: key, Comment: comment, Expired: googleSSHExpired(comment, time.Now())}, true
}

// metadataLines returns the keys of the ssh-keys and sshKeys items.
func metadataLines(md *compute.Metadata) []metadataLine {
	var out []metadataLine
	for _, item := range []string{sshKeysItem, legacySSHKeys} {
		v, ok := metadataValue(md, item)
		if !ok {
			continue
		}
		for _, line := range strings.Split(v, "\n") {
			if l, ok := parseMetadataLine(line); ok {
				out = append(out, l)
			}
		}
	}
	return out
}

// metadataBool reads a boolean metadata item as the guest agent does
// (TRUE, true, 1, ...); set is false when the item is absent.
func metadataBool(md *compute.Metadata, key string) (value, set bool) {
	v, ok := metadataValue(md, key)
	if !ok {
		return false, false
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && b, true
}

// effectiveBool is a setting the instance metadata decides when it sets
// it, else the project metadata; where names the one that decided.
func effectiveBool(instance, project *compute.Metadata, key string) (value bool, where string) {
	if v, ok := metadataBool(instance, key); ok {
		return v, "instance"
	}
	if v, ok := metadataBool(project, key); ok {
		return v, "project"
	}
	return false, ""
}

func (s *metadataKeyStore) List(ctx context.Context) (*app.SSHKeyListing, error) {
	c, name := s.l.c, s.l.inst.Name
	in, err := c.getInstance(ctx, s.l.zone, name)
	if err != nil {
		return nil, err
	}
	s.l.inst = in
	out := &app.SSHKeyListing{}
	pmd, err := c.projectMetadata(ctx)
	if err != nil {
		if !errors.Is(err, platform.ErrForbidden) {
			return nil, err
		}
		pmd = nil
		out.Notes = append(out.Notes, fmt.Sprintf("note: the project metadata cannot be read (%v): project-wide keys and a project-wide OS Login setting are not shown", err))
	}
	osLogin, osWhere := effectiveBool(in.Metadata, pmd, osLoginItem)
	blocked, blockWhere := effectiveBool(in.Metadata, pmd, blockProjectKeys)
	expired := 0
	for _, k := range metadataLines(in.Metadata) {
		if k.Expired {
			expired++
		}
		out.Keys = append(out.Keys, app.SSHKeyEntry{User: k.User, Key: k.Key, Comment: k.Comment, Source: sourceInstanceMetadata, Ignored: osLogin || k.Expired})
	}
	for _, k := range metadataLines(pmd) {
		if k.Expired {
			expired++
		}
		out.Keys = append(out.Keys, app.SSHKeyEntry{User: k.User, Key: k.Key, Comment: k.Comment, Source: sourceProjectMetadata,
			ReadOnly: true, Ignored: osLogin || blocked || k.Expired})
	}
	if expired > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf("note: %d listed key(s) have expired (google-ssh expireOn in the past): they no longer log in, and add puts such a key in again without an expiry", expired))
	}
	if blocked {
		out.Notes = append(out.Notes, fmt.Sprintf("note: instance %s blocks project-wide SSH keys (block-project-ssh-keys=TRUE in the %s metadata): the project metadata keys do not log in to it", name, blockWhere))
	}
	if osLogin {
		out.Notes = append(out.Notes, fmt.Sprintf("note: OS Login is enabled for instance %s (enable-oslogin=TRUE in the %s metadata): it ignores the ssh-keys metadata and logs in with the keys of the Google account (gcloud compute os-login ssh-keys add)", name, osWhere))
		out.ReadOnly = fmt.Errorf("%w: OS Login is enabled for instance %s (enable-oslogin=TRUE in the %s metadata), so it ignores the ssh-keys metadata; add the key to the Google account instead with `gcloud compute os-login ssh-keys add --key-file <path>`, or set enable-oslogin=FALSE in the instance metadata to use metadata keys",
			platform.ErrNotSupported, name, osWhere)
	}
	return out, nil
}

func (s *metadataKeyStore) Add(ctx context.Context, user string, key *platform.PublicKey) (bool, error) {
	if err := checkSSHUser(user, "--user"); err != nil {
		return false, err
	}
	line := user + ":" + sshremote.KeyLine(key.Key, key.Comment)
	added := false
	err := s.l.c.editInstanceMetadata(ctx, s.l.zone, s.l.inst.Name, func(md *compute.Metadata) bool {
		added = false
		for _, k := range metadataLines(md) {
			if k.User == user && !k.Expired && sshremote.SameKey(k.Key, key.Key) {
				return false
			}
		}
		v, _ := metadataValue(md, sshKeysItem)
		if v != "" && !strings.HasSuffix(v, "\n") {
			v += "\n"
		}
		setMetadataItem(md, sshKeysItem, v+line)
		added = true
		return true
	})
	return added, err
}

func (s *metadataKeyStore) Remove(ctx context.Context, user string, keys []ssh.PublicKey) (int, error) {
	removed := 0
	err := s.l.c.editInstanceMetadata(ctx, s.l.zone, s.l.inst.Name, func(md *compute.Metadata) bool {
		removed = 0
		for _, item := range []string{sshKeysItem, legacySSHKeys} {
			v, ok := metadataValue(md, item)
			if !ok {
				continue
			}
			var kept []string
			n := 0
			for _, line := range strings.Split(v, "\n") {
				if k, ok := parseMetadataLine(line); ok && k.User == user && anyKey(keys, k.Key) {
					n++
					continue
				}
				kept = append(kept, line)
			}
			if n == 0 {
				continue
			}
			removed += n
			if strings.TrimSpace(strings.Join(kept, "")) == "" {
				deleteMetadataItem(md, item)
			} else {
				setMetadataItem(md, item, strings.Join(kept, "\n"))
			}
		}
		return removed > 0
	})
	return removed, err
}

func anyKey(keys []ssh.PublicKey, k ssh.PublicKey) bool {
	for _, x := range keys {
		if sshremote.SameKey(x, k) {
			return true
		}
	}
	return false
}

// setMetadataItem sets key to value in md, replacing the item (a new one:
// the items belong to the instance as read) or appending it.
func setMetadataItem(md *compute.Metadata, key, value string) {
	for i, it := range md.Items {
		if it != nil && it.Key == key {
			md.Items[i] = &compute.MetadataItems{Key: key, Value: &value}
			return
		}
	}
	md.Items = append(md.Items, &compute.MetadataItems{Key: key, Value: &value})
}

func deleteMetadataItem(md *compute.Metadata, key string) {
	kept := md.Items[:0:0]
	for _, it := range md.Items {
		if it == nil || it.Key != key {
			kept = append(kept, it)
		}
	}
	md.Items = kept
}

// editInstanceMetadata reads the metadata of an instance, lets edit change
// a copy (true: write it), and writes it whole with the fingerprint as
// read, then waits for the operation. A fingerprint that changed meanwhile
// is read again and the edit retried once.
func (c *client) editInstanceMetadata(ctx context.Context, zone, name string, edit func(md *compute.Metadata) bool) error {
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
		if !edit(md) {
			return nil
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
