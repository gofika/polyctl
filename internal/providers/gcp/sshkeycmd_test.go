package gcp

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
)

// keyFP is the SHA256 fingerprint of a public key line.
func keyFP(t *testing.T, line string) string {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(k)
}

// keyInstance adds web-1 with instance keys of alice (ssh-keys, with an
// expiring line of carol) and bob (legacy sshKeys), and another metadata
// item; it returns the key lines of alice and bob.
func keyInstance(t *testing.T, h *gcpHarness) (alice, bob string) {
	t.Helper()
	alice, bob = testPublicKey(t, "alice@laptop"), testPublicKey(t, "bob@desk")
	carol := testPublicKey(t, `google-ssh {"userName":"carol@example.com","expireOn":"2030-01-01T00:00:00+0000"}`)
	in := h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.2", "203.0.113.2")
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	in.Metadata = &compute.Metadata{Fingerprint: "md-0", Items: []*compute.MetadataItems{
		{Key: "startup-script", Value: strPtr("#!/bin/sh\necho hi\n")},
		{Key: sshKeysItem, Value: strPtr("alice:" + alice + "\r\n# a comment line\ncarol:" + carol)},
		{Key: legacySSHKeys, Value: strPtr("bob:" + bob)},
	}}
	return alice, bob
}

func metadataItem(t *testing.T, h *gcpHarness, key string) (string, bool) {
	t.Helper()
	in := h.gce.instance("us-central1-a", "web-1")
	return metadataValue(in.Metadata, key)
}

func sshKeyRows(t *testing.T, h *gcpHarness) []app.SSHKeyRow {
	t.Helper()
	var rows []app.SSHKeyRow
	h.jsonOut(&rows)
	return rows
}

func rowSummary(rows []app.SSHKeyRow) []string {
	var out []string
	for _, r := range rows {
		s := r.User + " " + r.Source
		if r.ReadOnly {
			s += " read-only"
		}
		if r.Ignored {
			s += " ignored"
		}
		out = append(out, s)
	}
	return out
}

// list shows the instance keys (ssh-keys and the legacy sshKeys) and the
// project keys, read-only; --user narrows them.
func TestSSHKeyListGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	alice, _ := keyInstance(t, h)
	if err := h.run("compute", "instance", "ssh-key", "list", "web-1"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	rows := sshKeyRows(t, h)
	if got := rowSummary(rows); !slices.Equal(got, []string{"alice instance metadata", "bob instance metadata", "carol instance metadata", "ops project metadata read-only"}) {
		t.Fatalf("rows = %v", got)
	}
	if rows[0].Fingerprint != keyFP(t, alice) || rows[0].Type != "ed25519" || rows[0].Comment != "alice@laptop" {
		t.Errorf("alice = %+v", rows[0])
	}
	if len(h.gce.writes()) != 0 {
		t.Errorf("list wrote %v", h.gce.writes())
	}
	if err := h.run("compute", "instance", "ssh-key", "list", "web-1", "--user", "bob"); err != nil {
		t.Fatal(err)
	}
	if got := rowSummary(sshKeyRows(t, h)); !slices.Equal(got, []string{"bob instance metadata"}) {
		t.Errorf("--user bob = %v", got)
	}
}

// add appends a user:key line to the instance's ssh-keys, keeping every
// other item and line, with the fingerprint (retried once when stale); a key
// already there (instance or project) is unchanged without a write.
func TestSSHKeyAddGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	alice, bob := keyInstance(t, h)
	before, _ := metadataItem(t, h, sshKeysItem)
	dave := testPublicKey(t, "dave@example.com")
	add := []string{"compute", "instance", "ssh-key", "add", "web-1"}

	// No user: the comment tells none, and the non-interactive flow
	// needs --user before anything is read.
	if err := h.run(append(add, "--ssh-key", testPublicKey(t, "no user here"))...); exitClass(err) != "usage" || len(h.gce.calls) != 0 {
		t.Fatalf("no user = %v (%d calls)", err, len(h.gce.calls))
	}
	// A dry run reads and reports, and writes nothing.
	h.rt.Flags.DryRun = true
	if err := h.run(append(add, "--ssh-key", dave)...); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = false
	if r := rows(h.report()); len(r) != 1 || !strings.HasPrefix(r[0], "key/dave/"+keyFP(t, dave)+" would_create") || len(h.gce.writes()) != 0 {
		t.Fatalf("dry run = %v, writes %v", r, h.gce.writes())
	}

	h.gce.agent.staleMetadata = 1
	if err := h.run(append(add, "--ssh-key", dave)...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if r := rows(h.report()); len(r) != 1 || !strings.HasPrefix(r[0], "key/dave/"+keyFP(t, dave)+" created") {
		t.Fatalf("rows = %v", r)
	}
	v, _ := metadataItem(t, h, sshKeysItem)
	if v != before+"\ndave:"+dave {
		t.Errorf("ssh-keys = %q", v)
	}
	if s, _ := metadataItem(t, h, "startup-script"); s != "#!/bin/sh\necho hi\n" {
		t.Errorf("startup-script = %q", s)
	}
	if l, _ := metadataItem(t, h, legacySSHKeys); l != "bob:"+bob {
		t.Errorf("sshKeys = %q", l)
	}

	// Present: in ssh-keys, in the legacy item, in the project metadata.
	for _, c := range []struct{ args []string }{
		{[]string{"--ssh-key", dave}},
		{[]string{"--ssh-key", alice, "--user", "alice"}},
		{[]string{"--ssh-key", bob}},
		{[]string{"--ssh-key", projectKeyLine(t, h), "--user", "ops"}},
	} {
		if err := h.run(append(add, c.args...)...); err != nil {
			t.Fatal(err)
		}
		if r := rows(h.report()); len(r) != 1 || !strings.Contains(r[0], " unchanged already present") || len(h.gce.writes()) != 0 {
			t.Errorf("%v: rows = %v, writes %v", c.args, r, h.gce.writes())
		}
	}
	// The same key for another user is another entry.
	if err := h.run(append(add, "--ssh-key", alice, "--user", "deploy")...); err != nil {
		t.Fatal(err)
	}
	if v, _ := metadataItem(t, h, sshKeysItem); !strings.HasSuffix(v, "\ndeploy:"+alice) {
		t.Errorf("ssh-keys = %q", v)
	}
}

// An instance without ssh-keys gets the item.
func TestSSHKeyAddGCPNoItem(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.2", "203.0.113.2")
	k := testPublicKey(t, "erin@example.com")
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", k); err != nil {
		t.Fatal(err)
	}
	if v, ok := metadataItem(t, h, sshKeysItem); !ok || v != "erin:"+k {
		t.Errorf("ssh-keys = %q, %v", v, ok)
	}
}

func projectKeyLine(t *testing.T, h *gcpHarness) string {
	t.Helper()
	v, _ := metadataValue(h.gce.projectMeta["proj"], sshKeysItem)
	return strings.TrimPrefix(v, "ops:")
}

// remove asks first (--yes in the non-interactive flow), deletes the lines
// of the user holding the key from ssh-keys and sshKeys (an emptied item
// goes), keeps the others byte for byte; a key not there, or one only in the
// project metadata, is unchanged.
func TestSSHKeyRemoveGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	alice, bob := keyInstance(t, h)
	remove := []string{"compute", "instance", "ssh-key", "remove", "web-1"}

	if err := h.run(append(remove, "--fingerprint", keyFP(t, alice))...); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--yes") || len(h.gce.calls) != 0 {
		t.Fatalf("without --yes = %v (%d calls)", err, len(h.gce.calls))
	}
	h.rt.Flags.DryRun = true
	if err := h.run(append(remove, "--fingerprint", keyFP(t, alice))...); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = false
	if r := rows(h.report()); len(r) != 1 || !strings.HasPrefix(r[0], "key/alice/"+keyFP(t, alice)+" would_delete") || len(h.gce.writes()) != 0 {
		t.Fatalf("dry run = %v, writes %v", r, h.gce.writes())
	}

	h.gce.agent.staleMetadata = 1
	if err := h.run(append(remove, "--fingerprint", keyFP(t, alice), "--ssh-key", bob, "--yes")...); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	r := rows(h.report())
	slices.Sort(r)
	if len(r) != 2 || !strings.HasPrefix(r[0], "key/alice/"+keyFP(t, alice)+" deleted") || !strings.HasPrefix(r[1], "key/bob/"+keyFP(t, bob)+" deleted") {
		t.Fatalf("rows = %v", r)
	}
	v, _ := metadataItem(t, h, sshKeysItem)
	if strings.Contains(v, alice) || !strings.HasPrefix(v, "# a comment line\ncarol:") {
		t.Errorf("ssh-keys = %q", v)
	}
	if _, ok := metadataItem(t, h, legacySSHKeys); ok {
		t.Error("the emptied sshKeys item is kept")
	}
	if s, _ := metadataItem(t, h, "startup-script"); s != "#!/bin/sh\necho hi\n" {
		t.Errorf("startup-script = %q", s)
	}

	// Not there any more, and a project key: unchanged, nothing written.
	if err := h.run(append(remove, "--fingerprint", keyFP(t, alice), "--fingerprint", keyFP(t, projectKeyLine(t, h)), "--yes")...); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); len(r) != 2 || !strings.Contains(r[0], " unchanged not present") || !strings.Contains(r[1], " unchanged not present") || len(h.gce.writes()) != 0 {
		t.Errorf("absent = %v, writes %v", r, h.gce.writes())
	}
}

// OS Login on (instance first, then project): list says so, add and remove
// are exit code 7 before any write; an instance that turns it off for
// itself takes metadata keys.
func TestSSHKeyOSLoginGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	alice, _ := keyInstance(t, h)
	h.gce.mu.Lock()
	h.gce.projectMeta["proj"].Items = append(h.gce.projectMeta["proj"].Items, &compute.MetadataItems{Key: osLoginItem, Value: strPtr("TRUE")})
	h.gce.mu.Unlock()

	if err := h.run("compute", "instance", "ssh-key", "list", "web-1"); err != nil {
		t.Fatal(err)
	}
	for _, r := range sshKeyRows(t, h) {
		if !r.Ignored {
			t.Errorf("not ignored under OS Login: %+v", r)
		}
	}
	if !strings.Contains(h.stderr.String(), "OS Login is enabled") || !strings.Contains(h.stderr.String(), "project metadata") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", testPublicKey(t, "x@y")); exitClass(err) != "unsupported" || !strings.Contains(err.Error(), "gcloud compute os-login ssh-keys add") || len(h.gce.writes()) != 0 {
		t.Fatalf("add = %v, writes %v", err, h.gce.writes())
	}
	if err := h.run("compute", "instance", "ssh-key", "remove", "web-1", "--fingerprint", keyFP(t, alice), "--yes"); exitClass(err) != "unsupported" || len(h.gce.writes()) != 0 {
		t.Fatalf("remove = %v, writes %v", err, h.gce.writes())
	}

	in := h.gce.instance("us-central1-a", "web-1")
	h.gce.mu.Lock()
	h.gce.instances["proj/us-central1-a/web-1"].Metadata.Items = append(in.Metadata.Items, &compute.MetadataItems{Key: osLoginItem, Value: strPtr("false")})
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", testPublicKey(t, "x@y")); err != nil {
		t.Fatalf("instance OS Login off: %v", err)
	}
}

// An instance that blocks project keys lists them as ignored, and add puts
// a project key into the instance metadata.
func TestSSHKeyBlockedProjectKeysGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	keyInstance(t, h)
	in := h.gce.instance("us-central1-a", "web-1")
	h.gce.mu.Lock()
	h.gce.instances["proj/us-central1-a/web-1"].Metadata.Items = append(in.Metadata.Items, &compute.MetadataItems{Key: blockProjectKeys, Value: strPtr("TRUE")})
	h.gce.mu.Unlock()
	if err := h.run("compute", "instance", "ssh-key", "list", "web-1"); err != nil {
		t.Fatal(err)
	}
	if got := rowSummary(sshKeyRows(t, h)); got[len(got)-1] != "ops project metadata read-only ignored" || !strings.Contains(h.stderr.String(), "block-project-ssh-keys=TRUE") {
		t.Errorf("rows = %v, stderr %s", got, h.stderr.String())
	}
	ops := projectKeyLine(t, h)
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", ops, "--user", "ops"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); len(r) != 1 || !strings.Contains(r[0], " created") {
		t.Errorf("rows = %v", r)
	}
	if v, _ := metadataItem(t, h, sshKeysItem); !strings.HasSuffix(v, "\nops:"+ops) {
		t.Errorf("ssh-keys = %q", v)
	}
}

// A Windows instance is exit code 7, naming the password command.
func TestSSHKeyWindowsGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	addWindows(h, "win-1")
	err := h.run("compute", "instance", "ssh-key", "list", "win-1")
	if exitClass(err) != "unsupported" || !strings.Contains(err.Error(), "gcp compute instance password") {
		t.Fatalf("windows = %v", err)
	}
}

// On a terminal: the instance is picked, the key to add is picked from
// ~/.ssh/*.pub and its user asked when the comment tells none; remove
// offers the instance keys (not the project ones) and confirms.
func TestSSHKeyInteractiveGCP(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	h, _ := interactiveGCP(t, nil)
	alice, _ := keyInstance(t, h)
	pub := testPublicKey(t, "laptop key")
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte(pub+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id := h.gce.instance("us-central1-a", "web-1").Id

	p := h.answer(strconv.FormatUint(id, 10), filepath.Join(home, ".ssh", "id_ed25519.pub"), "frank")
	if err := h.run("compute", "instance", "ssh-key", "add"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if v, _ := metadataItem(t, h, sshKeysItem); !strings.HasSuffix(v, "\nfrank:"+pub) {
		t.Errorf("ssh-keys = %q", v)
	}
	if len(p.Answers) != 0 {
		t.Errorf("unanswered %v", p.Answers)
	}

	// deploy holds alice's key too: picking alice's entry removes only it.
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", alice, "--user", "deploy"); err != nil {
		t.Fatal(err)
	}
	p = h.answer(strconv.FormatUint(id, 10), []string{"alice " + keyFP(t, alice)})
	if err := h.run("compute", "instance", "ssh-key", "remove", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	for _, a := range p.Asked {
		if a.Kind == "multi" {
			for _, o := range a.Options {
				if strings.HasPrefix(o.Value, "ops ") {
					t.Errorf("a project key is offered: %v", o)
				}
			}
		}
	}
	if v, _ := metadataItem(t, h, sshKeysItem); strings.Contains(v, "alice:"+alice) || !strings.Contains(v, "\ndeploy:"+alice) {
		t.Errorf("ssh-keys = %q", v)
	}

	// A declined confirmation (the terminal answers no) is cancelled:
	// nothing written.
	h.answer(strconv.FormatUint(id, 10), []string{"frank " + keyFP(t, pub)})
	if err := h.run("compute", "instance", "ssh-key", "remove"); exitClass(err) != "nothing" || len(h.gce.writes()) != 0 {
		t.Fatalf("declined = %v, writes %v", err, h.gce.writes())
	}
}

// A key whose google-ssh expireOn has passed no longer logs in: list marks
// it ignored with a note, and add puts it in again (a new line, the expired
// one kept).
func TestSSHKeyExpiredGCP(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	keyInstance(t, h)
	old := testPublicKey(t, `google-ssh {"userName":"gina@example.com","expireOn":"2001-01-01T00:00:00+0000"}`)
	in := h.gce.instance("us-central1-a", "web-1")
	h.gce.mu.Lock()
	v, _ := metadataValue(in.Metadata, sshKeysItem)
	setMetadataItem(h.gce.instances["proj/us-central1-a/web-1"].Metadata, sshKeysItem, v+"\ngina:"+old)
	h.gce.mu.Unlock()

	if err := h.run("compute", "instance", "ssh-key", "list", "web-1", "--user", "gina"); err != nil {
		t.Fatal(err)
	}
	if got := rowSummary(sshKeyRows(t, h)); !slices.Equal(got, []string{"gina instance metadata ignored"}) || !strings.Contains(h.stderr.String(), "expired") {
		t.Errorf("rows = %v, stderr %s", got, h.stderr.String())
	}
	blob := strings.Join(strings.Fields(old)[:2], " ")
	if err := h.run("compute", "instance", "ssh-key", "add", "web-1", "--ssh-key", blob, "--user", "gina"); err != nil {
		t.Fatal(err)
	}
	if r := rows(h.report()); len(r) != 1 || !strings.Contains(r[0], " created") {
		t.Errorf("rows = %v", r)
	}
	if v, _ := metadataItem(t, h, sshKeysItem); !strings.HasSuffix(v, "\ngina:"+old+"\ngina:"+blob) {
		t.Errorf("ssh-keys = %q", v)
	}
}

func TestGoogleSSHExpired(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	for c, want := range map[string]bool{
		`google-ssh {"userName":"a@b","expireOn":"2026-11-23T00:00:00+0000"}`: true,
		`google-ssh {"userName":"a@b","expireOn":"2026-11-23T00:00:00Z"}`:     true,
		`google-ssh {"userName":"a@b","expireOn":"2026-11-25T00:00:00+0000"}`: false,
		`google-ssh {"userName":"a@b","expireOn":"tomorrow"}`:                 false,
		`google-ssh not json`: false,
		`alice@laptop`:        false,
	} {
		if got := googleSSHExpired(c, now); got != want {
			t.Errorf("%s = %v", c, got)
		}
	}
}
