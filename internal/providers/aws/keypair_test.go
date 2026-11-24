package aws

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// fakeKeyPair is a key pair held by the fake EC2 API.
type fakeKeyPair struct {
	name, id, typ, fingerprint string
	publicKey                  string // authorized_keys line without comment
	hidePublicKey              bool   // DescribeKeyPairs never returns the key
	created                    time.Time
	tags                       []ec2types.Tag
	priv                       *rsa.PrivateKey // the private key of a key pair CreateKeyPair made
}

// fakeEC2 is the key pair part of the EC2 API, per region, with the
// behaviour observed on the real API: DescribeKeyPairs returns everything in
// one call (the public key only with IncludePublicKey), ImportKeyPair
// refuses a taken name with InvalidKeyPair.Duplicate whatever the key, and
// a key that is not RSA or ED25519 with InvalidKey.Format.
type fakeEC2 struct {
	mu       sync.Mutex
	region   string
	regions  map[string][]*fakeKeyPair
	calls    []string
	includes []bool
	imports  []*ec2.ImportKeyPairInput
	shared   *fakeEC2s
	nextID   int
}

func (f *fakeEC2) record(call string) {
	f.calls = append(f.calls, f.region+":"+call)
}

func (f *fakeEC2) DescribeKeyPairs(_ context.Context, in *ec2.DescribeKeyPairsInput, _ ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DescribeKeyPairs")
	include := awssdk.ToBool(in.IncludePublicKey)
	f.includes = append(f.includes, include)
	if err := f.shared.descErr; err != nil {
		return nil, err
	}
	out := &ec2.DescribeKeyPairsOutput{}
	for _, kp := range f.regions[f.region] {
		info := ec2types.KeyPairInfo{KeyName: awssdk.String(kp.name), KeyPairId: awssdk.String(kp.id), KeyType: ec2types.KeyType(kp.typ),
			KeyFingerprint: awssdk.String(kp.fingerprint), Tags: kp.tags}
		if !kp.created.IsZero() {
			c := kp.created
			info.CreateTime = &c
		}
		if include && !kp.hidePublicKey {
			info.PublicKey = awssdk.String(kp.publicKey)
		}
		out.KeyPairs = append(out.KeyPairs, info)
	}
	return out, nil
}

func (f *fakeEC2) ImportKeyPair(_ context.Context, in *ec2.ImportKeyPairInput, _ ...func(*ec2.Options)) (*ec2.ImportKeyPairOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("ImportKeyPair")
	f.imports = append(f.imports, in)
	name := awssdk.ToString(in.KeyName)
	for _, kp := range f.regions[f.region] {
		if kp.name == name {
			return nil, &fakeAPIError{"InvalidKeyPair.Duplicate", "The keypair already exists"}
		}
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey(in.PublicKeyMaterial)
	if err != nil || (k.Type() != ssh.KeyAlgoRSA && k.Type() != ssh.KeyAlgoED25519) {
		return nil, &fakeAPIError{"InvalidKey.Format", "Key is not in valid OpenSSH public key format"}
	}
	f.nextID++
	kp := newFakeKeyPair(name, k)
	kp.id = "key-0new" + string(rune('0'+f.nextID))
	for _, s := range in.TagSpecifications {
		kp.tags = append(kp.tags, s.Tags...)
	}
	f.regions[f.region] = append(f.regions[f.region], kp)
	return &ec2.ImportKeyPairOutput{KeyName: awssdk.String(name), KeyPairId: awssdk.String(kp.id), KeyFingerprint: awssdk.String(kp.fingerprint)}, nil
}

// CreateKeyPair makes an RSA key pair and returns its private key (PEM,
// PKCS #1), as AWS does with KeyType rsa and KeyFormat pem.
func (f *fakeEC2) CreateKeyPair(_ context.Context, in *ec2.CreateKeyPairInput, _ ...func(*ec2.Options)) (*ec2.CreateKeyPairOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("CreateKeyPair")
	f.shared.creates = append(f.shared.creates, in)
	if err := f.shared.inst.errs["CreateKeyPair"]; err != nil {
		return nil, err
	}
	name := awssdk.ToString(in.KeyName)
	for _, kp := range f.regions[f.region] {
		if kp.name == name {
			return nil, &fakeAPIError{"InvalidKeyPair.Duplicate", "The keypair already exists"}
		}
	}
	if in.KeyType != ec2types.KeyTypeRsa || in.KeyFormat != ec2types.KeyFormatPem {
		return nil, &fakeAPIError{"InvalidParameterValue", "unexpected key type or format"}
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.NewPublicKey(&rk.PublicKey)
	if err != nil {
		return nil, err
	}
	f.nextID++
	kp := newFakeKeyPair(name, pub)
	kp.id, kp.priv, kp.fingerprint = "key-0gen"+string(rune('0'+f.nextID)), rk, "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
	for _, s := range in.TagSpecifications {
		kp.tags = append(kp.tags, s.Tags...)
	}
	f.regions[f.region] = append(f.regions[f.region], kp)
	material := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}))
	return &ec2.CreateKeyPairOutput{KeyName: awssdk.String(name), KeyPairId: awssdk.String(kp.id), KeyFingerprint: awssdk.String(kp.fingerprint), KeyMaterial: awssdk.String(material)}, nil
}

// DeleteKeyPair removes a key pair by name; a missing one is no error, as
// on AWS.
func (f *fakeEC2) DeleteKeyPair(_ context.Context, in *ec2.DeleteKeyPairInput, _ ...func(*ec2.Options)) (*ec2.DeleteKeyPairOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.record("DeleteKeyPair")
	f.shared.deletedKeyPairs = append(f.shared.deletedKeyPairs, awssdk.ToString(in.KeyName))
	if err := f.shared.inst.errs["DeleteKeyPair"]; err != nil {
		return nil, err
	}
	out := &ec2.DeleteKeyPairOutput{Return: awssdk.Bool(true)}
	kept := f.regions[f.region][:0]
	for _, kp := range f.regions[f.region] {
		if kp.name == awssdk.ToString(in.KeyName) {
			out.KeyPairId = awssdk.String(kp.id)
			continue
		}
		kept = append(kept, kp)
	}
	f.regions[f.region] = kept
	return out, nil
}

// newFakeKeyPair is a key pair as AWS stores an imported key.
func newFakeKeyPair(name string, k ssh.PublicKey) *fakeKeyPair {
	pk := &platform.PublicKey{Key: k}
	kp := &fakeKeyPair{name: name, id: "key-0" + name, publicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))),
		created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	switch k.Type() {
	case ssh.KeyAlgoED25519:
		kp.typ, kp.fingerprint = "ed25519", pk.FingerprintAWSED25519()
	case ssh.KeyAlgoRSA:
		kp.typ, kp.fingerprint = "rsa", pk.FingerprintAWSRSA()
	}
	return kp
}

// fakeEC2s hands out one fakeEC2 view per region over shared state.
type fakeEC2s struct {
	mu      sync.Mutex
	regions map[string][]*fakeKeyPair
	views   []*fakeEC2
	descErr error // DescribeKeyPairs fails with it when set
	inst    fakeInstances
	sg      fakeSGs
	find    fakeFind
	elb     fakeELBs
	acm     fakeACMs
	rds     fakeRDSs
	ebs     fakeEBS
	// creates are the CreateKeyPair requests, deletedKeyPairs the names
	// DeleteKeyPair was asked to delete.
	creates         []*ec2.CreateKeyPairInput
	deletedKeyPairs []string
}

func (s *fakeEC2s) calls() []string {
	var out []string
	for _, v := range s.views {
		v.mu.Lock()
		out = append(out, v.calls...)
		v.mu.Unlock()
	}
	return out
}

func (s *fakeEC2s) count(call string) int {
	n := 0
	for _, c := range s.calls() {
		if strings.HasSuffix(c, ":"+call) {
			n++
		}
	}
	return n
}

func (s *fakeEC2s) imports() []*ec2.ImportKeyPairInput {
	var out []*ec2.ImportKeyPairInput
	for _, v := range s.views {
		out = append(out, v.imports...)
	}
	return out
}

func (s *fakeEC2s) includes() []bool {
	var out []bool
	for _, v := range s.views {
		out = append(out, v.includes...)
	}
	return out
}

func (s *fakeEC2s) reset() {
	for _, v := range s.views {
		v.calls, v.imports, v.includes = nil, nil, nil
	}
}

// awsHarness is a Runtime with one AWS account (profile "lab", access keys,
// region ap-east-1) whose EC2 requests go to a fake.
type awsHarness struct {
	t      *testing.T
	rt     *app.Runtime
	ec2    *fakeEC2s
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	dir    string
}

func newAWSHarness(t *testing.T, flags app.Flags, defaults map[string]any) *awsHarness {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv(app.EnvNonInteractive, "")
	fakes := &fakeEC2s{regions: map[string][]*fakeKeyPair{}}
	old := newEC2
	newEC2 = func(cfg awssdk.Config) ec2API {
		fakes.mu.Lock()
		defer fakes.mu.Unlock()
		v := &fakeEC2{region: cfg.Region, regions: fakes.regions, shared: fakes}
		fakes.views = append(fakes.views, v)
		return v
	}
	oldSSM := newSSM
	newSSM = func(cfg awssdk.Config) ssmAPI { return &fakeSSM{shared: fakes, region: cfg.Region} }
	oldELB, oldRDS := newELB, newRDS
	newELB = func(cfg awssdk.Config) elbAPI { return &fakeELB{shared: fakes, region: cfg.Region} }
	newRDS = func(cfg awssdk.Config) rdsAPI { return &fakeRDS{shared: fakes, region: cfg.Region} }
	oldACM := newACM
	newACM = func(cfg awssdk.Config) acmAPI { return &fakeACM{shared: fakes, region: cfg.Region} }
	t.Cleanup(func() { newEC2, newSSM, newELB, newRDS, newACM = old, oldSSM, oldELB, oldRDS, oldACM })

	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles = map[string]*config.Profile{
		"lab": {Platforms: map[platform.ID]*config.Account{
			platform.AWS: {Metadata: map[string]string{metaMethod: methodKeys, metaRegion: "ap-east-1"}},
		}},
	}
	if defaults != nil {
		cfg.Defaults = config.Defaults{string(platform.AWS): defaults}
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key("lab", string(platform.AWS)), map[string]string{secretAccessKeyID: "AKIATESTFAKEKEY00000", secretSecretAccessKey: "test-secret"}); err != nil {
		t.Fatal(err)
	}
	flags.ConfigDir = dir
	if flags.Output == "" {
		flags.Output = "json"
	}
	if !flags.NonInteractiveSet {
		flags.NonInteractive, flags.NonInteractiveSet = true, true
	}
	h := &awsHarness{t: t, ec2: fakes, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, dir: dir}
	h.rt = app.New(flags, strings.NewReader(""), h.stdout, h.stderr)
	if err := h.rt.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = h.rt.Close() })
	return h
}

// add puts a key pair into the fake account.
func (h *awsHarness) add(region string, kps ...*fakeKeyPair) {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.regions[region] = append(h.ec2.regions[region], kps...)
}

func (h *awsHarness) pairs(region string) []*fakeKeyPair {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	return h.ec2.regions[region]
}

// run executes `polyctl aws <args>`.
func (h *awsHarness) run(args ...string) error {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	cmd := Command(h.rt)
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return cmd.ExecuteContext(context.Background())
}

func (h *awsHarness) jsonOut(v any) {
	h.t.Helper()
	if err := json.Unmarshal(h.stdout.Bytes(), v); err != nil {
		h.t.Fatalf("stdout is not JSON: %v\n%s", err, h.stdout.String())
	}
}

func (h *awsHarness) report() platform.Report {
	h.t.Helper()
	var rep platform.Report
	h.jsonOut(&rep)
	return rep
}

func genED25519(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func genRSA(t *testing.T) ssh.PublicKey {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(&rk.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func keyLine(k ssh.PublicKey, comment string) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " " + comment
}

func writeKeyFile(t *testing.T, dir, name string, k ssh.PublicKey) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(keyLine(k, "ops@example.com")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// scriptedPicker answers the questions of the interactive flow in order.
type scriptedPicker struct {
	t       *testing.T
	answers []string
	titles  []string
}

func (p *scriptedPicker) next(title string) (string, error) {
	p.titles = append(p.titles, title)
	if len(p.answers) == 0 {
		p.t.Errorf("unexpected question %q", title)
		return "", prompt.ErrAborted
	}
	v := p.answers[0]
	p.answers = p.answers[1:]
	return v, nil
}
func (p *scriptedPicker) Select(title string, _ []prompt.Option, _ string) (string, error) {
	return p.next(title)
}
func (p *scriptedPicker) MultiSelect(title string, _ []prompt.Option) ([]string, error) {
	v, err := p.next(title)
	return []string{v}, err
}
func (p *scriptedPicker) Confirm(title string, _ bool) (bool, error) {
	v, err := p.next(title)
	return v == "yes", err
}
func (p *scriptedPicker) Input(title, _ string, _ func(string) error) (string, error) {
	return p.next(title)
}

func TestKeyPairList(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ed, rs := genED25519(t), genRSA(t)
	edKP, rsKP := newFakeKeyPair("ops", ed), newFakeKeyPair("build", rs)
	h.add("ap-east-1", edKP, rsKP)
	h.add("us-west-2", newFakeKeyPair("west", genED25519(t)))

	if err := h.run("ec2", "key-pair", "list"); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	h.jsonOut(&got)
	if len(got) != 2 || got[0]["name"] != "build" || got[1]["name"] != "ops" {
		t.Fatalf("list = %v", got)
	}
	ops := got[1]
	if ops["key_pair_id"] != "key-0ops" || ops["type"] != "ed25519" || ops["fingerprint"] != edKP.fingerprint || ops["created"] != "2026-01-02T03:04:05Z" {
		t.Errorf("ops row = %v", ops)
	}
	if strings.HasPrefix(ops["fingerprint"].(string), "SHA256:") || !strings.HasSuffix(ops["fingerprint"].(string), "=") {
		t.Errorf("json keeps the fingerprint as AWS reports it: %v", ops["fingerprint"])
	}
	if _, ok := ops["public_key"]; ok || strings.Contains(h.stdout.String(), "AAAA") {
		t.Errorf("the public key must not be printed: %s", h.stdout.String())
	}
	if inc := h.ec2.includes(); len(inc) != 1 || inc[0] {
		t.Errorf("list must not ask for public keys: %v", inc)
	}

	// The second list is served from the inventory.
	h.ec2.reset()
	if err := h.run("ec2", "key-pair", "list"); err != nil {
		t.Fatal(err)
	}
	if n := h.ec2.count("DescribeKeyPairs"); n != 0 || !strings.Contains(h.stderr.String(), "local inventory") {
		t.Errorf("cached list: %d calls, stderr %q", n, h.stderr.String())
	}

	// --region lists another region, live.
	if err := h.run("ec2", "key-pair", "list", "--region", "us-west-2"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&got)
	if len(got) != 1 || got[0]["name"] != "west" || got[0]["region"] != "us-west-2" {
		t.Errorf("--region list = %v", got)
	}

	// The table adds the SHA256: prefix to ED25519 fingerprints only.
	g := keyPairGrid([]keyPairInfo{{Name: "ops", Type: "ed25519", Fingerprint: edKP.fingerprint}, {Name: "build", Type: "rsa", Fingerprint: rsKP.fingerprint}})
	if strings.Join(g.Headers, " ") != "NAME TYPE FINGERPRINT CREATED" || g.Rows[0][2] != "SHA256:"+edKP.fingerprint || g.Rows[1][2] != rsKP.fingerprint {
		t.Errorf("grid = %+v", g)
	}
}

func TestKeyPairListEmpty(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	if err := h.run("ec2", "key-pair", "list", "--region", "eu-west-1"); err != nil {
		t.Fatalf("an empty list is not an error: %v", err)
	}
	if strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no key pairs in eu-west-1") {
		t.Errorf("empty list: stdout %q, stderr %q", h.stdout.String(), h.stderr.String())
	}
}

func TestKeyPairListOffline(t *testing.T) {
	h := newAWSHarness(t, app.Flags{Offline: true}, nil)
	if err := h.run("ec2", "key-pair", "list", "--region", "eu-west-1"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("--region offline = %v", err)
	}
	if n := len(h.ec2.calls()); n != 0 {
		t.Errorf("offline list called the API %d times", n)
	}
}

func TestKeyPairImport(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, map[string]any{"tags": map[string]any{"team": "ops"}})
	ed := genED25519(t)
	file := writeKeyFile(t, h.dir, "id_ed25519.pub", ed)
	// The inventory of the region holds no key pair yet.
	if err := h.run("ec2", "key-pair", "list"); err != nil {
		t.Fatal(err)
	}
	h.ec2.reset()

	if err := h.run("ec2", "key-pair", "import", "ops", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/ops" || rep.Changes[0].Action != platform.Created || rep.Changes[0].ID == "" ||
		rep.Target.Region != "ap-east-1" || rep.DryRun {
		t.Fatalf("report = %+v", rep)
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), strings.Fields(keyLine(ed, ""))[1]) {
		t.Error("the public key must not be printed")
	}
	imps := h.ec2.imports()
	if len(imps) != 1 || awssdk.ToString(imps[0].KeyName) != "ops" {
		t.Fatalf("imports = %+v", imps)
	}
	if k, _, _, _, err := ssh.ParseAuthorizedKey(imps[0].PublicKeyMaterial); err != nil || !bytes.Equal(k.Marshal(), ed.Marshal()) {
		t.Errorf("imported material = %q (%v)", imps[0].PublicKeyMaterial, err)
	}
	if ts := imps[0].TagSpecifications; len(ts) != 1 || ts[0].ResourceType != ec2types.ResourceTypeKeyPair || len(ts[0].Tags) != 1 ||
		awssdk.ToString(ts[0].Tags[0].Key) != "team" || awssdk.ToString(ts[0].Tags[0].Value) != "ops" {
		t.Errorf("tags = %+v", ts)
	}
	// The new key pair is in the cached inventory at once.
	h.ec2.reset()
	if err := h.run("ec2", "key-pair", "list"); err != nil {
		t.Fatal(err)
	}
	var list []keyPairInfo
	h.jsonOut(&list)
	if len(list) != 1 || list[0].Name != "ops" || h.ec2.count("DescribeKeyPairs") != 0 {
		t.Errorf("list after import = %+v (calls %v)", list, h.ec2.calls())
	}

	// The key itself with --ssh-key, an RSA key, in another region.
	rs := genRSA(t)
	if err := h.run("ec2", "key-pair", "import", "build", "--ssh-key", keyLine(rs, "ci"), "--region", "us-west-2"); err != nil {
		t.Fatal(err)
	}
	if ps := h.pairs("us-west-2"); len(ps) != 1 || ps[0].name != "build" || ps[0].typ != "rsa" {
		t.Errorf("us-west-2 pairs = %+v", ps)
	}

	// A taken name is a usage error, whatever key it holds.
	err := h.run("ec2", "key-pair", "import", "ops", "--ssh-key-file", file)
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "ensure") {
		t.Errorf("duplicate = %v", err)
	}
}

func TestKeyPairImportRefusals(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ed := genED25519(t)
	file := writeKeyFile(t, h.dir, "id_ed25519.pub", ed)
	priv := filepath.Join(h.dir, "id_ed25519")
	_ = os.WriteFile(priv, pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("x")}), 0o600)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)

	cases := []struct {
		name string
		args []string
		want string
		is   error
	}{
		{"path in --ssh-key", []string{"ops", "--ssh-key", file}, "--ssh-key-file", platform.ErrInvalidInput},
		{"both key flags", []string{"ops", "--ssh-key", keyLine(ed, ""), "--ssh-key-file", file}, "mutually exclusive", app.ErrUsage},
		{"private key file", []string{"ops", "--ssh-key-file", priv}, "private key", platform.ErrInvalidInput},
		{"not a key", []string{"ops", "--ssh-key", "hello"}, "not an SSH public key", platform.ErrInvalidInput},
		{"ecdsa", []string{"ops", "--ssh-key", keyLine(eck, "")}, "not supported", platform.ErrInvalidInput},
		{"no key", []string{"ops"}, "--ssh-key-file", app.ErrUsage},
		{"bad name", []string{"opé", "--ssh-key-file", file}, "ASCII", app.ErrUsage},
	}
	for _, c := range cases {
		err := h.run(append([]string{"ec2", "key-pair", "import"}, c.args...)...)
		if !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %v containing %q", c.name, err, c.is, c.want)
		}
	}
	if calls := h.ec2.calls(); len(calls) != 0 {
		t.Errorf("refused imports must not call the API: %v", calls)
	}
}

func TestKeyPairImportDryRun(t *testing.T) {
	h := newAWSHarness(t, app.Flags{DryRun: true}, nil)
	file := writeKeyFile(t, h.dir, "id_ed25519.pub", genED25519(t))
	if err := h.run("ec2", "key-pair", "import", "ops", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if !rep.DryRun || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].Resource != "key-pair/ops" ||
		!strings.Contains(rep.Changes[0].Detail, "import from --ssh-key-file") {
		t.Errorf("dry run report = %+v", rep)
	}
	if calls := h.ec2.calls(); len(calls) != 0 {
		t.Errorf("the dry run of import sends no request: %v", calls)
	}
	// The key is still checked.
	if err := h.run("ec2", "key-pair", "import", "ops", "--ssh-key", "nope"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("dry run with a bad key = %v", err)
	}
}

func TestKeyPairEnsureMatchesExisting(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ed, rs := genED25519(t), genRSA(t)
	h.add("ap-east-1", newFakeKeyPair("ops", ed), newFakeKeyPair("build", rs), newFakeKeyPair("other", genED25519(t)))
	edFile := writeKeyFile(t, h.dir, "ed.pub", ed)

	// Matched by public key, without a name.
	if err := h.run("ec2", "key-pair", "ensure", "--ssh-key-file", edFile); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/ops" || rep.Changes[0].Action != platform.Unchanged ||
		rep.Changes[0].Detail != "matched by public key" || rep.Changes[0].ID != "key-0ops" {
		t.Fatalf("report = %+v", rep)
	}
	if inc := h.ec2.includes(); len(inc) != 1 || !inc[0] {
		t.Errorf("ensure must list with IncludePublicKey: %v", inc)
	}
	if h.ec2.count("ImportKeyPair") != 0 {
		t.Error("a matched key must not be imported")
	}

	// A name that does not exist, while the key exists under another
	// name: the existing one is used, with a note.
	if err := h.run("ec2", "key-pair", "ensure", "laptop", "--ssh-key", keyLine(rs, "x")); err != nil {
		t.Fatal(err)
	}
	if rep = h.report(); rep.Changes[0].Resource != "key-pair/build" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(h.stderr.String(), `note: key already exists as "build", ignoring <name> "laptop"`) {
		t.Errorf("stderr = %q", h.stderr.String())
	}

	// Only a name: an existing key pair is used without a key.
	if err := h.run("ec2", "key-pair", "ensure", "other"); err != nil {
		t.Fatal(err)
	}
	if rep = h.report(); rep.Changes[0].Resource != "key-pair/other" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("name only = %+v", rep)
	}
	if h.ec2.count("ImportKeyPair") != 0 {
		t.Errorf("nothing may be imported: %v", h.ec2.calls())
	}
}

// Without the public key in the listing (very old key pairs, unverified),
// the fingerprint AWS computed for an imported key still matches: SHA-256
// for ED25519, MD5 of the DER for RSA.
func TestKeyPairEnsureFingerprintFallback(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ed, rs := genED25519(t), genRSA(t)
	edKP, rsKP := newFakeKeyPair("ed", ed), newFakeKeyPair("rs", rs)
	edKP.hidePublicKey, rsKP.hidePublicKey = true, true
	h.add("ap-east-1", edKP, rsKP)
	for name, k := range map[string]ssh.PublicKey{"ed": ed, "rs": rs} {
		if err := h.run("ec2", "key-pair", "ensure", "--ssh-key", keyLine(k, "")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep := h.report(); rep.Changes[0].Resource != "key-pair/"+name || rep.Changes[0].Action != platform.Unchanged {
			t.Errorf("%s: report = %+v", name, rep)
		}
	}
	if h.ec2.count("ImportKeyPair") != 0 {
		t.Errorf("nothing may be imported: %v", h.ec2.calls())
	}
}

func TestKeyPairEnsureCreates(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	h.add("ap-east-1", newFakeKeyPair("other", genED25519(t)))
	ed := genED25519(t)
	file := writeKeyFile(t, h.dir, "ed.pub", ed)

	if err := h.run("ec2", "key-pair", "ensure", "ops", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/ops" || rep.Changes[0].Action != platform.Created || rep.Changes[0].ID == "" {
		t.Fatalf("report = %+v", rep)
	}
	if imps := h.ec2.imports(); len(imps) != 1 || awssdk.ToString(imps[0].KeyName) != "ops" {
		t.Fatalf("imports = %+v", imps)
	}
	// Run again: unchanged.
	if err := h.run("ec2", "key-pair", "ensure", "ops", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	if rep = h.report(); rep.Changes[0].Action != platform.Unchanged || len(h.ec2.imports()) != 1 {
		t.Errorf("second ensure = %+v", rep)
	}
}

func TestKeyPairEnsureDryRun(t *testing.T) {
	h := newAWSHarness(t, app.Flags{DryRun: true}, nil)
	ed := genED25519(t)
	h.add("ap-east-1", newFakeKeyPair("ops", ed))
	if err := h.run("ec2", "key-pair", "ensure", "--ssh-key", keyLine(ed, "")); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); !rep.DryRun || rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].Detail != "matched by public key" {
		t.Errorf("dry run, existing = %+v", rep)
	}
	if err := h.run("ec2", "key-pair", "ensure", "laptop", "--ssh-key", keyLine(genED25519(t), "")); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	if !rep.DryRun || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].Resource != "key-pair/laptop" {
		t.Errorf("dry run, new = %+v", rep)
	}
	if n := h.ec2.count("ImportKeyPair"); n != 0 {
		t.Errorf("the dry run wrote: %v", h.ec2.calls())
	}
}

func TestKeyPairEnsureRefusals(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ed := genED25519(t)
	h.add("ap-east-1", newFakeKeyPair("ops", genED25519(t)), newFakeKeyPair("dup1", ed), newFakeKeyPair("dup2", ed))
	newKey := keyLine(genED25519(t), "")

	// The name holds another key: never replaced.
	err := h.run("ec2", "key-pair", "ensure", "ops", "--ssh-key", newKey)
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "different public key") {
		t.Errorf("name with another key = %v", err)
	}
	// The name holds another key although the key exists elsewhere.
	err = h.run("ec2", "key-pair", "ensure", "ops", "--ssh-key", keyLine(ed, ""))
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "different public key") {
		t.Errorf("name with another key, key under other names = %v", err)
	}
	// The name exists but was listed without its public key and with a
	// fingerprint AWS generated: refused, without claiming another key.
	gen := newFakeKeyPair("generated", genRSA(t))
	gen.hidePublicKey, gen.fingerprint = true, "1f:51:ae:28:bf:89:e9:d8:1f:25:5d:37:2d:7d:b8:ca:9f:f5:f1:6f"
	h.add("ap-east-1", gen)
	err = h.run("ec2", "key-pair", "ensure", "generated", "--ssh-key", newKey)
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "without its public key") || strings.Contains(err.Error(), "different public key") {
		t.Errorf("name listed without public key = %v", err)
	}
	// A new key without a name: no name is invented.
	err = h.run("ec2", "key-pair", "ensure", "--ssh-key", newKey)
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "needs a name: pass <name>") {
		t.Errorf("no name = %v", err)
	}
	// A missing name without a key.
	err = h.run("ec2", "key-pair", "ensure", "missing")
	if !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--ssh-key-file") {
		t.Errorf("missing name, no key = %v", err)
	}
	// Nothing at all.
	if err = h.run("ec2", "key-pair", "ensure"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("nothing given = %v", err)
	}
	// The key under several names: ambiguous unless the name picks one.
	err = h.run("ec2", "key-pair", "ensure", "--ssh-key", keyLine(ed, ""))
	if !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "dup1, dup2") {
		t.Errorf("several matches = %v", err)
	}
	if err := h.run("ec2", "key-pair", "ensure", "dup2", "--ssh-key", keyLine(ed, "")); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/dup2" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("picked = %+v", rep)
	}
	// ECDSA is refused before any request.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)
	h.ec2.reset()
	if err = h.run("ec2", "key-pair", "ensure", "x", "--ssh-key", keyLine(eck, "")); !errors.Is(err, platform.ErrInvalidInput) || len(h.ec2.calls()) != 0 {
		t.Errorf("ecdsa = %v (calls %v)", err, h.ec2.calls())
	}
	if n := h.ec2.count("ImportKeyPair"); n != 0 {
		t.Errorf("refusals must not import: %v", h.ec2.calls())
	}
	// Invalid credentials map to the authentication exit code.
	h.ec2.descErr = &fakeAPIError{"AuthFailure", "AWS was not able to validate the provided access credentials"}
	if err = h.run("ec2", "key-pair", "ensure", "ops"); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("AuthFailure = %v", err)
	}
}

func TestKeyPairEnsureInteractive(t *testing.T) {
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	ed := genED25519(t)
	h.add("ap-east-1", newFakeKeyPair("dup1", ed), newFakeKeyPair("dup2", ed))
	file := writeKeyFile(t, h.dir, "new.pub", genED25519(t))
	t.Setenv("HOME", h.dir) // no ~/.ssh: the file is typed

	// A new key without a name: the name is asked for.
	p := &scriptedPicker{t: t, answers: []string{"laptop"}}
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "ensure", "--ssh-key-file", file); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/laptop" || rep.Changes[0].Action != platform.Created {
		t.Errorf("report = %+v (asked %v)", rep, p.titles)
	}

	// An empty name cancels: nothing to do, nothing created.
	h.rt.Picker = &scriptedPicker{t: t, answers: []string{""}}
	other := writeKeyFile(t, h.dir, "other.pub", genED25519(t))
	if err := h.run("ec2", "key-pair", "ensure", "--ssh-key-file", other); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("empty name = %v", err)
	}

	// A missing name without a key: the key file is asked for.
	h.rt.Picker = &scriptedPicker{t: t, answers: []string{writeKeyFile(t, h.dir, "third.pub", genED25519(t))}}
	if err := h.run("ec2", "key-pair", "ensure", "third"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/third" || rep.Changes[0].Action != platform.Created {
		t.Errorf("asked key = %+v", rep)
	}

	// Several matches: the choice is asked for.
	h.rt.Picker = &scriptedPicker{t: t, answers: []string{"dup2"}}
	if err := h.run("ec2", "key-pair", "ensure", "--ssh-key", keyLine(ed, "")); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/dup2" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("chosen = %+v", rep)
	}
	if n := len(h.ec2.imports()); n != 2 {
		t.Errorf("imports = %d, want 2", n)
	}
}

func TestKeyPairCommandsOffline(t *testing.T) {
	h := newAWSHarness(t, app.Flags{Offline: true}, nil)
	file := writeKeyFile(t, h.dir, "ed.pub", genED25519(t))
	for _, args := range [][]string{
		{"ec2", "key-pair", "import", "ops", "--ssh-key-file", file},
		{"ec2", "key-pair", "ensure", "ops", "--ssh-key-file", file},
	} {
		if err := h.run(args...); !errors.Is(err, app.ErrOffline) {
			t.Errorf("%v offline = %v", args, err)
		}
	}
	if calls := h.ec2.calls(); len(calls) != 0 {
		t.Errorf("offline writes called the API: %v", calls)
	}
}

func TestSyncKeyPairs(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	h.add("ap-east-1", newFakeKeyPair("ops", genED25519(t)))
	c := &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) }}
	res, err := c.Sync(context.Background(), platform.ResKeyPair)
	if err != nil || len(res) != 1 || res[0].Type != platform.ResKeyPair || res[0].Name != "ops" || res[0].ID != "key-0ops" {
		t.Fatalf("Sync = %+v, %v", res, err)
	}
	if inc := h.ec2.includes(); len(inc) != 1 || inc[0] {
		t.Errorf("sync must not fetch public keys: %v", inc)
	}
}

func TestImportErrorMapping(t *testing.T) {
	if err := importError("ops", "ap-east-1", &fakeAPIError{"InvalidKey.Format", "Key is not in valid OpenSSH public key format"}); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("InvalidKey.Format = %v", err)
	}
	if err := importError("ops", "ap-east-1", &fakeAPIError{"UnauthorizedOperation", "denied"}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("UnauthorizedOperation = %v", err)
	}
	other := &fakeAPIError{"InternalError", "boom"}
	if err := importError("ops", "ap-east-1", other); !errors.Is(err, other) || errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("unknown error = %v", err)
	}
}
