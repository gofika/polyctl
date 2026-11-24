package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// ec2InstanceTree is the command group of EC2 instances, as the notes
// about the password command name it.
const ec2InstanceTree = "aws ec2 instance"

// windowsUser is the login of an EC2 Windows instance: the AWS Windows
// images generate the password of Administrator at the first boot and
// encrypt it with the public key of the instance's key pair.
const windowsUser = "Administrator"

// The wait for the Windows password polls every 15 seconds (AWS needs a
// few minutes after the instance runs), up to defaultPasswordTimeout
// unless --password-timeout says otherwise. Tests shorten nothing: they
// use the fake clock of the instance waits.
var passwordPollInterval = 15 * time.Second

const defaultPasswordTimeout = 20 * time.Minute

// windowsParamPath is the SSM path of the public parameters that hold the
// latest AWS Windows images, one per edition.
const windowsParamPath = "/aws/service/ami-windows-latest/"

// windowsParamName matches the parameter of the English Full Base image of
// a Windows Server year (2016, 2019, 2022, 2025, ...): the desktop
// experience edition, x86_64 (AWS publishes no arm64 Windows images).
var windowsParamName = regexp.MustCompile(`^Windows_Server-(\d{4})-English-Full-Base$`)

// windowsImageName matches the name of such an image:
// Windows_Server-<year>-English-Full-Base-<yyyy.mm.dd>.
var windowsImageName = regexp.MustCompile(`^Windows_Server-(\d{4})-English-Full-Base-(\d{4}\.\d{2}\.\d{2})$`)

// latestWindowsAMI returns the image of the newest Windows Server English
// Full Base: the public SSM parameters under windowsParamPath first, the
// highest year among them (so a new Windows Server release is used as soon
// as AWS publishes its parameter), when its image is available, not
// deprecated and x86_64; when they cannot be read (no
// ssm:GetParametersByPath permission, ...) or that image is not, the
// newest available, not deprecated x86_64 image owned by Amazon named Windows_Server-<year>-English-Full-Base-<date> (highest
// year, then latest date). note receives a line about the fallback.
func (c *client) latestWindowsAMI(ctx context.Context, region string, note func(string)) (imageInfo, error) {
	region = c.regionOr(region)
	best, _, err := c.windowsParameter(ctx, region)
	if err == nil && best != "" {
		img, derr := c.describeImage(ctx, region, best)
		switch {
		case derr == nil && img.pickable(archX8664):
			img.Windows = true
			return img, nil
		case derr == nil:
			err = fmt.Errorf("its image %s is not an available x86_64 image", best)
		case errors.Is(derr, platform.ErrNotFound):
			err = fmt.Errorf("its image %s does not exist", best)
		default:
			return imageInfo{}, derr
		}
	}
	if err == nil {
		err = errors.New("no Windows_Server-<year>-English-Full-Base parameter")
	}
	if note != nil {
		note(fmt.Sprintf("note: cannot read the parameters under %s (%v); picking the newest Windows Server English Full Base image instead", windowsParamPath, mapErr(err)))
	}
	pg := ec2.NewDescribeImagesPaginator(c.ec2For(region), &ec2.DescribeImagesInput{
		Owners: []string{"amazon"},
		Filters: []ec2types.Filter{
			{Name: awssdk.String("name"), Values: []string{"Windows_Server-*-English-Full-Base-*"}},
			{Name: awssdk.String("platform"), Values: []string{"windows"}},
			{Name: awssdk.String("state"), Values: []string{"available"}},
			{Name: awssdk.String("architecture"), Values: []string{"x86_64"}},
		},
		IncludeDeprecated: awssdk.Bool(false),
	})
	var pick *imageInfo
	var pickYear, pickDate string
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return imageInfo{}, ec2Err("DescribeImages", region, err)
		}
		for _, im := range page.Images {
			info := imageFrom(im)
			m := windowsImageName.FindStringSubmatch(info.Name)
			if m == nil || !info.pickable(archX8664) {
				continue
			}
			if pick == nil || m[1] > pickYear || m[1] == pickYear && (m[2] > pickDate || m[2] == pickDate && info.Created > pick.Created) {
				pick, pickYear, pickDate = &info, m[1], m[2]
			}
		}
	}
	if pick == nil {
		return imageInfo{}, fmt.Errorf("%w: no Windows Server English Full Base image in %s; pass --ami <ami-id>", platform.ErrNotFound, region)
	}
	pick.Windows = true
	return *pick, nil
}

// windowsParameter returns the image id held by the newest
// Windows_Server-<year>-English-Full-Base parameter, and its year.
func (c *client) windowsParameter(ctx context.Context, region string) (string, int, error) {
	pg := ssm.NewGetParametersByPathPaginator(c.ssmFor(region), &ssm.GetParametersByPathInput{
		Path: awssdk.String(windowsParamPath), MaxResults: awssdk.Int32(10),
	})
	best, bestYear := "", 0
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return "", 0, err
		}
		for _, p := range page.Parameters {
			name := strings.TrimPrefix(awssdk.ToString(p.Name), windowsParamPath)
			m := windowsParamName.FindStringSubmatch(name)
			v := awssdk.ToString(p.Value)
			if m == nil || !strings.HasPrefix(v, "ami-") {
				continue
			}
			if y, _ := strconv.Atoi(m[1]); y > bestYear {
				best, bestYear = v, y
			}
		}
	}
	return best, bestYear, nil
}

// windowsArchCheck refuses an instance type that runs no Windows Server
// image: AWS publishes x86_64 Windows images only. A Mac type is exit code
// 7, an arm64 type exit code 2.
func windowsArchCheck(typ string, archs []string) error {
	for _, a := range archs {
		if a == "x86_64" {
			return nil
		}
	}
	for _, a := range archs {
		if strings.HasSuffix(a, "_mac") {
			return fmt.Errorf("%w: instance type %s is a Mac type (%s), which runs no Windows", platform.ErrNotSupported, typ, strings.Join(archs, ", "))
		}
	}
	return app.UsageErrf("instance type %s runs %s: Windows Server images are x86_64 only; choose an x86_64 type", typ, strings.Join(archs, ", "))
}

// ------------------------------------------------------------ keys

// windowsKey is the RSA private key that decrypts a Windows password, with
// its PEM text.
type windowsKey struct {
	key *rsa.PrivateKey
	pem string
}

// publicKey is the key as key pair resolution matches it.
func (k *windowsKey) publicKey(source string) (*platform.PublicKey, error) {
	pub, err := ssh.NewPublicKey(&k.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &platform.PublicKey{Key: pub, Source: source}, nil
}

// parseWindowsKey parses an unencrypted RSA private key (PKCS #1 or
// PKCS #8 PEM, or the OpenSSH format). Anything else is an error that
// never quotes the key.
func parseWindowsKey(text string) (*windowsKey, error) {
	raw, err := ssh.ParseRawPrivateKey([]byte(text))
	if err != nil {
		var pm *ssh.PassphraseMissingError
		if errors.As(err, &pm) {
			return nil, errors.New("the private key is encrypted with a passphrase; decrypt a copy first (ssh-keygen -p -N '' -m PEM -f <copy>)")
		}
		return nil, errors.New("not an RSA private key in PEM or OpenSSH format")
	}
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		return &windowsKey{key: k, pem: text}, nil
	}
	return nil, fmt.Errorf("a %T key cannot decrypt a Windows password: AWS encrypts it for RSA key pairs only (ED25519 key pairs are not supported for Windows)", raw)
}

// loadWindowsKey reads --key-file (~ is expanded); a file that cannot be
// read or parsed is a usage error.
func loadWindowsKey(path string) (*windowsKey, error) {
	b, err := os.ReadFile(platform.ExpandHome(path))
	if err != nil {
		return nil, app.UsageErrf("--key-file: %v", err)
	}
	k, err := parseWindowsKey(string(b))
	if err != nil {
		return nil, app.UsageErrf("--key-file %s: %v", path, err)
	}
	return k, nil
}

// decryptWindowsPassword decrypts the PasswordData of GetPasswordData:
// base64, then RSA PKCS #1 v1.5 with the key pair's private key.
func decryptWindowsPassword(k *rsa.PrivateKey, data string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(data), ""))
	if err != nil {
		return "", errors.New("the password data AWS returned is not base64")
	}
	plain, err := rsa.DecryptPKCS1v15(rand.Reader, k, ct)
	if err != nil {
		return "", errors.New("the password does not decrypt with this private key (it is not the private key of the instance's key pair)")
	}
	return string(plain), nil
}

// createKeyPairRSA creates an RSA key pair whose private key AWS returns
// once (PEM); tags, when not empty, go on the key pair.
func (c *client) createKeyPairRSA(ctx context.Context, region, name string, tags map[string]string) (keyPairInfo, string, error) {
	region = c.regionOr(region)
	in := &ec2.CreateKeyPairInput{KeyName: awssdk.String(name), KeyType: ec2types.KeyTypeRsa, KeyFormat: ec2types.KeyFormatPem}
	if len(tags) > 0 {
		in.TagSpecifications = []ec2types.TagSpecification{{ResourceType: ec2types.ResourceTypeKeyPair, Tags: sortedTags(tags)}}
	}
	out, err := c.ec2For(region).CreateKeyPair(ctx, in)
	if err != nil {
		if platform.HasErrorCode(err, errKeyPairDuplicate) {
			return keyPairInfo{}, "", fmt.Errorf("%w: key pair %q already exists in %s (an existing key pair is never replaced)", platform.ErrInvalidInput, name, region)
		}
		return keyPairInfo{}, "", ec2Err("CreateKeyPair", region, err)
	}
	pem := awssdk.ToString(out.KeyMaterial)
	if pem == "" {
		return keyPairInfo{}, "", fmt.Errorf("ec2:CreateKeyPair in %s returned no private key for %s", region, name)
	}
	info := keyPairInfo{Name: awssdk.ToString(out.KeyName), KeyPairID: awssdk.ToString(out.KeyPairId), Type: string(ec2types.KeyTypeRsa),
		Fingerprint: awssdk.ToString(out.KeyFingerprint), Region: region}
	if info.Name == "" {
		info.Name = name
	}
	return info, pem, nil
}

// deleteKeyPair deletes a key pair by name and returns its id when AWS
// reports one.
func (c *client) deleteKeyPair(ctx context.Context, region, name string) (string, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).DeleteKeyPair(ctx, &ec2.DeleteKeyPairInput{KeyName: awssdk.String(name)})
	if err != nil {
		return "", ec2Err("DeleteKeyPair", region, err)
	}
	return awssdk.ToString(out.KeyPairId), nil
}

// passwordData returns the encrypted Windows password of an instance; ""
// while AWS has not generated it yet.
func (c *client) passwordData(ctx context.Context, region, id string) (string, error) {
	region = c.regionOr(region)
	out, err := c.ec2For(region).GetPasswordData(ctx, &ec2.GetPasswordDataInput{InstanceId: awssdk.String(id)})
	if err != nil {
		if platform.HasErrorCode(err, "InvalidInstanceID.NotFound") {
			return "", fmt.Errorf("%w: instance %s in %s", platform.ErrNotFound, id, region)
		}
		return "", ec2Err("GetPasswordData", region, err)
	}
	return strings.TrimSpace(awssdk.ToString(out.PasswordData)), nil
}

// ------------------------------------------------------------ login

// windowsLogin is the login of a Windows instance a create makes. The key
// pair step fills key (created by polyctl, or read from --key-file); the
// instance step records the instance with created, waits for the password
// with wait, and finish shows the result once the plan has run.
type windowsLogin struct {
	rt      *app.Runtime
	c       *client
	profile string
	region  string
	name    string

	key *windowsKey
	// createdKeyPair is the key pair polyctl created (its private key is
	// stored with the credentials, and deleting the instance deletes it);
	// "" when the key is the user's (--key-file), which is not stored.
	createdKeyPair string
	// createdKeyPairID is its id, to drop it from the inventory when it
	// is deleted again.
	createdKeyPairID string

	id       string
	password string
	// stored reports that the credentials as they are now are stored.
	stored bool
}

func (w *windowsLogin) credentials() secrets.Credentials {
	c := secrets.Credentials{Ref: secrets.Ref{Platform: platform.AWS, Profile: w.profile, Location: w.region, InstanceID: w.id},
		Name: w.name, User: windowsUser, Password: w.password, KeyPair: w.createdKeyPair}
	if w.createdKeyPair != "" && w.key != nil {
		c.PrivateKey = w.key.pem
	}
	return c
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

// created records the instance RunInstances made: the user, and the
// private key when polyctl created the key pair, so that the password
// command can fetch the password later. A failure is left to finish.
func (w *windowsLogin) created(ctx context.Context, id string) {
	w.id = id
	w.put(ctx)
}

// pendingInstancePrefix starts the instance id under which the login of an
// instance whose RunInstances result is unknown is stored: the password
// command finds it by the instance name, and stores it again under the
// real id once it has fetched the password.
const pendingInstancePrefix = "pending-"

// pending stores the login of an instance whose RunInstances result is
// unknown, under the client token of the request and the instance name,
// so that the private key of the key pair polyctl created survives the
// run. Nothing is shown: finish has no instance id. A cancelled or timed
// out run (one way the result becomes unknown) still stores it.
func (w *windowsLogin) pending(ctx context.Context, token string) {
	w.id = pendingInstancePrefix + token
	w.put(context.WithoutCancel(ctx))
	if !w.stored {
		w.rt.Infof("warning: the private key of key pair %s could not be stored: if instance %s exists, reset its Windows password in AWS", w.createdKeyPair, w.name)
	} else {
		w.rt.Infof("note: key pair %s is kept and its private key stored: if instance %s exists, `%s` fetches its password", w.createdKeyPair, w.name, app.PasswordCommandLine(ec2InstanceTree, w.name))
	}
	w.id = ""
}

// wait polls GetPasswordData until AWS has generated the password, then
// decrypts and stores it. It returns the state for the change report; the
// create succeeds whatever it is.
func (w *windowsLogin) wait(ctx context.Context, timeout time.Duration) string {
	var data string
	err := platform.WaitUntil(ctx, platform.WaitOptions{
		Resource: "instance/" + w.name, Want: "Windows password available", Timeout: timeout, Interval: passwordPollInterval, Clock: instanceClock,
	}, func(ctx context.Context) (platform.WaitState, string, error) {
		d, err := w.c.passwordData(ctx, w.region, w.id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if d == "" {
			return platform.KeepWaiting, "password not generated yet", nil
		}
		data = d
		return platform.WaitDone, "password generated", nil
	})
	var te *platform.WaitTimeoutError
	switch {
	case errors.As(err, &te):
		w.rt.Infof("note: the Windows password of instance %s (%s) was not generated within %s", w.name, w.id, timeout)
		return "Windows password not available yet"
	case err != nil:
		w.rt.Infof("warning: cannot read the Windows password of instance %s (%s): %v", w.name, w.id, err)
		return "Windows password not read"
	}
	pw, err := decryptWindowsPassword(w.key.key, data)
	if err != nil {
		w.rt.Infof("warning: the Windows password of instance %s (%s): %v", w.name, w.id, err)
		return "Windows password not decrypted"
	}
	w.password = pw
	w.put(ctx)
	return "Windows password retrieved"
}

// finish shows the login once the plan has run, whether or not a later
// step failed: the instance exists from RunInstances on. Nothing happens
// when no instance was created (a dry run, an earlier failure, a Linux
// instance).
func (w *windowsLogin) finish(ctx context.Context) error {
	if w == nil || w.id == "" {
		return nil
	}
	var err error
	if w.stored {
		w.rt.ShowCredentials(w.credentials(), ec2InstanceTree)
	} else {
		err = w.rt.SaveCredentials(ctx, w.credentials(), ec2InstanceTree, nil)
	}
	if w.password == "" && w.createdKeyPair == "" {
		w.rt.Infof("note: polyctl does not store the private key of --key-file: pass it to `%s --key-file <path>`", app.PasswordCommandLine(ec2InstanceTree, w.id))
	}
	return err
}

// createdKeyPairOf returns the key pair polyctl created for an instance
// and recorded with its credentials, when the instance still uses it; ""
// otherwise (a key pair of the user's is never deleted).
func createdKeyPairOf(ctx context.Context, rt *app.Runtime, l *locatedInstance) string {
	st, err := rt.Secrets()
	if err != nil {
		rt.Verbosef("read the stored login of %s: %v", l.id(), err)
		return ""
	}
	c, err := st.Get(ctx, secrets.Ref{Platform: platform.AWS, Profile: l.profile, Location: l.region, InstanceID: l.id()})
	if err != nil {
		if !errors.Is(err, platform.ErrNotFound) {
			rt.Infof("warning: cannot read the stored login of instance %s: %v; a key pair polyctl created for it is not deleted", l.id(), err)
		}
		return ""
	}
	if c.KeyPair == "" || c.KeyPair != awssdk.ToString(l.inst.KeyName) {
		return ""
	}
	return c.KeyPair
}

// forgetLogin removes what polyctl stored for a deleted instance: the key
// pair it created for it (kp, "" for none; a failure is a warning) and the
// stored credentials. It returns the change of the key pair, nil when
// there is none.
func forgetLogin(ctx context.Context, rt *app.Runtime, l *locatedInstance, kp string) *platform.Change {
	var ch *platform.Change
	if kp != "" {
		id, err := l.c.deleteKeyPair(ctx, l.region, kp)
		if err != nil {
			rt.Infof("warning: the key pair %s polyctl created for instance %s was not deleted: %v; delete it with the AWS console or CLI", kp, l.id(), err)
		} else {
			if id != "" {
				dropKeyPair(ctx, rt, l.profile, id)
			}
			rt.Infof("key pair %s, created by polyctl for instance %s, deleted", kp, l.id())
			ch = &platform.Change{Resource: "key-pair/" + kp, Action: platform.Deleted, ID: id, Detail: "created by polyctl for this instance"}
		}
	}
	rt.ForgetCredentials(ctx, secrets.Ref{Platform: platform.AWS, Profile: l.profile, Location: l.region, InstanceID: l.id()})
	return ch
}

// dropKeyPair removes a key pair from the inventory.
func dropKeyPair(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResKeyPair}, platform.ResKeyPair, id)
	}
}

// ------------------------------------------------------------ password

func ec2PasswordCmd(rt *app.Runtime) *cobra.Command {
	var keyFile string
	cmd := app.InstancePasswordCommand(rt, app.PasswordCommand{
		Platform:     platform.AWS,
		Tree:         ec2InstanceTree,
		LocationFlag: "region",
		Detail: `AWS EC2: a Windows instance generates the password of Administrator at
its first boot and AWS encrypts it with the public key of the instance's
RSA key pair. create --os windows waits for it (--password-timeout, 20
minutes by default), decrypts it and stores it. When it was not ready in
time, this command asks AWS again (ec2:GetPasswordData) and decrypts it
with the private key polyctl stored, when polyctl created the key pair,
or with --key-file: the private key of a key pair of yours (polyctl does
not store it). The password is stored once it is known. A password AWS
has not generated yet is exit code 4 ("try again in a few minutes"), as
is an instance with nothing stored and no --key-file. --key-file also
fetches the password of a Windows instance polyctl did not create.
Deleting the instance with polyctl removes its stored credentials and the
key pair polyctl created for it.`,
		Retrieve: func(ctx context.Context, profile, location, ref string, stored *secrets.Credentials) (*secrets.Credentials, error) {
			return retrieveWindowsLogin(ctx, rt, profile, location, ref, stored, keyFile)
		},
	})
	cmd.Example += "\n  polyctl " + ec2InstanceTree + " password win-1 --key-file ~/.ssh/ops-rsa.pem"
	cmd.Flags().StringVar(&keyFile, "key-file", "", "RSA private key of the instance's key pair (PEM or OpenSSH, unencrypted; ~ is expanded) to decrypt the password with; never stored")
	return cmd
}

// retrieveWindowsLogin fetches and decrypts the Windows password of an
// instance whose stored credentials lack it (stored) or that has none
// stored (stored is nil, which needs --key-file).
func retrieveWindowsLogin(ctx context.Context, rt *app.Runtime, profile, location, ref string, stored *secrets.Credentials, keyFile string) (*secrets.Credentials, error) {
	var key *windowsKey
	if keyFile != "" {
		k, err := loadWindowsKey(keyFile)
		if err != nil {
			return nil, err
		}
		key = k
	}
	var c *client
	var cred secrets.Credentials
	label := ""
	if stored == nil {
		if key == nil {
			return nil, fmt.Errorf("%w: no Windows credentials stored for instance %q in profile %s: polyctl stores them when it creates an instance with --os windows; for another Windows instance pass --key-file <the RSA private key of its key pair> to fetch and decrypt the password AWS generated",
				platform.ErrNotFound, ref, profile)
		}
		l, err := resolveInstance(ctx, rt, ref, location, false)
		if err != nil {
			return nil, err
		}
		if l.inst.Platform != ec2types.PlatformValuesWindows {
			return nil, fmt.Errorf("%w: instance %s is not a Windows instance: it has no password (Linux instances log in with their key pair)", platform.ErrNotFound, instanceLabel(l.inst))
		}
		c, label = l.c, instanceLabel(l.inst)
		cred = secrets.Credentials{Ref: secrets.Ref{Platform: platform.AWS, Profile: l.profile, Location: l.region, InstanceID: l.id()},
			Name: instanceName(l.inst), User: windowsUser}
	} else {
		cred = *stored
		label = cred.InstanceID
		if cred.Name != "" && cred.Name != cred.InstanceID {
			label = cred.Name + " (" + cred.InstanceID + ")"
		}
		if key == nil && cred.PrivateKey != "" {
			k, err := parseWindowsKey(cred.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("the stored private key of instance %s: %v", label, err)
			}
			key = k
		}
		if key == nil {
			return nil, fmt.Errorf("%w: the Windows password of instance %s is not stored and polyctl holds no private key to decrypt it (the key pair is yours): pass --key-file <the RSA private key of its key pair>",
				platform.ErrNotFound, label)
		}
		if pendingID := cred.InstanceID; strings.HasPrefix(pendingID, pendingInstancePrefix) {
			// Stored when the RunInstances result was unknown: the
			// instance, if it exists, goes by the name.
			l, err := resolveInstance(ctx, rt, cred.Name, cred.Location, false)
			if err != nil {
				return nil, fmt.Errorf("the login of instance %s was stored while its creation was uncertain: %w", cred.Name, err)
			}
			// Only the instance that uncertain RunInstances launched runs
			// with the key pair: another instance of the name does not.
			if tok := strings.TrimPrefix(pendingID, pendingInstancePrefix); awssdk.ToString(l.inst.ClientToken) != tok {
				return nil, fmt.Errorf("%w: the login of instance %s was stored while its creation was uncertain, and instance %s was not launched by that create (its client token differs): that create launched no instance, or one that is gone; if no instance of it exists, delete key pair %s in AWS",
					platform.ErrNotFound, cred.Name, instanceLabel(l.inst), cred.KeyPair)
			}
			c = l.c
			cred.Ref = secrets.Ref{Platform: platform.AWS, Profile: l.profile, Location: l.region, InstanceID: l.id()}
			label = instanceLabel(l.inst)
			// From now on the login goes by the instance id.
			if st, err := rt.Secrets(); err == nil && st.Put(ctx, cred) == nil {
				_ = st.Delete(ctx, stored.Ref)
			}
		} else {
			// The profile asked for, not the stored row's: the row of an
			// account that was logged out names a detached profile.
			var err error
			if c, err = openProfile(ctx, rt, profile); err != nil {
				return nil, err
			}
		}
	}
	data, err := c.passwordData(ctx, cred.Location, cred.InstanceID)
	if err != nil {
		return nil, err
	}
	if data == "" {
		return nil, fmt.Errorf("%w: the Windows password of instance %s is not available yet (AWS generates it a few minutes after launch): try again in a few minutes",
			platform.ErrNotFound, label)
	}
	pw, err := decryptWindowsPassword(key.key, data)
	if err != nil {
		return nil, fmt.Errorf("instance %s: %v", label, err)
	}
	cred.Password = pw
	return &cred, nil
}

// ------------------------------------------------------------ create

// errLinuxKeyRequired refuses a Linux create without any key: an instance
// nobody can log in to.
func errLinuxKeyRequired() error {
	return app.UsageErrf("a key pair is required (Linux instances log in with a key only, never a password): pass --key-pair <name> (an existing key pair), --ssh-key-file <path> / --ssh-key <public key> with --key-pair <name> to import one, or set defaults.aws.key_name")
}

// askWindowsKeyFile asks, in the interactive flow, for the RSA private key
// file of --key-pair when a Windows instance gets --key-pair without
// --key-file (checked as typed; read only to decrypt the password, never
// stored). Otherwise keyFile is returned as it is, and windowsKeyFlags
// keeps the usage error of the non-interactive flow.
func askWindowsKeyFile(rt *app.Runtime, keys app.KeyFlags, keyFile string) (string, error) {
	if keys.KeyPair == "" || keyFile != "" || keys.SSHKey != "" || keys.SSHKeyFile != "" || !rt.Interactive() {
		return keyFile, nil
	}
	return rt.AskInput("--key-file", fmt.Sprintf("Path of the RSA private key of key pair %s (decrypts the Windows password)", keys.KeyPair), "", func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return errors.New("the path of the private key file is required")
		}
		_, err := loadWindowsKey(s)
		return inline(err)
	})
}

// windowsKeyFlags refuses the key flags that cannot serve a Windows
// instance: a public key decrypts nothing, and a key pair of the user's
// is of no use without its private key.
func windowsKeyFlags(keys app.KeyFlags, keyFile string) error {
	if keys.SSHKey != "" || keys.SSHKeyFile != "" {
		return app.UsageErrf("--ssh-key and --ssh-key-file do not apply to Windows instances: the Windows password is decrypted with the private key of an RSA key pair; pass --key-file <private key> (with --key-pair <name> to import it under that name), or neither to let polyctl create the key pair")
	}
	if keys.KeyPair != "" && keyFile == "" {
		return app.UsageErrf("--key-pair %q needs --key-file <its RSA private key> for a Windows instance: polyctl decrypts the Windows password with it; without both, polyctl creates an RSA key pair for the instance", keys.KeyPair)
	}
	return nil
}

// windowsKeyPairStep resolves the key pair of a Windows instance and
// returns its name and the plan step that provides it. With --key-file
// (win.key set) it is the key pair that holds that key's public key,
// imported under --key-pair when none does. Otherwise polyctl creates an
// RSA key pair named by naming.aws_windows_key_pair; one of that name
// already existing is a usage error (polyctl never reuses a key pair whose
// private key it may not hold).
func windowsKeyPairStep(ctx context.Context, rt *app.Runtime, c *client, profile, region, name, keyPairFlag, keyFile string, win *windowsLogin) (string, platform.Step, error) {
	lister := &keyPairLister{c: c, region: region}
	if win.key != nil {
		pub, err := win.key.publicKey("--key-file " + keyFile)
		if err != nil {
			return "", platform.Step{}, app.UsageErrf("--key-file %s: %v", keyFile, err)
		}
		in := keyInputBase()
		in.Key, in.Name, in.AllowedTypes = pub, keyPairFlag, []string{platform.KeyTypeRSA}
		kp, err := platform.ResolveKeyPair(ctx, lister, in)
		if err != nil {
			return "", platform.Step{}, err
		}
		for _, n := range kp.Notes {
			rt.Infof("%s", n)
		}
		var kpTags map[string]string
		if kp.Create && !rt.DryRun() {
			if kpTags, err = keyPairTags(rt, profile); err != nil {
				return "", platform.Step{}, err
			}
		}
		return kp.Name, kp.Step(func(ctx context.Context, name string, key *platform.PublicKey) (string, error) {
			info, err := c.importKeyPair(ctx, region, name, key, kpTags)
			if err != nil {
				return "", err
			}
			storeKeyPair(ctx, rt, c, profile, info)
			return info.KeyPairID, nil
		}), nil
	}
	kpName, err := rt.ResourceName("aws_windows_key_pair", "", map[string]string{"name": name})
	if err != nil {
		return "", platform.Step{}, app.UsageErrf("%v", err)
	}
	if err := checkKeyPairName(kpName); err != nil {
		return "", platform.Step{}, err
	}
	pairs, err := lister.ListKeyPairs(ctx)
	if err != nil {
		return "", platform.Step{}, err
	}
	for _, kp := range pairs {
		if kp.Name == kpName {
			return "", platform.Step{}, app.UsageErrf("key pair %q (naming.aws_windows_key_pair) already exists in %s: polyctl creates a new RSA key pair for a Windows instance and never reuses one; pass --key-pair %s --key-file <its RSA private key> to launch with it, or set naming.aws_windows_key_pair", kpName, region, kpName)
		}
	}
	var kpTags map[string]string
	if !rt.DryRun() {
		if kpTags, err = keyPairTags(rt, profile); err != nil {
			return "", platform.Step{}, err
		}
	}
	return kpName, platform.Step{Resource: "key-pair/" + kpName, Action: platform.Created,
		Desc: "create RSA key pair for the Windows password (private key stored encrypted by polyctl, never shown)",
		Apply: func(ctx context.Context) (platform.Change, error) {
			info, pem, err := c.createKeyPairRSA(ctx, region, kpName, kpTags)
			if err != nil {
				return platform.Change{}, err
			}
			k, err := parseWindowsKey(pem)
			if err != nil {
				_, _ = c.deleteKeyPair(ctx, region, kpName)
				return platform.Change{}, fmt.Errorf("the private key AWS returned for key pair %s: %v (the key pair was deleted again)", kpName, err)
			}
			win.key, win.createdKeyPair, win.createdKeyPairID = k, info.Name, info.KeyPairID
			storeKeyPair(ctx, rt, c, profile, info)
			return platform.Change{ID: info.KeyPairID}, nil
		}}, nil
}
