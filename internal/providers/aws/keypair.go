package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
)

// keyPairInfo is the inventory and output representation of an EC2 key
// pair. Fingerprint is KeyFingerprint as AWS reports it (padded base64
// SHA-256 for ED25519, colon-separated hexadecimal for RSA). The public key
// itself is never stored or printed.
type keyPairInfo struct {
	Name        string `json:"name" yaml:"name"`
	KeyPairID   string `json:"key_pair_id" yaml:"key_pair_id"`
	Type        string `json:"type" yaml:"type"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Created     string `json:"created" yaml:"created"`
	Region      string `json:"region,omitempty" yaml:"region,omitempty"`
}

func (k keyPairInfo) resource() platform.Resource {
	return platform.Resource{Type: platform.ResKeyPair, ID: k.KeyPairID, Name: k.Name, Data: k}
}

// displayFingerprint is the fingerprint as the table shows it: an ED25519
// fingerprint (base64, no prefix) gets the "SHA256:" prefix OpenSSH uses;
// anything else is shown as AWS reports it.
func (k keyPairInfo) displayFingerprint() string {
	fp := k.Fingerprint
	if k.Type == string(ec2types.KeyTypeEd25519) && fp != "" && !strings.Contains(fp, ":") {
		return "SHA256:" + fp
	}
	return fp
}

// keyPairRecord is a listed key pair with its public key, when AWS returned
// one that parses.
type keyPairRecord struct {
	info      keyPairInfo
	publicKey ssh.PublicKey
}

func keyPairFrom(region string, kp ec2types.KeyPairInfo) keyPairRecord {
	rec := keyPairRecord{info: keyPairInfo{
		Name:        awssdk.ToString(kp.KeyName),
		KeyPairID:   awssdk.ToString(kp.KeyPairId),
		Type:        string(kp.KeyType),
		Fingerprint: awssdk.ToString(kp.KeyFingerprint),
		Region:      region,
	}}
	if kp.CreateTime != nil {
		rec.info.Created = kp.CreateTime.UTC().Format(time.RFC3339)
	}
	if pub := strings.TrimSpace(awssdk.ToString(kp.PublicKey)); pub != "" {
		// A public key that does not parse is left out: the key pair is
		// then matched by its fingerprint.
		if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err == nil {
			rec.publicKey = k
		}
	}
	if rec.info.Type == "" && rec.publicKey != nil {
		switch rec.publicKey.Type() {
		case platform.KeyTypeED25519:
			rec.info.Type = string(ec2types.KeyTypeEd25519)
		case platform.KeyTypeRSA:
			rec.info.Type = string(ec2types.KeyTypeRsa)
		}
	}
	return rec
}

// describeKeyPairs lists every key pair of a region. DescribeKeyPairs is not
// paginated: one call returns them all. With includePublicKey the public
// keys come along (for matching; they are never printed).
func (c *client) describeKeyPairs(ctx context.Context, region string, includePublicKey bool) ([]keyPairRecord, error) {
	if region == "" {
		region = c.region
	}
	in := &ec2.DescribeKeyPairsInput{}
	if includePublicKey {
		in.IncludePublicKey = awssdk.Bool(true)
	}
	out, err := c.ec2For(region).DescribeKeyPairs(ctx, in)
	if err != nil {
		return nil, fmt.Errorf("describe key pairs in %s: %w", region, mapErr(err))
	}
	recs := make([]keyPairRecord, 0, len(out.KeyPairs))
	for _, kp := range out.KeyPairs {
		recs = append(recs, keyPairFrom(region, kp))
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].info.Name < recs[j].info.Name })
	return recs, nil
}

// listKeyPairs returns the key pairs of a region, without public keys.
func (c *client) listKeyPairs(ctx context.Context, region string) ([]keyPairInfo, error) {
	recs, err := c.describeKeyPairs(ctx, region, false)
	if err != nil {
		return nil, err
	}
	out := make([]keyPairInfo, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.info)
	}
	return out, nil
}

// keyPairResources returns the key pairs of a region as inventory resources.
func (c *client) keyPairResources(ctx context.Context, region string) ([]platform.Resource, error) {
	kps, err := c.listKeyPairs(ctx, region)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(kps))
	for _, k := range kps {
		out = append(out, k.resource())
	}
	return out, nil
}

// keyPairLister lists the key pairs of one region for key pair resolution,
// with their public keys. The listing is fetched once.
type keyPairLister struct {
	c      *client
	region string
	pairs  []platform.KeyPair
	done   bool
}

var _ platform.KeyPairLister = (*keyPairLister)(nil)

func (l *keyPairLister) ListKeyPairs(ctx context.Context) ([]platform.KeyPair, error) {
	if l.done {
		return l.pairs, nil
	}
	recs, err := l.c.describeKeyPairs(ctx, l.region, true)
	if err != nil {
		return nil, err
	}
	l.pairs = make([]platform.KeyPair, 0, len(recs))
	for _, r := range recs {
		l.pairs = append(l.pairs, platform.KeyPair{Name: r.info.Name, ID: r.info.KeyPairID, Fingerprint: r.info.Fingerprint, PublicKey: r.publicKey})
	}
	l.done = true
	return l.pairs, nil
}

// KeyInput is the AWS part of key pair resolution: keys are matched by
// their public key (fingerprints as a fallback), and only RSA and ED25519
// keys can be imported.
func keyInputBase() platform.KeyInput {
	return platform.KeyInput{Match: platform.MatchAWS, AllowedTypes: platform.AWSKeyTypes, CheckName: checkKeyPairName}
}

// Errors of ImportKeyPair that are the caller's to correct.
const (
	errKeyPairDuplicate = "InvalidKeyPair.Duplicate"
	errKeyFormat        = "InvalidKey.Format"
)

// importKeyPair imports key under name. tags, when not empty, are set on the
// key pair. A name that is taken (whatever key it holds) and a key AWS
// refuses are usage errors.
func (c *client) importKeyPair(ctx context.Context, region, name string, key *platform.PublicKey, tags map[string]string) (keyPairInfo, error) {
	if region == "" {
		region = c.region
	}
	in := &ec2.ImportKeyPairInput{
		KeyName:           awssdk.String(name),
		PublicKeyMaterial: ssh.MarshalAuthorizedKey(key.Key),
	}
	if len(tags) > 0 {
		keys := make([]string, 0, len(tags))
		for k := range tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		spec := ec2types.TagSpecification{ResourceType: ec2types.ResourceTypeKeyPair}
		for _, k := range keys {
			spec.Tags = append(spec.Tags, ec2types.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
		}
		in.TagSpecifications = []ec2types.TagSpecification{spec}
	}
	out, err := c.ec2For(region).ImportKeyPair(ctx, in)
	if err != nil {
		return keyPairInfo{}, importError(name, region, err)
	}
	info := keyPairInfo{
		Name:        awssdk.ToString(out.KeyName),
		KeyPairID:   awssdk.ToString(out.KeyPairId),
		Fingerprint: awssdk.ToString(out.KeyFingerprint),
		Region:      region,
	}
	if info.Name == "" {
		info.Name = name
	}
	switch key.Type() {
	case platform.KeyTypeED25519:
		info.Type = string(ec2types.KeyTypeEd25519)
	case platform.KeyTypeRSA:
		info.Type = string(ec2types.KeyTypeRsa)
	}
	return info, nil
}

func importError(name, region string, err error) error {
	var ae apiError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case errKeyPairDuplicate:
			return fmt.Errorf("%w: key pair %q already exists in %s (an existing key pair is never replaced): choose another name, or use `polyctl aws ec2 key-pair ensure` to reuse the key pair that holds this key", platform.ErrInvalidInput, name, region)
		case errKeyFormat:
			return fmt.Errorf("%w: AWS refused the public key (%s: %s); AWS imports RSA (2048 bits or more) and ED25519 keys only", platform.ErrInvalidInput, ae.ErrorCode(), strings.TrimSpace(ae.ErrorMessage()))
		}
	}
	return fmt.Errorf("import key pair %s in %s: %w", name, region, mapErr(err))
}
