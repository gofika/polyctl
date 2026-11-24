package aliyun

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
)

// keyPairPageSize is the largest page DescribeKeyPairs accepts (50; the
// default is 10, and 51 or more is InvalidParameter).
const keyPairPageSize = 50

// Error codes of ImportKeyPair: a name that is taken (whatever key it
// holds) and a name ECS refuses (shorter than 2 characters, ...).
const (
	errKeyPairExists    = "KeyPair.AlreadyExist"
	errKeyPairMalformed = "InvalidKeyPairName.Malformed"
)

// keyPairInfo is the inventory and output form of an ECS key pair: its
// fingerprint, the MD5 of the key in lower-case hexadecimal without colons
// (the form polyctl has seen). DescribeKeyPairs returns the public key
// itself only when asked (IncludePublicKey, see boundKeyPair); the listing
// leaves it out.
type keyPairInfo struct {
	Name        string `json:"name" yaml:"name"`
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Created     string `json:"created" yaml:"created"`
	Region      string `json:"region" yaml:"region"`
}

// resource is the inventory row; a key pair has no id of its own and its
// name is unique per region only.
func (k keyPairInfo) resource() platform.Resource {
	return platform.Resource{Type: platform.ResKeyPair, ID: k.Region + "/" + k.Name, Name: k.Name, ParentID: k.Region, Data: k}
}

// keyPairTimeLayouts are the forms CreationTime takes: ECS writes minutes
// only ("2026-11-17T13:54Z"); the others are tolerated.
var keyPairTimeLayouts = []string{"2006-01-02T15:04Z", time.RFC3339, "2006-01-02T15:04:05Z"}

// parseKeyPairTime parses a CreationTime; ok is false when no layout fits.
func parseKeyPairTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range keyPairTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func keyPairFrom(region string, kp ecs.KeyPair) keyPairInfo {
	created := kp.CreationTime
	if t, ok := parseKeyPairTime(created); ok {
		created = t.Format(time.RFC3339)
	}
	return keyPairInfo{Name: kp.KeyPairName, Fingerprint: strings.ToLower(kp.KeyPairFingerPrint), Created: created, Region: region}
}

// listKeyPairs lists the key pairs of a region, every page; name keeps the
// key pair of that name (an exact match: callers refuse names holding *,
// which ECS reads as a wildcard), fingerprint the key pairs of that MD5
// fingerprint (hexadecimal without colons, which is the only form ECS
// filters by).
func (c *client) listKeyPairs(ctx context.Context, region, name, fingerprint string) ([]keyPairInfo, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []keyPairInfo
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeKeyPairsRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(keyPairPageSize)
		req.KeyPairName = name
		req.KeyPairFingerPrint = strings.ReplaceAll(fingerprint, ":", "")
		resp, err := cl.DescribeKeyPairs(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeKeyPairs "+region, err)
		}
		for _, kp := range resp.KeyPairs.KeyPair {
			if name != "" && kp.KeyPairName != name {
				continue
			}
			out = append(out, keyPairFrom(region, kp))
		}
		if len(resp.KeyPairs.KeyPair) == 0 || page*keyPairPageSize >= resp.TotalCount {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// boundKeyPair reads the key pair name of a region with its public key
// (DescribeKeyPairs with IncludePublicKey=true), to match the local keys
// of an instance bound to it: nil and why when it cannot be read. A public
// key that is missing or cannot be parsed leaves the fingerprint to match.
func (c *client) boundKeyPair(ctx context.Context, region, name string) (*platform.KeyPair, string) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err.Error()
	}
	req := ecs.CreateDescribeKeyPairsRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.KeyPairName = name
	req.IncludePublicKey = requests.NewBoolean(true)
	req.PageSize = requests.NewInteger(keyPairPageSize)
	resp, err := cl.DescribeKeyPairs(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeKeyPairs "+region, err).Error()
	}
	for _, kp := range resp.KeyPairs.KeyPair {
		// KeyPairName filters with wildcards: keep the exact name.
		if kp.KeyPairName != name {
			continue
		}
		out := &platform.KeyPair{Name: kp.KeyPairName, ID: kp.KeyPairName, Fingerprint: strings.ToLower(kp.KeyPairFingerPrint)}
		if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(kp.PublicKey)); err == nil {
			out.PublicKey = pk
		}
		return out, ""
	}
	return nil, "no key pair of that name in " + region
}

// importKeyPair imports a public key as the key pair name. Only the key
// itself is sent, not its comment.
func (c *client) importKeyPair(ctx context.Context, region, name string, key *platform.PublicKey) (keyPairInfo, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return keyPairInfo{}, err
	}
	req := ecs.CreateImportKeyPairRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.KeyPairName = name
	req.PublicKeyBody = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.Key)))
	resp, err := cl.ImportKeyPair(req)
	if err != nil {
		return keyPairInfo{}, wrapErr("ecs ImportKeyPair "+name, err)
	}
	fp := strings.ToLower(resp.KeyPairFingerPrint)
	if fp == "" {
		fp = key.FingerprintMD5Hex()
	}
	out := keyPairInfo{Name: name, Fingerprint: fp, Created: time.Now().UTC().Truncate(time.Minute).Format(time.RFC3339), Region: region}
	if resp.KeyPairName != "" {
		out.Name = resp.KeyPairName
	}
	return out, nil
}

// keyPairResources lists the key pairs of a region for the inventory.
func (c *client) keyPairResources(ctx context.Context, region string) ([]platform.Resource, error) {
	kps, err := c.listKeyPairs(ctx, region, "", "")
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(kps))
	for _, k := range kps {
		out = append(out, k.resource())
	}
	return out, nil
}

// keyPairLister feeds platform.ResolveKeyPair. With a public key it asks
// ECS for the key pairs of its fingerprint first (one request), adding the
// key pair named on the command line; when none holds the key it falls
// back to the whole listing, which also tells whether the name is taken.
type keyPairLister struct {
	c      *client
	region string
	key    *platform.PublicKey
	name   string
}

func (l *keyPairLister) ListKeyPairs(ctx context.Context) ([]platform.KeyPair, error) {
	var kps []keyPairInfo
	var err error
	switch {
	case l.key != nil:
		if kps, err = l.c.listKeyPairs(ctx, l.region, "", l.key.FingerprintMD5Hex()); err != nil {
			return nil, err
		}
		if len(kps) == 0 {
			if kps, err = l.c.listKeyPairs(ctx, l.region, "", ""); err != nil {
				return nil, err
			}
		} else if l.name != "" {
			named, err := l.c.listKeyPairs(ctx, l.region, l.name, "")
			if err != nil {
				return nil, err
			}
			for _, n := range named {
				if !containsKeyPair(kps, n.Name) {
					kps = append(kps, n)
				}
			}
		}
	case l.name != "":
		if kps, err = l.c.listKeyPairs(ctx, l.region, l.name, ""); err != nil {
			return nil, err
		}
	default:
		if kps, err = l.c.listKeyPairs(ctx, l.region, "", ""); err != nil {
			return nil, err
		}
	}
	out := make([]platform.KeyPair, 0, len(kps))
	for _, k := range kps {
		out = append(out, platform.KeyPair{Name: k.Name, ID: k.Name, Fingerprint: k.Fingerprint})
	}
	return out, nil
}

func containsKeyPair(kps []keyPairInfo, name string) bool {
	for _, k := range kps {
		if k.Name == name {
			return true
		}
	}
	return false
}
