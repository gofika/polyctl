package aws

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// sharedProfile is a profile of the shared AWS files.
type sharedProfile struct {
	name, region string
	// kinds says how it gets credentials: sso, role, process, keys.
	kinds []string
}

// sharedFiles are the shared config and credentials files, as the SDK
// finds them (AWS_CONFIG_FILE and AWS_SHARED_CREDENTIALS_FILE first).
func sharedFiles() (config, credentials string) {
	home, _ := os.UserHomeDir()
	config, credentials = os.Getenv("AWS_CONFIG_FILE"), os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if config == "" && home != "" {
		config = filepath.Join(home, ".aws", "config")
	}
	if credentials == "" && home != "" {
		credentials = filepath.Join(home, ".aws", "credentials")
	}
	return config, credentials
}

// sharedProfiles lists the profiles of the shared AWS files by name: the
// [default] and [profile <name>] sections of the config file and the
// sections of the credentials file. Other sections (sso-session,
// services) are no profiles. Unreadable files list nothing.
func sharedProfiles() []sharedProfile {
	config, credentials := sharedFiles()
	byName := map[string]*sharedProfile{}
	get := func(name string) *sharedProfile {
		p := byName[name]
		if p == nil {
			p = &sharedProfile{name: name}
			byName[name] = p
		}
		return p
	}
	addKind := func(p *sharedProfile, k string) {
		for _, have := range p.kinds {
			if have == k {
				return
			}
		}
		p.kinds = append(p.kinds, k)
	}
	read := func(path string, isConfig bool) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		var cur *sharedProfile
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				sec := strings.TrimSpace(line[1 : len(line)-1])
				cur = nil
				switch {
				case sec == "default":
					cur = get(sec)
				case isConfig && strings.HasPrefix(sec, "profile "):
					cur = get(strings.TrimSpace(strings.TrimPrefix(sec, "profile ")))
				case !isConfig && sec != "":
					cur = get(sec)
				}
				continue
			}
			if cur == nil {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch k, v = strings.TrimSpace(k), strings.TrimSpace(v); k {
			case "region":
				if isConfig {
					cur.region = v
				}
			case "sso_session", "sso_start_url":
				addKind(cur, "sso")
			case "role_arn":
				addKind(cur, "role")
			case "credential_process":
				addKind(cur, "process")
			case "aws_access_key_id":
				addKind(cur, "keys")
			}
		}
	}
	read(config, true)
	read(credentials, false)
	out := make([]sharedProfile, 0, len(byName))
	for _, p := range byName {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// askSharedProfile asks for the AWS profile of a profile login in the
// interactive flow: the profiles of the shared files (region and kind of
// credentials shown), def preselected, or "Another profile..." typed;
// without shared files the name is typed.
func askSharedProfile(in platform.LoginInput, io *prompt.IO, def string) (string, error) {
	profiles := sharedProfiles()
	if len(profiles) == 0 {
		return io.Line("AWS profile name (from ~/.aws/config)", def)
	}
	var opts []prompt.Option
	for _, p := range profiles {
		opts = append(opts, prompt.Option{Label: joinLabel(p.name, p.region, strings.Join(p.kinds, ",")), Value: p.name})
	}
	const other = "\x00other"
	opts = append(opts, prompt.Option{Label: "Another profile...", Value: other})
	v, err := in.Select(io, "AWS profile (from ~/.aws/config and ~/.aws/credentials)", opts, def)
	if err != nil || v != other {
		return v, err
	}
	return io.Required("AWS profile name")
}

// identityCenterRegions are the commercial regions offered for the
// Identity Center instance; another one can be typed.
var identityCenterRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2", "af-south-1", "ap-east-1", "ap-south-1", "ap-south-2",
	"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ca-central-1", "ca-west-1", "eu-central-1", "eu-central-2", "eu-west-1", "eu-west-2", "eu-west-3", "eu-south-1", "eu-south-2",
	"eu-north-1", "il-central-1", "me-south-1", "me-central-1", "sa-east-1",
}

// askSSORegion asks for the region of the Identity Center instance in the
// interactive flow: a list of the commercial regions, def preselected, or
// "Another region..." typed and checked.
func askSSORegion(in platform.LoginInput, io *prompt.IO, def string) (string, error) {
	var opts []prompt.Option
	for _, r := range identityCenterRegions {
		opts = append(opts, prompt.Option{Label: r, Value: r})
	}
	known := false
	for _, r := range identityCenterRegions {
		known = known || r == def
	}
	if !known && def != "" {
		opts = append([]prompt.Option{{Label: def, Value: def}}, opts...)
	}
	const other = "\x00other"
	opts = append(opts, prompt.Option{Label: "Another region...", Value: other})
	v, err := in.Select(io, "Identity Center region", opts, def)
	if err != nil || v != other {
		return v, err
	}
	for {
		r, err := io.Required("Identity Center region (such as eu-west-1)")
		if err != nil {
			return "", err
		}
		if validRegionName(strings.TrimSpace(r)) {
			return strings.TrimSpace(r), nil
		}
		io.Err.Write([]byte("not a region name such as eu-west-1\n"))
	}
}
