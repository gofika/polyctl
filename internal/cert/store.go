package cert

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

// Well-known ACME directories.
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Files of a bundle directory.
const (
	fileFullchain = "fullchain.pem"
	fileCert      = "cert.pem"
	fileChain     = "chain.pem"
	filePrivKey   = "privkey.pem"
	fileMeta      = "meta.json"
)

// archiveKeep is how many replaced bundles the archive of a domain keeps.
const archiveKeep = 3

// Store is the local certificate store of one ACME directory:
//
//	<dir>/                      0700
//	  accounts/<ca host>/<id>/  account.json, account.key (0600)
//	  live/<root>/              fullchain.pem cert.pem chain.pem privkey.pem (0600) meta.json
//	  archive/<root>/<time>/    the bundles live/<root> held before (the last 3)
//	  pending/<root>/           privkey.pem of an issuance in progress
//	  locks/<root>.lock         serializes the issuance of one root domain
//	  history.log               one JSON line per certificate created or updated
//	  ca/<host>/...             accounts, live, archive and pending of any
//	                            other ACME directory (staging included)
//
// Only the default directory (Let's Encrypt production) uses the top-level
// live/, so a staging certificate can never be mistaken for a trusted one.
type Store struct {
	// Dir is the root of the store (cert.dir).
	Dir string
	// Base holds accounts, live, archive and pending of Directory.
	Base string
	// Directory is the ACME directory URL the store is for.
	Directory string
	// Warnf reports a repaired or suspicious state (nil: silent).
	Warnf func(format string, args ...any)
	// Now is the clock (nil: time.Now).
	Now func() time.Time
}

// OpenStore returns the store under dir for an ACME directory. Nothing is
// created until something is written.
func OpenStore(dir, directory string) *Store {
	s := &Store{Dir: dir, Base: dir, Directory: directory}
	if directory != LetsEncryptProduction {
		s.Base = filepath.Join(dir, "ca", directorySlug(directory))
	}
	return s
}

// directorySlug names the subtree of a non-default ACME directory: its
// host name (with the port, if any, joined by an underscore).
func directorySlug(directory string) string {
	u, err := url.Parse(directory)
	if err != nil || u.Host == "" {
		sum := sha256.Sum256([]byte(directory))
		return "dir-" + hex.EncodeToString(sum[:6])
	}
	return strings.ReplaceAll(strings.ToLower(u.Host), ":", "_")
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) warnf(format string, args ...any) {
	if s.Warnf != nil {
		s.Warnf(format, args...)
	}
}

// LivePath is the directory of the current bundle of root.
func (s *Store) LivePath(root string) string { return filepath.Join(s.Base, "live", root) }

func (s *Store) archivePath(root string) string { return filepath.Join(s.Base, "archive", root) }

// PendingKeyPath is the private key of an issuance of root in progress.
func (s *Store) PendingKeyPath(root string) string {
	return filepath.Join(s.Base, "pending", root, filePrivKey)
}

// LockPath is the lock file of root.
func (s *Store) LockPath(root string) string { return filepath.Join(s.Dir, "locks", root+".lock") }

func (s *Store) historyPath() string { return filepath.Join(s.Dir, "history.log") }

// meta is meta.json of a bundle.
type meta struct {
	Names         []string `json:"names"`
	Serial        string   `json:"serial"`
	NotAfter      string   `json:"not_after"`
	KeyType       string   `json:"key_type"`
	IssuedAt      string   `json:"issued_at"`
	ACMEDirectory string   `json:"acme_directory"`
}

// Load reads the bundle of root, or returns nil when the store has none.
// The bundle is checked: certificate and key must parse and belong
// together, otherwise the error is ErrCorrupt. With repair, a private key
// readable by others is made 0600, and a live directory that is missing
// while the archive holds a bundle (an interrupted replacement) is
// restored from the newest archived one; both are reported through Warnf.
// Without repair nothing is written: the same states are only reported, and
// the archived bundle is returned from where it is.
func (s *Store) Load(root string, repair bool) (*Bundle, error) {
	live := s.LivePath(root)
	if _, err := os.Stat(live); errors.Is(err, fs.ErrNotExist) {
		latest, err := s.latestArchive(root)
		if err != nil || latest == "" {
			return nil, err
		}
		if !repair {
			s.warnf("warning: %s is missing; the newest archived certificate %s is used (the next `cert ensure` restores it)", live, latest)
			b, err := s.loadDir(root, latest, false)
			if b != nil {
				b.NeedsRepair = true
			}
			return b, err
		}
		if err := os.MkdirAll(filepath.Dir(live), 0o700); err != nil {
			return nil, err
		}
		if err := os.Rename(latest, live); err != nil {
			return nil, fmt.Errorf("restore %s from %s: %w", live, latest, err)
		}
		s.warnf("warning: %s was missing (an interrupted replacement); restored it from %s", live, latest)
	} else if err != nil {
		return nil, err
	}
	return s.loadDir(root, live, repair)
}

func (s *Store) loadDir(root, dir string, repair bool) (*Bundle, error) {
	fullchain, err := os.ReadFile(filepath.Join(dir, fileFullchain))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	keyPath := filepath.Join(dir, filePrivKey)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	badMode := false
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(keyPath); err == nil && fi.Mode().Perm()&0o077 != 0 {
			badMode = !repair
			if repair {
				if err := os.Chmod(keyPath, 0o600); err != nil {
					return nil, err
				}
				s.warnf("warning: %s was readable by others (mode %04o); changed it to 0600", keyPath, fi.Mode().Perm())
			} else {
				s.warnf("warning: %s is readable by others (mode %04o); it should be 0600", keyPath, fi.Mode().Perm())
			}
		}
	}
	b, err := NewBundle(root, fullchain, key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dir, err)
	}
	b.Path, b.NeedsRepair = dir, badMode
	if data, err := os.ReadFile(filepath.Join(dir, fileMeta)); err == nil {
		var m meta
		if json.Unmarshal(data, &m) == nil {
			b.IssuedAt, _ = time.Parse(time.RFC3339, m.IssuedAt)
			b.ACMEDirectory = m.ACMEDirectory
		}
	}
	return b, nil
}

// latestArchive returns the newest archived bundle directory of root, or
// "" when there is none.
func (s *Store) latestArchive(root string) (string, error) {
	names, err := s.archiveNames(root)
	if err != nil || len(names) == 0 {
		return "", err
	}
	return filepath.Join(s.archivePath(root), names[len(names)-1]), nil
}

// archiveNames lists the archived bundles of root, oldest first.
func (s *Store) archiveNames(root string) ([]string, error) {
	entries, err := os.ReadDir(s.archivePath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

// List returns the root domains that have a live bundle.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.Base, "live"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// Save makes b the live bundle of its domain. The five files are written
// to a staging directory first; the current live directory is then moved
// to the archive and the staging directory renamed in its place, so a
// reader sees either the old bundle or the new one. The archive keeps the
// newest archiveKeep bundles, and the pending key of the domain is removed.
func (s *Store) Save(b *Bundle) error {
	root := b.Domain
	liveDir := filepath.Join(s.Base, "live")
	if err := mkdirs(s.Dir, liveDir); err != nil {
		return err
	}
	staging := filepath.Join(liveDir, fmt.Sprintf(".%s.staging-%d", root, os.Getpid()))
	_ = os.RemoveAll(staging)
	if err := os.Mkdir(staging, 0o700); err != nil {
		return err
	}
	now := s.now().UTC()
	m := meta{Names: b.Names, Serial: b.Serial, NotAfter: b.NotAfter.Format(time.RFC3339), KeyType: b.KeyType,
		IssuedAt: now.Format(time.RFC3339), ACMEDirectory: s.Directory}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{fileFullchain, b.FullchainPEM, 0o644},
		{fileCert, b.CertPEM, 0o644},
		{fileChain, b.ChainPEM, 0o644},
		{filePrivKey, b.PrivKeyPEM, 0o600},
		{fileMeta, append(mj, '\n'), 0o644},
	}
	for _, f := range files {
		if err := writeFileSync(filepath.Join(staging, f.name), f.data, f.perm); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
	}
	live := s.LivePath(root)
	if _, err := os.Stat(live); err == nil {
		arch := s.archivePath(root)
		if err := os.MkdirAll(arch, 0o700); err != nil {
			_ = os.RemoveAll(staging)
			return err
		}
		dst := filepath.Join(arch, now.Format("20060102T150405Z"))
		for i := 1; ; i++ {
			if _, err := os.Stat(dst); errors.Is(err, fs.ErrNotExist) {
				break
			}
			dst = filepath.Join(arch, fmt.Sprintf("%s-%d", now.Format("20060102T150405Z"), i))
		}
		if err := os.Rename(live, dst); err != nil {
			_ = os.RemoveAll(staging)
			return fmt.Errorf("archive %s: %w", live, err)
		}
	}
	if err := os.Rename(staging, live); err != nil {
		return fmt.Errorf("install %s: %w", live, err)
	}
	b.Path, b.IssuedAt, b.ACMEDirectory = live, now, s.Directory
	if names, err := s.archiveNames(root); err == nil && len(names) > archiveKeep {
		for _, n := range names[:len(names)-archiveKeep] {
			_ = os.RemoveAll(filepath.Join(s.archivePath(root), n))
		}
	}
	_ = os.RemoveAll(filepath.Dir(s.PendingKeyPath(root)))
	return nil
}

// LoadPendingKey returns the key a previous, interrupted issuance of root
// left behind, or nil.
func (s *Store) LoadPendingKey(root string) (crypto.Signer, error) {
	data, err := os.ReadFile(s.PendingKeyPath(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(data)
}

// SavePendingKey writes the key of an issuance of root before the CA is
// asked for the certificate, so a certificate the CA issued can still be
// matched with its key when saving it fails.
func (s *Store) SavePendingKey(root string, key crypto.Signer) error {
	data, err := MarshalPrivateKey(key)
	if err != nil {
		return err
	}
	path := s.PendingKeyPath(root)
	if err := mkdirs(s.Dir, filepath.Dir(path)); err != nil {
		return err
	}
	return writeFileSync(path, data, 0o600)
}

// HistoryEntry is one line of history.log.
type HistoryEntry struct {
	Time          string `json:"time"`
	Action        string `json:"action"`
	Domain        string `json:"domain"`
	Serial        string `json:"serial,omitempty"`
	NotAfter      string `json:"not_after,omitempty"`
	ACMEDirectory string `json:"acme_directory,omitempty"`
	// Target names where a certificate was deployed (cert deploy), with
	// the deployer, the profile, the name the certificate got there and
	// the days it had left.
	Target   string `json:"target,omitempty"`
	Deployer string `json:"deployer,omitempty"`
	Profile  string `json:"profile,omitempty"`
	CertName string `json:"cert_name,omitempty"`
	DaysLeft *int   `json:"days_left,omitempty"`
}

// AppendHistory adds a line to history.log.
func (s *Store) AppendHistory(e HistoryEntry) error {
	if e.Time == "" {
		e.Time = s.now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if err := mkdirs(s.Dir); err != nil {
		return err
	}
	f, err := os.OpenFile(s.historyPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// mkdirs creates directories with mode 0700.
func mkdirs(dirs ...string) error {
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// writeFileSync writes a file with perm and flushes it to disk.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// The mode of an existing file is not changed by OpenFile.
	return os.Chmod(path, perm)
}
