package cert

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// lockRetry is how often a held lock is tried again.
var lockRetry = time.Second

// Lock takes the exclusive lock of root, waiting until ctx ends. Two
// polyctl processes (a cron job and a manual run, two deployments) never
// issue a certificate for the same root domain at the same time; different
// root domains do not wait for each other. The returned function releases
// the lock.
func (s *Store) Lock(ctx context.Context, root string) (func(), error) {
	path := s.LockPath(root)
	if err := mkdirs(s.Dir, filepath.Dir(path)); err != nil {
		return nil, err
	}
	fl := flock.New(path)
	ok, err := fl.TryLockContext(ctx, lockRetry)
	if err != nil || !ok {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || err == nil {
			return nil, fmt.Errorf("another polyctl process is issuing the certificate of %s (lock %s); try again later", root, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { _ = fl.Unlock() }, nil
}
