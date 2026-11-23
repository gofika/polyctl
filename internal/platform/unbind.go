package platform

import "context"

// RecordUnbinder is implemented by DNS clients whose zones can hold records
// that belong to another service of the platform and cannot be deleted
// through the DNS API (the CNAME Cloudflare creates for the custom domain
// of an R2 bucket). Deleting such a record means unbinding it from that
// service, which then removes the record itself.
type RecordUnbinder interface {
	// Match reports whether rec is owned by another service; owner then
	// names it for people ("r2 bucket assets").
	Match(zone Zone, rec Record) (owner string, ok bool)
	// Unbind releases the record from its owner. handled=true means the
	// binding is gone and the platform removes the record by itself: the
	// caller must not delete it as well. handled=false (with the reason in
	// err) means it could not be unbound; such a record cannot be deleted
	// through the DNS API either, so the caller leaves it alone and reports
	// the failure.
	Unbind(ctx context.Context, zone Zone, rec Record) (handled bool, err error)
}

// Peer is another account on the same platform, opened.
type Peer struct {
	Profile string
	Client  Client
}

// PeerAware is implemented by clients that may have to act through the
// other accounts of their platform (an R2 bucket that lives in another
// Cloudflare account than the zone). The runtime hands them a function that
// opens those accounts on demand.
type PeerAware interface {
	SetPeers(peers func(ctx context.Context) ([]Peer, error))
}
