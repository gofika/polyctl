package cert

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/gofika/polyctl/internal/platform"
)

// ErrAccountNotFound is returned by Issuer.ResolveAccount when the CA does
// not know the account key (it was never registered, or was deactivated).
var ErrAccountNotFound = errors.New("the CA does not know this account")

// ObtainRequest is one certificate order.
type ObtainRequest struct {
	// Domains are the names of the certificate; the first is the subject.
	Domains []string
	// Key is the certificate's private key (already saved as pending).
	Key     crypto.Signer
	KeyType string
	// Provider writes the challenge records; Propagation decides when they
	// are visible.
	Provider    *DNSProvider
	Propagation *Propagation
	// Resolvers are the recursive resolvers (host:port) the ACME library
	// may ask while solving.
	Resolvers []string
	// CertTimeout bounds the wait for the certificate after the order was
	// finalized.
	CertTimeout time.Duration
}

// Issuer is the ACME CA as `cert ensure` uses it.
type Issuer interface {
	// ResolveAccount returns the URI of the account of a.Key at the CA, or
	// ErrAccountNotFound.
	ResolveAccount(ctx context.Context, a *Account) (string, error)
	// Register registers a.Key with a.Email, agreeing to the terms of
	// service, and returns the account URI.
	Register(ctx context.Context, a *Account) (string, error)
	// Obtain orders a certificate, solving its authorizations with DNS-01,
	// and returns the full chain (leaf first) as PEM.
	Obtain(ctx context.Context, a *Account, req ObtainRequest) ([]byte, error)
}

// LegoIssuer is the Issuer of an ACME directory, implemented with lego.
type LegoIssuer struct {
	Directory string
	// HTTPClient talks to the CA (nil: lego's default client).
	HTTPClient *http.Client
	UserAgent  string
	// Verbosef receives lego's progress log (nil: discarded).
	Verbosef func(format string, args ...any)
}

// legoUser is an account as lego sees it.
type legoUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *legoUser) GetEmail() string                        { return u.email }
func (u *legoUser) GetRegistration() *registration.Resource { return u.reg }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// legoLogMu serializes the redirection of lego's global logger.
var legoLogMu sync.Mutex

// logWriter forwards lego's log lines to a Verbosef.
type logWriter struct{ f func(string, ...any) }

func (l logWriter) out(s string) {
	if l.f != nil {
		l.f("acme: %s", strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "[INFO]")))
	}
}
func (l logWriter) Fatal(args ...any)                 { l.out(fmt.Sprint(args...)) }
func (l logWriter) Fatalln(args ...any)               { l.out(fmt.Sprintln(args...)) }
func (l logWriter) Fatalf(format string, args ...any) { l.out(fmt.Sprintf(format, args...)) }
func (l logWriter) Print(args ...any)                 { l.out(fmt.Sprint(args...)) }
func (l logWriter) Println(args ...any)               { l.out(fmt.Sprintln(args...)) }
func (l logWriter) Printf(format string, args ...any) { l.out(fmt.Sprintf(format, args...)) }

// RedirectLegoLog sends lego's log (which goes to stderr by default) to f,
// or discards it when f is nil.
func RedirectLegoLog(f func(string, ...any)) {
	legoLogMu.Lock()
	defer legoLogMu.Unlock()
	legolog.Logger = logWriter{f: f}
}

func (l *LegoIssuer) client(a *Account, keyType string, certTimeout time.Duration) (*lego.Client, error) {
	u := &legoUser{email: a.Email, key: a.Key}
	if a.URI != "" {
		u.reg = &registration.Resource{URI: a.URI}
	}
	cfg := lego.NewConfig(u)
	cfg.CADirURL = l.Directory
	if l.HTTPClient != nil {
		cfg.HTTPClient = l.HTTPClient
	}
	if l.UserAgent != "" {
		cfg.UserAgent = l.UserAgent
	}
	if kt, ok := legoKeyTypes[keyType]; ok {
		cfg.Certificate.KeyType = kt
	}
	if certTimeout > 0 {
		cfg.Certificate.Timeout = certTimeout
	}
	RedirectLegoLog(l.Verbosef)
	return lego.NewClient(cfg)
}

// legoKeyTypes maps --key-type to lego's key types.
var legoKeyTypes = map[string]certcrypto.KeyType{
	KeyEC256:   certcrypto.EC256,
	KeyEC384:   certcrypto.EC384,
	KeyRSA2048: certcrypto.RSA2048,
	KeyRSA4096: certcrypto.RSA4096,
}

// ResolveAccount looks the account key up at the CA (newAccount with
// onlyReturnExisting).
func (l *LegoIssuer) ResolveAccount(ctx context.Context, a *Account) (string, error) {
	return runCtx(ctx, func() (string, error) {
		// The lookup is by key: the request carries the key itself, not
		// the account URI the store may hold.
		c, err := l.client(&Account{Email: a.Email, Key: a.Key}, "", 0)
		if err != nil {
			return "", err
		}
		res, err := c.Registration.ResolveAccountByKey()
		if err != nil {
			var pd *acme.ProblemDetails
			if errors.As(err, &pd) && strings.HasSuffix(pd.Type, ":accountDoesNotExist") {
				return "", ErrAccountNotFound
			}
			return "", err
		}
		return res.URI, nil
	})
}

// Register registers the account, agreeing to the terms of service.
func (l *LegoIssuer) Register(ctx context.Context, a *Account) (string, error) {
	return runCtx(ctx, func() (string, error) {
		// newAccount is signed with the key itself (RFC 8555 section 7.3):
		// lego would sign with the account URI as kid when it has one, and
		// a URI the store kept from an account the CA forgot is refused.
		c, err := l.client(&Account{Email: a.Email, Key: a.Key}, "", 0)
		if err != nil {
			return "", err
		}
		res, err := c.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return "", registrationError(err)
		}
		return res.URI, nil
	})
}

// Obtain orders the certificate. lego presents the challenges of every
// authorization first, then validates them one by one, then cleans up.
func (l *LegoIssuer) Obtain(ctx context.Context, a *Account, req ObtainRequest) ([]byte, error) {
	return runCtx(ctx, func() ([]byte, error) {
		c, err := l.client(a, req.KeyType, req.CertTimeout)
		if err != nil {
			return nil, err
		}
		opts := []dns01.ChallengeOption{
			dns01.WrapPreCheck(req.Propagation.Check),
			dns01.DisableAuthoritativeNssPropagationRequirement(),
		}
		if len(req.Resolvers) > 0 {
			opts = append(opts, dns01.AddRecursiveNameservers(req.Resolvers))
		}
		if err := c.Challenge.SetDNS01Provider(req.Provider, opts...); err != nil {
			return nil, err
		}
		res, err := c.Certificate.Obtain(certificate.ObtainRequest{
			Domains:    req.Domains,
			Bundle:     true,
			PrivateKey: req.Key,
		})
		if err != nil {
			return nil, err
		}
		return res.Certificate, nil
	})
}

// runCtx runs a call of lego (which takes no context) and returns early
// with the context's error when ctx ends first. The call itself stops soon
// after: the DNS provider and the propagation check use ctx too.
func runCtx[T any](ctx context.Context, f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// registrationError turns the CA's refusal of a contact address or of the
// missing agreement into invalid input (exit code 2), with the CA's own
// detail.
func registrationError(err error) error {
	var pd *acme.ProblemDetails
	if !errors.As(err, &pd) {
		return err
	}
	switch {
	case strings.HasSuffix(pd.Type, ":invalidContact"), strings.HasSuffix(pd.Type, ":unsupportedContact"),
		strings.HasSuffix(pd.Type, ":invalidEmail"):
		return fmt.Errorf("%w: the CA refused the e-mail address (set a working address with --email or cert.email): %s", platform.ErrInvalidInput, pd.Detail)
	case strings.HasSuffix(pd.Type, ":malformed"):
		d := strings.ToLower(pd.Detail)
		if strings.Contains(d, "email") || strings.Contains(d, "contact") || strings.Contains(d, "public suffix") || strings.Contains(d, "terms of service") {
			return fmt.Errorf("%w: the CA refused the registration: %s", platform.ErrInvalidInput, pd.Detail)
		}
	}
	return err
}

// describeObtainError adds what helps to a failed issuance: the DNSSEC
// advice, the CA's Retry-After of a rate limit, the last values each
// resolver saw on a propagation timeout, and where the pending key is.
func describeObtainError(err error, prop *Propagation, pendingKey string) error {
	var b strings.Builder
	var rl *acme.RateLimitedError
	var pd *acme.ProblemDetails
	switch {
	case errors.As(err, &rl):
		fmt.Fprintf(&b, "the CA rate-limited the request (%s): %s", rl.Type, rl.Detail)
		if rl.RetryAfter != "" {
			fmt.Fprintf(&b, "; retry after %s", rl.RetryAfter)
		}
		b.WriteString("; polyctl does not retry on its own")
	case errors.As(err, &pd) && strings.Contains(strings.ToUpper(pd.Detail), "DNSSEC"):
		fmt.Fprintf(&b, "certificate request failed: DNSSEC misconfiguration\n  %s\n", pd.Detail)
		b.WriteString("Retrying will not help. Either remove the DS record at the registrar to disable DNSSEC,\n")
		b.WriteString("or enable DNSSEC correctly at the DNS host; wait for the change to take effect, then run again")
	case errors.As(err, &pd):
		fmt.Fprintf(&b, "certificate request failed (%s): %s", pd.Type, pd.Detail)
	default:
		b.WriteString("certificate request failed: ")
		b.WriteString(err.Error())
	}
	if strings.Contains(err.Error(), "propagation") && strings.Contains(err.Error(), "time limit exceeded") && prop != nil {
		if s := prop.Summary(); s != "" {
			fmt.Fprintf(&b, "; last seen by the resolvers: %s", s)
		}
		b.WriteString(" (a TTL cache or nameservers that do not point to the hosting account; try again later)")
	}
	if pendingKey != "" {
		fmt.Fprintf(&b, "; the private key of this attempt is kept at %s and is used again by the next run", pendingKey)
	}
	return &obtainError{msg: b.String(), err: err}
}

// obtainError keeps the original error reachable (errors.Is / As) under a
// message that explains it.
type obtainError struct {
	msg string
	err error
}

func (e *obtainError) Error() string { return e.msg }
func (e *obtainError) Unwrap() error { return e.err }
