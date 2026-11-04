// Package httpx is a tiny JSON REST helper shared by providers that talk to
// plain HTTP APIs (Cloudflare, name.com, GoDaddy).
package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// UserAgent is sent with every request.
var UserAgent = "polyctl/dev"

// Client is a base-URL bound JSON client.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// Prepare adds authentication to each request.
	Prepare func(r *http.Request)
	// MaxRetries for 429/5xx responses.
	MaxRetries int
}

// New returns a client with sane defaults.
func New(baseURL string, prepare func(*http.Request)) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP: &http.Client{
			Timeout: 60 * time.Second,
			// REST APIs do not redirect; following one would resend the
			// Authorization header (possibly over plain http) and turn a
			// POST into a bodiless GET. Surface 3xx as an error instead.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		Prepare:    prepare,
		MaxRetries: 3,
	}
}

// Error is a non-2xx response.
type Error struct {
	Status int
	Method string
	URL    string
	Body   string
}

func (e *Error) Error() string {
	body := e.Body
	if len(body) > 400 {
		body = body[:400] + "..."
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.Status, strings.TrimSpace(body))
}

// Unwrap maps 401/403 to platform.ErrUnauthorized and 404 to platform.ErrNotFound.
func (e *Error) Unwrap() error {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return platform.ErrUnauthorized
	case http.StatusNotFound:
		return platform.ErrNotFound
	}
	return nil
}

// idempotentMethods may be retried after a transport error or a 5xx: the
// server may have processed the first attempt, but repeating it is harmless.
// POST/PATCH are not in the list, so a timed-out create is never duplicated.
var idempotentMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// Do performs a JSON request. in (if non-nil) is marshalled as the body; out
// (if non-nil) receives the decoded response body. Query parameters are appended.
//
// 429 responses are retried for every method (the server did not process the
// request); transport errors and 5xx responses only for idempotent methods.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt*attempt) * 500 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", UserAgent)
		if in != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.Prepare != nil {
			c.Prepare(req)
		}
		idempotent := idempotentMethods[method]
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if !idempotent {
				return err
			}
			lastErr = err
			continue
		}
		rb, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil {
			if !idempotent {
				return err
			}
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && idempotent) {
			lastErr = &Error{Status: resp.StatusCode, Method: method, URL: u, Body: string(rb)}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &Error{Status: resp.StatusCode, Method: method, URL: u, Body: string(rb)}
		}
		if out != nil && len(bytes.TrimSpace(rb)) > 0 {
			if err := json.Unmarshal(rb, out); err != nil {
				return fmt.Errorf("decode %s %s: %w", method, u, err)
			}
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return lastErr
}

// Get is a GET helper.
func (c *Client) Get(ctx context.Context, path string, query url.Values, out any) error {
	return c.Do(ctx, http.MethodGet, path, query, nil, out)
}
