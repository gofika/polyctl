// Package dnstest runs fake DNS resolvers on 127.0.0.1 for tests, so that
// code which queries resolvers never needs the network.
package dnstest

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Answer is what the fake resolver answers to an NS query of one name.
type Answer struct {
	// Rcode is the response code (dns.RcodeSuccess when zero).
	Rcode int
	// NS are the nameservers of the answer section.
	NS []string
	// SOA, when set, puts an SOA record owned by this name in the authority
	// section (what a recursive resolver sends with a NODATA answer).
	SOA string
	// Truncate answers over UDP with the TC bit and no records; the full
	// answer is given over TCP only.
	Truncate bool
}

// Server is a fake resolver listening on UDP and TCP of one port.
type Server struct {
	// Addr is the host:port of the server.
	Addr string

	mu       sync.Mutex
	answers  map[string]Answer
	udp, tcp int
}

// Start runs a fake resolver until the test ends. Names are matched without
// case or trailing dot; a name without an answer is NXDOMAIN.
func Start(t testing.TB, answers map[string]Answer) *Server { return start(t, answers, false) }

// StartUDPOnly is Start without the TCP listener: a truncated answer then
// cannot be retried over TCP.
func StartUDPOnly(t testing.TB, answers map[string]Answer) *Server {
	return start(t, answers, true)
}

func start(t testing.TB, answers map[string]Answer, noTCP bool) *Server {
	t.Helper()
	s := &Server{answers: map[string]Answer{}}
	for k, v := range answers {
		s.answers[norm(k)] = v
	}
	for range 20 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		var l net.Listener
		if !noTCP {
			if l, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
				pc.Close()
				continue
			}
		}
		s.Addr = fmt.Sprintf("127.0.0.1:%d", port)
		s.serve(t, &dns.Server{PacketConn: pc, Handler: s.handler(false)})
		if l != nil {
			s.serve(t, &dns.Server{Listener: l, Handler: s.handler(true)})
		}
		return s
	}
	t.Fatal("dnstest: no free port for UDP and TCP")
	return nil
}

func (s *Server) serve(t testing.TB, srv *dns.Server) {
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
}

// Set replaces the answer for name.
func (s *Server) Set(name string, a Answer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers[norm(name)] = a
}

// Queries returns how many queries the server got over UDP and TCP.
func (s *Server) Queries() (udp, tcp int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp, s.tcp
}

func (s *Server) handler(tcp bool) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		s.mu.Lock()
		if tcp {
			s.tcp++
		} else {
			s.udp++
		}
		var a Answer
		ok := false
		if len(req.Question) == 1 {
			a, ok = s.answers[norm(req.Question[0].Name)]
		}
		s.mu.Unlock()
		switch {
		case !ok:
			m.Rcode = dns.RcodeNameError
		case a.Truncate && !tcp:
			m.Truncated = true
		default:
			m.Rcode = a.Rcode
			q := req.Question[0]
			for _, n := range a.NS {
				m.Answer = append(m.Answer, &dns.NS{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  dns.Fqdn(n),
				})
			}
			if a.SOA != "" {
				m.Ns = append(m.Ns, &dns.SOA{
					Hdr:     dns.RR_Header{Name: dns.Fqdn(a.SOA), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
					Ns:      "ns1." + dns.Fqdn(a.SOA),
					Mbox:    "hostmaster." + dns.Fqdn(a.SOA),
					Serial:  1,
					Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
				})
			}
		}
		_ = w.WriteMsg(m)
	}
}

// Silent returns the address of a UDP socket that reads queries and never
// answers them: a resolver that times out.
func Silent(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr().String()
}

func norm(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }
