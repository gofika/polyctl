package gcp

import (
	"testing"

	"google.golang.org/api/compute/v1"
)

func TestLBNameOf(t *testing.T) {
	maps := map[string]string{"projects/p/regions/r/targetHttpProxies/old-proxy": "old-lb"}
	for _, c := range []struct {
		fr   *compute.ForwardingRule
		want string
	}{
		{&compute.ForwardingRule{Name: "fr-web-1", Labels: map[string]string{lbLabel: "lb-web-1"}, Target: apiBase + "projects/p/regions/r/targetHttpProxies/old-proxy"}, "lb-web-1"},
		{&compute.ForwardingRule{Name: "old-fr", Target: apiBase + "projects/p/regions/r/targetHttpProxies/old-proxy"}, "old-lb"},
		{&compute.ForwardingRule{Name: "fr-tcp", Target: apiBase + "projects/p/regions/r/targetTcpProxies/x"}, "fr-tcp"},
	} {
		if got := lbNameOf(c.fr, maps); got != c.want {
			t.Errorf("lbNameOf(%s) = %s, want %s", c.fr.Name, got, c.want)
		}
	}
}
