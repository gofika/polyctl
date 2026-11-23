package platform

import "testing"

func TestParseTarget(t *testing.T) {
	ok := map[string]LBTargetSpec{
		"i-0123456789abcdef0":    {ID: "i-0123456789abcdef0"},
		"i-0123456789abcdef0:80": {ID: "i-0123456789abcdef0", Port: 80},
		" 10.0.1.5:https ":       {ID: "10.0.1.5", Port: 443},
		"2001:db8::1":            {ID: "2001:db8::1"},
		"[2001:db8::1]:8080":     {ID: "2001:db8::1", Port: 8080},
		"[2001:db8::1]":          {ID: "2001:db8::1"},
	}
	for in, want := range ok {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"", ":80", "i-1:0", "i-1:x", "[2001:db8::1", "[2001:db8::1]80"} {
		if _, err := ParseTarget(in); err == nil {
			t.Errorf("ParseTarget(%q) accepted", in)
		}
	}
	if s := (LBTargetSpec{ID: "2001:db8::1", Port: 80}).String(); s != "[2001:db8::1]:80" {
		t.Errorf("String = %q", s)
	}
	ts, err := ParseTargets([]string{"i-1:80", "i-1:80", "i-1"})
	if err != nil || len(ts) != 2 {
		t.Errorf("ParseTargets = %+v, %v", ts, err)
	}
	if !IsIPTarget("10.0.0.1") || IsIPTarget("i-1") {
		t.Error("IsIPTarget")
	}
}

func TestListenerForwardsTo(t *testing.T) {
	l := LBListener{DefaultAction: "forward", TargetGroups: []string{"tg-1"}}
	if !l.ForwardsTo("tg-1") || l.ForwardsTo("tg-2") {
		t.Error("forward")
	}
	l.TargetGroups = append(l.TargetGroups, "tg-2")
	if l.ForwardsTo("tg-1") {
		t.Error("weighted forward to two groups")
	}
	if (LBListener{DefaultAction: "redirect", TargetGroups: []string{"tg-1"}}).ForwardsTo("tg-1") {
		t.Error("redirect")
	}
	lb := LoadBalancer{Zones: []LBZone{{Zone: "a", Subnet: "s-1"}, {Zone: "b", Subnet: "s-2"}}}
	if z, s := lb.ZoneNames(), lb.Subnets(); len(z) != 2 || z[1] != "b" || s[0] != "s-1" {
		t.Errorf("zones %v subnets %v", z, s)
	}
}
