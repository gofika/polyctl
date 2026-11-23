package app

import (
	"testing"
	"time"
)

func TestAgo(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		10 * time.Second: "just now",
		4 * time.Minute:  "4m ago",
		6 * time.Hour:    "6h ago",
		47 * time.Hour:   "47h ago",
		72 * time.Hour:   "3d ago",
	} {
		if got := Ago(now.Add(-d), now); got != want {
			t.Errorf("Ago(%s) = %q, want %q", d, got, want)
		}
	}
}
