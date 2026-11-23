package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func TestWouldWrite(t *testing.T) {
	var out, errb bytes.Buffer
	rt := New(Flags{}, strings.NewReader(""), &out, &errb)
	target := platform.Target{Platform: platform.AWS, Profile: "p"}
	ch := platform.Change{Resource: "instance/i-1", Action: platform.Updated, Detail: "stop"}
	if done, err := rt.WouldWrite(target, ch); done || err != nil || out.Len() != 0 {
		t.Fatalf("without --dry-run: %v %v %q", done, err, out.String())
	}
	rt.Flags.DryRun = true
	done, err := rt.WouldWrite(target, ch)
	if !done || err != nil {
		t.Fatalf("with --dry-run: %v %v", done, err)
	}
	if !strings.Contains(out.String(), "instance/i-1  would update  stop") || !strings.Contains(errb.String(), "dry run: would update instance/i-1 (stop)") {
		t.Errorf("stdout %q stderr %q", out.String(), errb.String())
	}
	out.Reset()
	rt.format = output.JSON
	if _, err := rt.WouldWrite(target); err != nil || !strings.Contains(out.String(), `"changes": []`) || !strings.Contains(out.String(), `"dry_run": true`) {
		t.Errorf("empty report = %q, %v", out.String(), err)
	}
}

func TestEnsurePrintsReportOnFailure(t *testing.T) {
	var out bytes.Buffer
	rt := New(Flags{}, strings.NewReader(""), &out, &bytes.Buffer{})
	boom := errors.New("boom")
	plan := &platform.Plan{Steps: []platform.Step{
		{Resource: "a", Action: platform.Created, Apply: func(context.Context) (platform.Change, error) { return platform.Change{ID: "id-a"}, nil }},
		{Resource: "b", Action: platform.Created, Apply: func(context.Context) (platform.Change, error) { return platform.Change{}, boom }},
	}}
	err := rt.Ensure(t.Context(), "test ensure", platform.Target{Platform: platform.AWS, Profile: "p"}, plan)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if s := out.String(); !strings.Contains(s, "a         created  id-a") || !strings.Contains(s, "b         failed   boom") {
		t.Errorf("report = %q", s)
	}
}

func TestWaitFlags(t *testing.T) {
	parse := func(def bool, args ...string) (bool, time.Duration, error) {
		var w WaitFlags
		cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error { return nil }}
		AddWaitFlags(cmd, &w, def, 0)
		if err := cmd.ParseFlags(args); err != nil {
			return false, 0, err
		}
		return w.Resolve(cmd)
	}
	if wait, to, err := parse(false); err != nil || wait || to != DefaultWaitTimeout {
		t.Errorf("default (no wait) = %v %v %v", wait, to, err)
	}
	if wait, to, err := parse(false, "--wait", "--timeout", "90s"); err != nil || !wait || to != 90*time.Second {
		t.Errorf("--wait = %v %v %v", wait, to, err)
	}
	if wait, _, err := parse(true); err != nil || !wait {
		t.Errorf("ensure default = %v %v", wait, err)
	}
	if wait, _, err := parse(true, "--no-wait"); err != nil || wait {
		t.Errorf("--no-wait = %v %v", wait, err)
	}
	if _, _, err := parse(true, "--no-wait", "--wait"); !errors.Is(err, ErrUsage) {
		t.Errorf("contradiction = %v", err)
	}
	if _, _, err := parse(false, "--timeout", "0s"); !errors.Is(err, ErrUsage) {
		t.Errorf("zero timeout = %v", err)
	}
	if _, _, err := parse(false, "--no-wait"); err == nil {
		t.Error("--no-wait exists only where waiting is the default")
	}
}
