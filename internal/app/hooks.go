package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// Failure is the event hooks.on_failure is told about.
type Failure struct {
	// Event names what failed: "<command>.failed" (cert.deploy.failed,
	// aws.ec2.security-group.ensure.failed, ...).
	Event    string `json:"event"`
	Platform string `json:"platform,omitempty"`
	Profile  string `json:"profile,omitempty"`
	// Deployer and Target name the item of a batch that failed.
	Deployer string `json:"deployer,omitempty"`
	Target   string `json:"target,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Error    string `json:"error"`
	// Time is set by NotifyFailure (RFC 3339, UTC).
	Time    string            `json:"time"`
	Changes []platform.Change `json:"changes,omitempty"`
}

// HookTimeout bounds one call of a hook.
var HookTimeout = 15 * time.Second

// hookHTTPClient sends webhook notifications; tests replace it.
var hookHTTPClient = &http.Client{}

// NotifyFailure calls hooks.on_failure, when it is set, with f. It is best
// effort: a hook that fails or runs out of time is reported on stderr as a
// warning and changes nothing else (the exit code stays the command's). A
// dry run and an --offline run notify nobody: --offline never touches the
// network, which a webhook (or a shell command) would, and a run stopped by
// it (ErrOffline) did what the user asked. The hook is a webhook when it starts with
// http:// or https:// (POST, JSON body), otherwise a shell command (sh -c,
// cmd /S /C on Windows, the command passed as written) that gets the event as JSON on stdin and in the
// POLYCTL_EVENT, POLYCTL_PLATFORM, POLYCTL_PROFILE, POLYCTL_DEPLOYER,
// POLYCTL_TARGET, POLYCTL_DOMAIN and POLYCTL_ERROR variables.
func (rt *Runtime) NotifyFailure(ctx context.Context, f Failure) {
	if rt.Flags.DryRun || rt.Flags.Offline {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	hook := strings.TrimSpace(cfg.Hooks.OnFailure)
	if hook == "" {
		return
	}
	if f.Time == "" {
		f.Time = time.Now().UTC().Format(time.RFC3339)
	}
	body, err := json.Marshal(f)
	if err != nil {
		rt.Infof("warning: hooks.on_failure: %v", err)
		return
	}
	// The command's own context may be what ended (Ctrl-C, a timeout): the
	// notification of that failure must still go out.
	hctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), HookTimeout)
	defer cancel()
	if strings.HasPrefix(hook, "http://") || strings.HasPrefix(hook, "https://") {
		err = postHook(hctx, hook, body)
	} else {
		err = runHook(hctx, hook, f, body, rt.Stderr)
	}
	if err != nil {
		rt.Infof("warning: hooks.on_failure: %v", err)
		return
	}
	rt.Verbosef("hooks.on_failure notified (%s)", f.Event)
}

func postHook(ctx context.Context, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return errors.New("the webhook URL is not valid")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hookHTTPClient.Do(req)
	if err != nil {
		// The URL of a webhook is often its secret (Slack, Teams, ...):
		// report why the request failed without quoting it.
		var ue *neturl.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("webhook request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}

func runHook(ctx context.Context, command string, f Failure, body []byte, stderr io.Writer) error {
	cmd := shellCommand(ctx, command)
	cmd.Env = append(os.Environ(),
		"POLYCTL_EVENT="+f.Event,
		"POLYCTL_PLATFORM="+f.Platform,
		"POLYCTL_PROFILE="+f.Profile,
		"POLYCTL_DEPLOYER="+f.Deployer,
		"POLYCTL_TARGET="+f.Target,
		"POLYCTL_DOMAIN="+f.Domain,
		"POLYCTL_ERROR="+f.Error,
	)
	cmd.Stdin = bytes.NewReader(body)
	// The hook's own output is diagnostics: stderr, never stdout, which
	// holds the command's result.
	cmd.Stdout, cmd.Stderr = stderr, stderr
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("command timed out after %s", HookTimeout)
		}
		return fmt.Errorf("command failed: %v", err)
	}
	return nil
}
