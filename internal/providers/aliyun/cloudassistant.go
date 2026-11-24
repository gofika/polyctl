package aliyun

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

// Cloud Assistant is the temporary way into an ECS Linux instance that
// needs neither a local key nor a network path: its agent (preinstalled on
// the public images released since 2017-12-01) runs a shell command as
// root (RunCommand of a RunShellScript, the result read with
// DescribeInvocationResults). The command is not kept (KeepCommand false),
// so it counts against no quota of saved commands.
//
// Alibaba Cloud's own temporary SSH keys (Workbench password-free login,
// the public command ACS-ECS-SendSshPublicKey-linux.sh, ali-instance-cli
// send_public_key) are delivered through the same agent and then still
// need an SSH login, so they would reach no instance Cloud Assistant
// cannot.

const (
	// assistantTimeout is how long the command may run (seconds; the
	// default is 60): the key scripts take well under a second.
	assistantTimeout = 60
	// assistantOutputLimit is the output DescribeInvocationResults keeps
	// (24 KB); the rest is dropped, and Dropped says how much.
	assistantOutputLimit = 24 * 1024
	// assistantCutMargin is how close to the limit output counts as cut.
	assistantCutMargin = 100
	// assistantCommandName names the command in the console.
	assistantCommandName = "polyctl-ssh-key"
	// errInvokeNotFound is DescribeInvocationResults' answer for an
	// invocation it does not know (yet).
	errInvokeNotFound = "InvalidInvokeId.NotFound"
)

// assistantPollInterval is the pause between two DescribeInvocationResults
// calls; the waits use netClock, which tests replace.
var assistantPollInterval = time.Second

// cloudAssistantOnline tells whether Cloud Assistant can run a command on
// the instance (DescribeCloudAssistantStatus): its agent must have sent a
// heartbeat within the last two minutes. When the credentials may not ask,
// nil: RunCommand decides.
func (c *client) cloudAssistantOnline(ctx context.Context, region, id string) error {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return err
	}
	req := ecs.CreateDescribeCloudAssistantStatusRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceId = &[]string{id}
	resp, err := cl.DescribeCloudAssistantStatus(req)
	if err != nil {
		w := wrapErr("ecs DescribeCloudAssistantStatus "+region, err)
		if errors.Is(w, platform.ErrForbidden) || errors.Is(w, platform.ErrUnauthorized) {
			return nil
		}
		return w
	}
	for _, s := range resp.InstanceCloudAssistantStatusSet.InstanceCloudAssistantStatus {
		if s.InstanceId != id {
			continue
		}
		if s.OSType != "" && !strings.EqualFold(s.OSType, "linux") {
			return fmt.Errorf("Cloud Assistant reports the instance as %s, not Linux", s.OSType)
		}
		if s.CloudAssistantStatus != "true" {
			return errors.New("the Cloud Assistant agent of the instance is not online (no heartbeat in the last two minutes)")
		}
		return nil
	}
	return errors.New("the instance has no Cloud Assistant agent")
}

// assistantWrapper runs @CMD@ with its standard error captured apart:
// Cloud Assistant returns one output, so the command's standard output
// comes first, as written, then a line holding @MARK@, then its standard
// error. The exit status is the command's.
const assistantWrapper = `exec 3>&1
e=$( (
@CMD@
) 2>&1 1>&3 3>&-; printf '\n%s' "$?")
c=${e##*
}
e=${e%
*}
printf '\n%s\n%s' '@MARK@' "$e"
exit "$c"
`

// assistantProgram is the program Cloud Assistant runs for command, with a
// marker that splits its output.
func assistantProgram(command string) (prog, mark string) {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	mark = "polyctl-stderr-" + hex.EncodeToString(b)
	return strings.NewReplacer("@CMD@", command, "@MARK@", mark).Replace(assistantWrapper), mark
}

// splitAssistantOutput splits the output of assistantProgram into the
// command's standard output and standard error; ok is false when the
// marker is missing (the output is not the program's whole output). An
// output that ends with the marker, its newline trimmed away, has no
// standard error.
func splitAssistantOutput(out, mark string) (stdout, stderr []byte, ok bool) {
	sep := "\n" + mark + "\n"
	i := strings.LastIndex(out, sep)
	if i < 0 {
		if strings.HasSuffix(out, sep[:len(sep)-1]) {
			return []byte(out[:len(out)-len(sep)+1]), []byte{}, true
		}
		return nil, nil, false
	}
	return []byte(out[:i]), []byte(out[i+len(sep):]), true
}

// runShellCommand runs command as root on the instance with Cloud
// Assistant (RunCommand, then DescribeInvocationResults until it ends) and
// returns its output and exit status. A command that exits non-zero is no
// error; one that did not run, or whose output was cut, is.
func (c *client) runShellCommand(ctx context.Context, region, id, command string) (stdout, stderr []byte, code int, err error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, nil, 0, err
	}
	prog, mark := assistantProgram(command)
	req := ecs.CreateRunCommandRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.Type = "RunShellScript"
	req.InstanceId = &[]string{id}
	req.Name = assistantCommandName
	req.ContentEncoding = "Base64"
	// The content travels in the form body, not in the query string, which
	// a few kilobytes of script would make long.
	req.FormParams = map[string]string{"CommandContent": base64.StdEncoding.EncodeToString([]byte(prog))}
	req.Timeout = requests.NewInteger(assistantTimeout)
	req.KeepCommand = requests.NewBoolean(false)
	// A resent request runs the script again without a token.
	req.ClientToken = clientToken()
	resp, err := cl.RunCommand(req)
	if err != nil {
		w := wrapErr("ecs RunCommand "+region, err)
		if errors.Is(w, platform.ErrForbidden) || errors.Is(w, platform.ErrUnauthorized) {
			return nil, nil, 0, fmt.Errorf("the credentials need the RAM actions ecs:RunCommand (with ecs:CommandRunAs) and ecs:DescribeInvocationResults on the instance: %w", w)
		}
		return nil, nil, 0, w
	}
	if resp.InvokeId == "" {
		return nil, nil, 0, fmt.Errorf("ecs RunCommand %s returned no invocation id", region)
	}

	var res *ecs.InvocationResult
	timeout := time.Duration(assistantTimeout+60) * time.Second
	err = platform.WaitUntil(ctx, platform.WaitOptions{Resource: "invocation " + resp.InvokeId + " on " + id, Want: "finished",
		Timeout: timeout, Interval: assistantPollInterval, Clock: netClock()},
		func(ctx context.Context) (platform.WaitState, string, error) {
			q := ecs.CreateDescribeInvocationResultsRequest()
			c.route(q, endpointECS)
			q.RegionId = region
			q.InvokeId = resp.InvokeId
			q.InstanceId = id
			q.ContentEncoding = "Base64"
			out, err := cl.DescribeInvocationResults(q)
			if err != nil {
				w := wrapErr("ecs DescribeInvocationResults "+region, err)
				// An invocation just created may not be visible yet.
				if platform.HasErrorCode(w, errInvokeNotFound) {
					return platform.KeepWaiting, "not visible yet", nil
				}
				if errors.Is(w, platform.ErrForbidden) || errors.Is(w, platform.ErrUnauthorized) {
					return platform.KeepWaiting, "", fmt.Errorf("the credentials need the RAM action ecs:DescribeInvocationResults: %w", w)
				}
				return platform.KeepWaiting, "", w
			}
			for i := range out.Invocation.InvocationResults.InvocationResult {
				r := &out.Invocation.InvocationResults.InvocationResult[i]
				if r.InstanceId != "" && r.InstanceId != id {
					continue
				}
				switch r.InvocationStatus {
				case "Success", "Failed", "Error", "Timeout", "Cancelled", "Terminated", "Invalid", "Aborted":
					res = r
					return platform.WaitDone, r.InvocationStatus, nil
				}
				return platform.KeepWaiting, r.InvocationStatus, nil
			}
			// Not listed yet.
			return platform.KeepWaiting, "not visible yet", nil
		})
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, 0, err
		}
		return nil, nil, 0, fmt.Errorf("Cloud Assistant invocation %s on instance %s was sent, but its result is unknown (it may have run): %w", resp.InvokeId, id, err)
	}
	// Success and Failed (a non-zero exit) carry the exit status of a
	// command that ran; anything else did not run or did not finish.
	if res.InvocationStatus != "Success" && (res.InvocationStatus != "Failed" || (res.ErrorCode != "" && res.ErrorCode != "ExitCodeNonzero")) {
		detail := res.InvocationStatus
		if res.ErrorCode != "" {
			detail += " (" + res.ErrorCode
			if res.ErrorInfo != "" {
				detail += ": " + res.ErrorInfo
			}
			detail += ")"
		}
		return nil, nil, 0, fmt.Errorf("Cloud Assistant invocation %s on instance %s did not finish: %s", resp.InvokeId, id, detail)
	}
	raw, err := base64.StdEncoding.DecodeString(res.Output)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("Cloud Assistant invocation %s on instance %s: the output is not base64: %w", resp.InvokeId, id, err)
	}
	// Output past the limit is dropped; output near it may have been cut.
	if res.Dropped > 0 || len(raw) >= assistantOutputLimit-assistantCutMargin {
		return nil, nil, 0, fmt.Errorf("%w: the output of Cloud Assistant invocation %s on instance %s reaches the 24 KB Cloud Assistant returns: it may be cut, so it is not used",
			platform.ErrNotSupported, resp.InvokeId, id)
	}
	so, se, ok := splitAssistantOutput(string(raw), mark)
	if !ok {
		return nil, nil, 0, fmt.Errorf("Cloud Assistant invocation %s on instance %s: the output does not end as the command does: it is not used", resp.InvokeId, id)
	}
	return so, se, int(res.ExitCode), nil
}
