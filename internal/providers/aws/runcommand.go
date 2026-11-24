package aws

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/gofika/polyctl/internal/platform"
)

// AWS Systems Manager Run Command is the temporary way into a Linux
// instance that needs neither a local key nor a network path: the SSM Agent
// on the instance runs the command as root (document AWS-RunShellScript).
// It works on instances that Systems Manager manages (SSM Agent running and
// registered, which needs an instance profile such as
// AmazonSSMManagedInstanceCore or the Default Host Management
// Configuration).

const (
	// runShellDocument is the AWS document that runs shell commands on
	// Linux.
	runShellDocument = "AWS-RunShellScript"
	// runExecutionTimeout is how long the command may run once started
	// (seconds): the key scripts take well under a second.
	runExecutionTimeout = 60
	// runDeliveryTimeout is how long the agent has to pick the command up
	// (seconds; 30 is the least SendCommand accepts): an agent that does
	// not, does not run it at all.
	runDeliveryTimeout = 30
	// ssmStdoutLimit and ssmStderrLimit are the lengths of output
	// GetCommandInvocation returns at most (characters); longer output is
	// cut.
	ssmStdoutLimit = 24000
	ssmStderrLimit = 8000
	// ssmCutMargin is how close to a limit output counts as cut.
	ssmCutMargin = 100
)

// runCommandPollInterval is the pause between two GetCommandInvocation
// calls; the waits use instanceClock, which tests replace.
var runCommandPollInterval = time.Second

// ssmManagedLinux tells whether Systems Manager can run a command on the
// instance (ssm:DescribeInstanceInformation): it must be a managed Linux
// node whose agent is online. When the credentials may not describe it,
// nil: SendCommand decides.
func (c *client) ssmManagedLinux(ctx context.Context, region, id string) error {
	out, err := c.ssmFor(region).DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
		Filters: []ssmtypes.InstanceInformationStringFilter{{Key: awssdk.String("InstanceIds"), Values: []string{id}}},
	})
	if err != nil {
		if errors.Is(mapErr(err), platform.ErrUnauthorized) {
			return nil
		}
		return fmt.Errorf("ssm:DescribeInstanceInformation in %s: %w", region, mapErr(err))
	}
	for _, in := range out.InstanceInformationList {
		if awssdk.ToString(in.InstanceId) != id {
			continue
		}
		if in.PingStatus != ssmtypes.PingStatusOnline {
			return fmt.Errorf("the SSM Agent of the instance is not online (ping status %s)", in.PingStatus)
		}
		if in.PlatformType != "" && in.PlatformType != ssmtypes.PlatformTypeLinux {
			return fmt.Errorf("Systems Manager reports the instance as %s, not Linux", in.PlatformType)
		}
		return nil
	}
	return errors.New("the instance is not managed by Systems Manager (no SSM Agent registered: it needs the agent and an instance profile that allows Systems Manager)")
}

// runShellCommand runs command as root on the instance with Run Command
// (ssm:SendCommand of AWS-RunShellScript, then ssm:GetCommandInvocation
// until it ends) and returns its output and exit status. A command that
// exits non-zero is no error; one that did not run, or whose output was
// cut, is.
func (c *client) runShellCommand(ctx context.Context, region, id, command string) (stdout, stderr []byte, code int, err error) {
	api := c.ssmFor(region)
	sent, err := api.SendCommand(ctx, &ssm.SendCommandInput{
		DocumentName: awssdk.String(runShellDocument),
		InstanceIds:  []string{id},
		Parameters: map[string][]string{
			"commands":         {command},
			"executionTimeout": {strconv.Itoa(runExecutionTimeout)},
		},
		TimeoutSeconds: awssdk.Int32(runDeliveryTimeout),
		Comment:        awssdk.String("polyctl ssh-key"),
	})
	if err != nil {
		m := mapErr(err)
		switch {
		case errors.Is(m, platform.ErrUnauthorized):
			return nil, nil, 0, fmt.Errorf("ssm:SendCommand in %s (the credentials need the IAM action ssm:SendCommand on the instance and on the document %s): %w", region, runShellDocument, m)
		case apiErrorCode(err) == "InvalidInstanceId":
			return nil, nil, 0, fmt.Errorf("ssm:SendCommand in %s: the instance is not a managed node whose SSM Agent is running: %w", region, m)
		}
		return nil, nil, 0, fmt.Errorf("ssm:SendCommand in %s: %w", region, m)
	}
	if sent.Command == nil || awssdk.ToString(sent.Command.CommandId) == "" {
		return nil, nil, 0, fmt.Errorf("ssm:SendCommand in %s returned no command id", region)
	}
	cmdID := awssdk.ToString(sent.Command.CommandId)

	var res *ssm.GetCommandInvocationOutput
	timeout := time.Duration(runExecutionTimeout+runDeliveryTimeout+30) * time.Second
	err = platform.WaitUntil(ctx, platform.WaitOptions{Resource: "command " + cmdID + " on " + id, Want: "finished",
		Timeout: timeout, Interval: runCommandPollInterval, Clock: instanceClock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			out, err := api.GetCommandInvocation(ctx, &ssm.GetCommandInvocationInput{CommandId: awssdk.String(cmdID), InstanceId: awssdk.String(id)})
			if err != nil {
				// Run Command is eventually consistent: the invocation
				// may not be visible right after SendCommand.
				if apiErrorCode(err) == "InvocationDoesNotExist" {
					return platform.KeepWaiting, "not visible yet", nil
				}
				m := mapErr(err)
				if errors.Is(m, platform.ErrUnauthorized) {
					return platform.KeepWaiting, "", fmt.Errorf("ssm:GetCommandInvocation in %s (the credentials need the IAM action ssm:GetCommandInvocation): %w", region, m)
				}
				return platform.KeepWaiting, "", fmt.Errorf("ssm:GetCommandInvocation in %s: %w", region, m)
			}
			switch out.Status {
			case ssmtypes.CommandInvocationStatusPending, ssmtypes.CommandInvocationStatusInProgress, ssmtypes.CommandInvocationStatusDelayed:
				return platform.KeepWaiting, string(out.Status), nil
			}
			res = out
			return platform.WaitDone, string(out.Status), nil
		})
	if err != nil {
		return nil, nil, 0, err
	}
	detail := awssdk.ToString(res.StatusDetails)
	if detail == "" {
		detail = string(res.Status)
	}
	// Success and Failed carry the exit status of a command that ran;
	// anything else (TimedOut, Cancelled, Undeliverable) did not finish.
	if (res.Status != ssmtypes.CommandInvocationStatusSuccess && res.Status != ssmtypes.CommandInvocationStatusFailed) || res.ResponseCode < 0 {
		return nil, nil, 0, fmt.Errorf("Run Command %s on instance %s did not finish: %s", cmdID, id, detail)
	}
	so, se := awssdk.ToString(res.StandardOutputContent), awssdk.ToString(res.StandardErrorContent)
	// Output near the limit may have been cut (with or without a marker
	// of the agent's): it is not trusted.
	if len(so) >= ssmStdoutLimit-ssmCutMargin || len(se) >= ssmStderrLimit-ssmCutMargin {
		return nil, nil, 0, fmt.Errorf("the output of Run Command %s on instance %s reaches the %d characters Systems Manager returns: it may be cut, so it is not used", cmdID, id, ssmStdoutLimit)
	}
	return []byte(so), []byte(se), int(res.ResponseCode), nil
}
