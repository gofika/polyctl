package aws

import (
	"context"
	"strconv"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeRunCommand is the Systems Manager Run Command part of the fake
// state: the managed nodes, and a command runner standing for their SSM
// Agent.
type fakeRunCommand struct {
	// nodes are the managed nodes by instance id.
	nodes map[string]ssmtypes.InstanceInformation
	// exec runs a command as root on an instance (nil: nothing runs and
	// the invocation times out).
	exec func(id, command string) (stdout, stderr string, code int)
	// describeErr, sendErr and getErr fail those calls.
	describeErr, sendErr, getErr error
	// hidden is how many GetCommandInvocation calls of a command answer
	// InvocationDoesNotExist first (eventual consistency).
	hidden int
	// status overrides the final status of every invocation.
	status ssmtypes.CommandInvocationStatus
	// stdout pads the output of every command (to test the cut).
	stdoutPad string
	sent      []ssm.SendCommandInput
	invs      map[string]*fakeInvocation
	describes int
}

type fakeInvocation struct {
	id     string
	gets   int
	result ssm.GetCommandInvocationOutput
}

// manage makes an instance a managed node with that ping status.
func (f *fakeRunCommand) manage(id string, ping ssmtypes.PingStatus) {
	if f.nodes == nil {
		f.nodes = map[string]ssmtypes.InstanceInformation{}
	}
	f.nodes[id] = ssmtypes.InstanceInformation{InstanceId: awssdk.String(id), PingStatus: ping, PlatformType: ssmtypes.PlatformTypeLinux}
}

func (s *fakeSSM) DescribeInstanceInformation(_ context.Context, in *ssm.DescribeInstanceInformationInput, _ ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	f := &s.shared.run
	f.describes++
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	out := &ssm.DescribeInstanceInformationOutput{}
	for _, flt := range in.Filters {
		if awssdk.ToString(flt.Key) != "InstanceIds" {
			continue
		}
		for _, id := range flt.Values {
			if n, ok := f.nodes[id]; ok {
				out.InstanceInformationList = append(out.InstanceInformationList, n)
			}
		}
	}
	return out, nil
}

func (s *fakeSSM) SendCommand(_ context.Context, in *ssm.SendCommandInput, _ ...func(*ssm.Options)) (*ssm.SendCommandOutput, error) {
	s.shared.mu.Lock()
	f := &s.shared.run
	f.sent = append(f.sent, *in)
	if f.sendErr != nil {
		s.shared.mu.Unlock()
		return nil, f.sendErr
	}
	if len(in.InstanceIds) != 1 || awssdk.ToString(in.DocumentName) != runShellDocument || len(in.Parameters["commands"]) != 1 {
		s.shared.mu.Unlock()
		return nil, &fakeAPIError{"InvalidParameters", "unexpected request"}
	}
	id := in.InstanceIds[0]
	n, ok := f.nodes[id]
	if !ok || n.PingStatus != ssmtypes.PingStatusOnline {
		s.shared.mu.Unlock()
		return nil, &fakeAPIError{"InvalidInstanceId", "Instances not in a valid state for account"}
	}
	if f.invs == nil {
		f.invs = map[string]*fakeInvocation{}
	}
	inv := &fakeInvocation{id: "cmd-" + strconv.Itoa(len(f.sent))}
	f.invs[inv.id] = inv
	exec, pad, status := f.exec, f.stdoutPad, f.status
	s.shared.mu.Unlock()

	res := ssm.GetCommandInvocationOutput{CommandId: awssdk.String(inv.id), InstanceId: awssdk.String(id), ResponseCode: -1,
		Status: ssmtypes.CommandInvocationStatusTimedOut, StatusDetails: awssdk.String("DeliveryTimedOut")}
	if exec != nil {
		so, se, code := exec(id, in.Parameters["commands"][0])
		res.StandardOutputContent, res.StandardErrorContent, res.ResponseCode = awssdk.String(so+pad), awssdk.String(se), int32(code)
		res.Status, res.StatusDetails = ssmtypes.CommandInvocationStatusSuccess, awssdk.String("Success")
		if code != 0 {
			res.Status, res.StatusDetails = ssmtypes.CommandInvocationStatusFailed, awssdk.String("Failed")
		}
	}
	if status != "" {
		res.Status, res.StatusDetails = status, awssdk.String(string(status))
	}
	s.shared.mu.Lock()
	inv.result = res
	s.shared.mu.Unlock()
	return &ssm.SendCommandOutput{Command: &ssmtypes.Command{CommandId: awssdk.String(inv.id)}}, nil
}

// GetCommandInvocation answers InvocationDoesNotExist for the first hidden
// calls of a command, then InProgress once, then the result.
func (s *fakeSSM) GetCommandInvocation(_ context.Context, in *ssm.GetCommandInvocationInput, _ ...func(*ssm.Options)) (*ssm.GetCommandInvocationOutput, error) {
	s.shared.mu.Lock()
	defer s.shared.mu.Unlock()
	f := &s.shared.run
	if f.getErr != nil {
		return nil, f.getErr
	}
	inv, ok := f.invs[awssdk.ToString(in.CommandId)]
	if !ok || awssdk.ToString(in.InstanceId) != awssdk.ToString(inv.result.InstanceId) {
		return nil, &fakeAPIError{"InvalidCommandId", "no such command"}
	}
	inv.gets++
	switch {
	case inv.gets <= f.hidden:
		return nil, &fakeAPIError{"InvocationDoesNotExist", "The command ID and managed node ID you specified didn't match any invocations"}
	case inv.gets == f.hidden+1:
		return &ssm.GetCommandInvocationOutput{CommandId: in.CommandId, InstanceId: in.InstanceId, Status: ssmtypes.CommandInvocationStatusInProgress, ResponseCode: -1}, nil
	}
	out := inv.result
	return &out, nil
}
