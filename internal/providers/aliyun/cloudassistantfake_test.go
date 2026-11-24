package aliyun

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// fakeAssistant answers the Cloud Assistant API of ECS: the agent status
// of instances, RunCommand (run at once through exec) and
// DescribeInvocationResults, which first answers nothing for hidden reads
// and Running for running reads, then the result. Like Cloud Assistant it
// returns standard output and standard error as one output.
type fakeAssistant struct {
	t   *testing.T
	api *fakeAPI
	// status is the CloudAssistantStatus of instances ("true", "false");
	// an instance missing from it has no agent.
	status map[string]string
	osType string
	// exec runs a command as root on an instance.
	exec func(id, cmd string) (stdout, stderr string, code int)

	// unknown reads answer InvalidInvokeId.NotFound, then hidden reads
	// nothing and running reads Running.
	unknown, hidden, running int
	// result, when set, is the InvocationStatus of every invocation, with
	// errorCode as its ErrorCode.
	result, errorCode string
	// dropped is the Dropped of every result; pad is added to the output.
	dropped int
	pad     string
	// statusErr and runErr, when set, answer DescribeCloudAssistantStatus
	// and RunCommand.
	statusErr, runErr string
	// resultsErr, when set, answers DescribeInvocationResults.
	resultsErr string

	runs        []url.Values
	programs    []string
	invocations map[string]map[string]any
	reads       map[string]int
}

func newFakeAssistant(t *testing.T, api *fakeAPI) *fakeAssistant {
	a := &fakeAssistant{t: t, api: api, status: map[string]string{}, osType: "Linux", invocations: map[string]map[string]any{}, reads: map[string]int{}}
	api.on("DescribeCloudAssistantStatus", a.describeStatus)
	api.on("RunCommand", a.runCommand)
	api.on("DescribeInvocationResults", a.describeResults)
	return a
}

func (a *fakeAssistant) describeStatus(q url.Values) (int, any) {
	if a.statusErr != "" {
		return 403, apiErr(a.statusErr, "not allowed")
	}
	var out []map[string]any
	for i := 1; ; i++ {
		id := q.Get(fmt.Sprintf("InstanceId.%d", i))
		if id == "" {
			break
		}
		if s, ok := a.status[id]; ok {
			out = append(out, map[string]any{"InstanceId": id, "CloudAssistantStatus": s, "OSType": a.osType})
		}
	}
	return 200, map[string]any{"TotalCount": len(out), "InstanceCloudAssistantStatusSet": map[string]any{"InstanceCloudAssistantStatus": out}}
}

func (a *fakeAssistant) runCommand(q url.Values) (int, any) {
	a.runs = append(a.runs, q)
	a.api.mu.Lock()
	query := a.api.queries[len(a.api.queries)-1]
	a.api.mu.Unlock()
	if strings.Contains(query, "CommandContent") {
		a.t.Error("RunCommand carries CommandContent in the query string")
	}
	if a.runErr != "" {
		return 403, apiErr(a.runErr, "not allowed")
	}
	id := q.Get("InstanceId.1")
	if q.Get("Type") != "RunShellScript" || q.Get("ContentEncoding") != "Base64" || id == "" {
		return 400, apiErr("InvalidParameter", "bad request")
	}
	prog, err := base64.StdEncoding.DecodeString(q.Get("CommandContent"))
	if err != nil {
		return 400, apiErr("InvalidCommandContent", err.Error())
	}
	a.programs = append(a.programs, string(prog))
	stdout, stderr, code := a.exec(id, string(prog))
	status, ec := "Success", ""
	if code != 0 {
		status, ec = "Failed", "ExitCodeNonzero"
	}
	if a.result != "" {
		status, ec = a.result, a.errorCode
	}
	invoke := fmt.Sprintf("t-%04d", len(a.runs))
	a.invocations[invoke] = map[string]any{"InstanceId": id, "InvokeId": invoke, "InvocationStatus": status, "ErrorCode": ec,
		"ExitCode": code, "Dropped": a.dropped, "Output": base64.StdEncoding.EncodeToString([]byte(stdout + stderr + a.pad))}
	return 200, map[string]any{"CommandId": "c-1", "InvokeId": invoke, "RequestId": "r"}
}

func (a *fakeAssistant) describeResults(q url.Values) (int, any) {
	if a.resultsErr != "" {
		return 403, apiErr(a.resultsErr, "not allowed")
	}
	inv := a.invocations[q.Get("InvokeId")]
	if inv == nil || q.Get("ContentEncoding") != "Base64" {
		return 400, apiErr("InvalidInvokeId.NotFound", "no such invocation")
	}
	n := a.reads[q.Get("InvokeId")]
	a.reads[q.Get("InvokeId")] = n + 1
	if n < a.unknown {
		return 404, apiErr("InvalidInvokeId.NotFound", "no such invocation")
	}
	n -= a.unknown
	var rows []map[string]any
	switch {
	case n < a.hidden:
	case n < a.hidden+a.running:
		rows = append(rows, map[string]any{"InstanceId": inv["InstanceId"], "InvokeId": inv["InvokeId"], "InvocationStatus": "Running"})
	default:
		rows = append(rows, inv)
	}
	return 200, map[string]any{"Invocation": map[string]any{"InvocationResults": map[string]any{"InvocationResult": rows}}}
}
