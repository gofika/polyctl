package aliyun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/domain"

	"github.com/gofika/polyctl/internal/platform"
)

// domainStatusLabels translates the numeric DomainStatus of the registrar API.
var domainStatusLabels = map[string]string{
	"1": "renewal required",
	"2": "redemption required",
	"3": "normal",
	"4": "real-name verification required",
	"5": "transfer-out pending",
	"6": "deleted",
}

func domainStatus(code string) string {
	if l, ok := domainStatusLabels[code]; ok {
		return l
	}
	return code
}

// domainFromList converts a QueryDomainList entry.
func domainFromList(d domain.Domain) platform.Domain {
	out := platform.Domain{
		Name:        platform.NormalizeDomain(d.DomainName),
		Nameservers: append([]string(nil), d.DnsList.Dns...),
		Status:      domainStatus(d.DomainStatus),
		ExpiresAt:   d.ExpirationDate,
		Extra: map[string]any{
			"status_code":     d.DomainStatus,
			"registrant_type": d.RegistrantType,
			"premium":         d.Premium,
		},
	}
	if d.InstanceId != "" {
		out.Extra["instance_id"] = d.InstanceId
	}
	if d.RegistrationDate != "" {
		out.Extra["registered_at"] = d.RegistrationDate
	}
	if d.DomainType != "" {
		out.Extra["domain_type"] = d.DomainType
	}
	if d.ExpirationDateStatus != "" {
		out.Extra["expiration_status"] = d.ExpirationDateStatus
	}
	return out
}

// domainFromDetail converts a QueryDomainByDomainName response.
func domainFromDetail(r *domain.QueryDomainByDomainNameResponse) platform.Domain {
	out := platform.Domain{
		Name:        platform.NormalizeDomain(r.DomainName),
		Nameservers: append([]string(nil), r.DnsList.Dns...),
		Status:      domainStatus(r.DomainStatus),
		ExpiresAt:   r.ExpirationDate,
		Extra: map[string]any{
			"status_code":     r.DomainStatus,
			"registrant_type": r.RegistrantType,
			"premium":         r.Premium,
		},
	}
	switch strings.ToUpper(r.TransferProhibitionLock) {
	case "OPEN":
		t := true
		out.Locked = &t
	case "CLOSE", "NONE_SETTING":
		f := false
		out.Locked = &f
	}
	if r.DomainNameProxyService {
		t := true
		out.Privacy = &t
	}
	for k, v := range map[string]string{
		"instance_id":        r.InstanceId,
		"registered_at":      r.RegistrationDate,
		"domain_type":        r.DomainType,
		"expiration_status":  r.ExpirationDateStatus,
		"update_lock":        r.UpdateProhibitionLock,
		"transfer_out":       r.TransferOutStatus,
		"real_name_status":   r.RealNameStatus,
		"registrant_name":    r.RegistrantName,
		"registrant_org":     r.RegistrantOrganization,
		"registrant_email":   r.Email,
		"domain_group":       r.DomainGroupName,
		"email_verification": fmt.Sprint(r.EmailVerificationStatus),
	} {
		if v != "" {
			out.Extra[k] = v
		}
	}
	return out
}

// ListDomains lists every registered domain (paginated).
func (c *client) ListDomains(ctx context.Context) ([]platform.Domain, error) {
	cl, err := c.domainClient(ctx)
	if err != nil {
		return nil, err
	}
	var out []platform.Domain
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := domain.CreateQueryDomainListRequest()
		c.routeRegistrar(req)
		req.PageNum = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(pageSize)
		resp, err := cl.QueryDomainList(req)
		if err != nil {
			return nil, wrapErr("domain QueryDomainList", err)
		}
		for _, d := range resp.Data.Domain {
			out = append(out, domainFromList(d))
		}
		if len(resp.Data.Domain) == 0 || !resp.NextPage || (resp.TotalPageNum > 0 && page >= resp.TotalPageNum) {
			break
		}
	}
	return out, nil
}

// GetDomain fetches one registered domain.
func (c *client) GetDomain(ctx context.Context, name string) (*platform.Domain, error) {
	cl, err := c.domainClient(ctx)
	if err != nil {
		return nil, err
	}
	name = platform.NormalizeDomain(name)
	req := domain.CreateQueryDomainByDomainNameRequest()
	c.routeRegistrar(req)
	req.DomainName = name
	resp, err := cl.QueryDomainByDomainName(req)
	if err != nil {
		return nil, wrapErr("domain QueryDomainByDomainName "+name, err)
	}
	if resp.DomainName == "" {
		return nil, fmt.Errorf("domain %s: %w", name, platform.ErrNotFound)
	}
	d := domainFromDetail(resp)
	return &d, nil
}

// ErrTaskPending is returned when the registrar has accepted a change but
// had not applied it when the wait ran out. The change may still complete;
// the error message carries the task number.
var ErrTaskPending = errors.New("registrar task still pending")

// Registrar tasks are asynchronous; SetNameservers waits for completion.
// Variables so tests can shorten them.
var (
	nsTaskTimeout  = 60 * time.Second
	nsTaskInterval = 2 * time.Second
)

// Task status codes of QueryTaskDetailList.
const (
	taskWaiting   = 0
	taskExecuting = 1
	taskSuccess   = 2
	taskFailure   = 3
)

// SetNameservers changes the domain's nameservers and waits until the
// registrar has applied the change (or reports a failure).
func (c *client) SetNameservers(ctx context.Context, name string, ns []string) error {
	if len(ns) == 0 {
		return fmt.Errorf("set nameservers: at least one nameserver is required")
	}
	cl, err := c.domainClient(ctx)
	if err != nil {
		return err
	}
	name = platform.NormalizeDomain(name)
	servers := make([]string, 0, len(ns))
	for _, s := range ns {
		if s = platform.NormalizeDomain(s); s != "" {
			servers = append(servers, s)
		}
	}
	req := domain.CreateSaveBatchTaskForModifyingDomainDnsRequest()
	c.routeRegistrar(req)
	req.DomainName = &[]string{name}
	req.DomainNameServer = &servers
	req.AliyunDns = requests.NewBoolean(false)
	resp, err := cl.SaveBatchTaskForModifyingDomainDns(req)
	if err != nil {
		return wrapErr("domain SaveBatchTaskForModifyingDomainDns "+name, err)
	}
	if resp.TaskNo == "" {
		return fmt.Errorf("set nameservers of %s: %w (the registrar returned no task number)", name, ErrTaskPending)
	}
	return c.waitTask(ctx, cl, name, resp.TaskNo)
}

// waitTask polls QueryTaskDetailList until the task for name completes.
func (c *client) waitTask(ctx context.Context, cl *domain.Client, name, taskNo string) error {
	deadline := time.Now().Add(nsTaskTimeout)
	for {
		req := domain.CreateQueryTaskDetailListRequest()
		c.routeRegistrar(req)
		req.TaskNo = taskNo
		req.DomainName = name
		req.PageNum = requests.NewInteger(1)
		req.PageSize = requests.NewInteger(pageSize)
		resp, err := cl.QueryTaskDetailList(req)
		if err != nil {
			return wrapErr("domain QueryTaskDetailList "+taskNo, err)
		}
		for _, td := range resp.Data.TaskDetail {
			if td.DomainName != "" && platform.NormalizeDomain(td.DomainName) != name {
				continue
			}
			status := strings.ToUpper(td.TaskStatus)
			switch {
			case td.TaskStatusCode == taskSuccess, status == "EXECUTE_SUCCESS":
				return nil
			case td.TaskStatusCode == taskFailure, status == "EXECUTE_FAILURE":
				reason := td.FailReason
				if reason == "" {
					reason = td.ErrorMsg
				}
				if reason == "" {
					reason = "no reason given"
				}
				return fmt.Errorf("set nameservers of %s: registrar task %s failed: %s", name, taskNo, reason)
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("set nameservers of %s: %w (task %s; check `aliyun domain get %s` later)", name, ErrTaskPending, taskNo, name)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("set nameservers of %s: %w (task %s)", name, ctx.Err(), taskNo)
		case <-time.After(nsTaskInterval):
		}
	}
}
