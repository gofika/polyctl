package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// domainArgs fills in a missing <domain> argument in the interactive flow
// with a domain of the local index (app.Runtime.PickDomain). With the
// argument given it returns args unchanged.
func domainArgs(cmd *cobra.Command, rt *app.Runtime, args []string, p app.DomainPick) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	if p.Arg == "" {
		p.Arg = "<domain>"
	}
	d, err := rt.PickDomain(cmd.Context(), p)
	if err != nil {
		return nil, err
	}
	return []string{d}, nil
}

// zoneKinds and domainKinds are the index entries the pickers offer.
var (
	zoneKinds   = []platform.ResourceType{platform.ResZone}
	domainKinds = []platform.ResourceType{platform.ResDomain}
)

// certStoreOptions lists the certificates of a store in domain order, each
// labelled "domain  key type  expires 2027-01-01 (30 days)".
func certStoreOptions(st *cert.Store) ([]prompt.Option, error) {
	roots, err := st.List()
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, root := range roots {
		b, err := st.Load(root, false)
		if err != nil || b == nil {
			continue
		}
		days := int(time.Until(b.NotAfter).Hours() / 24)
		expiry := fmt.Sprintf("expires %s (%d days)", b.NotAfter.UTC().Format("2006-01-02"), days)
		if days < 0 {
			expiry = "expired " + b.NotAfter.UTC().Format("2006-01-02")
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(root, b.KeyType, expiry), Value: root})
	}
	return opts, nil
}

// pickRecords lets the user tick the records to delete among existing (the
// records of a zone, or of one name of it), asked with title: every record
// but the zone's own (SOA, apex NS), labelled "name  type  value  ttl 300
// proxied  [owner]  id" ("-" for what a record does not have), a record
// owned by another service marked with that service.
func pickRecords(rt *app.Runtime, dns platform.DNSService, zone platform.Zone, title string, existing []platform.Record) ([]platform.Record, error) {
	items := platform.ClassifyDeleteAll(platform.DNSDeleteAll{Zone: zone, DNS: dns, Records: existing})
	owners := map[string]string{}
	var recs []platform.Record
	for _, it := range items {
		if it.Disposition != platform.DispNormal && it.Disposition != platform.DispBound {
			continue
		}
		recs = append(recs, it.Record)
		owners[it.Record.ID] = it.Owner
	}
	return rt.PickRecords(title, "record in zone "+zone.Name, recs, func(r platform.Record) string { return owners[r.ID] })
}

// certStoreLabel says what the store holds for the root domain of d:
// "store: 42 days left", "store: expired" or "store: none".
func certStoreLabel(rt *app.Runtime, staging bool, d string) string {
	root, err := cert.RootDomain(d)
	if err != nil {
		return ""
	}
	st, err := cert.OpenRuntimeStore(rt, staging)
	if err != nil {
		return ""
	}
	b, err := st.Load(root, false)
	if err != nil || b == nil {
		return "store: none"
	}
	if days := int(time.Until(b.NotAfter).Hours() / 24); days >= 0 {
		return fmt.Sprintf("store: %d days left", days)
	}
	return "store: expired"
}
