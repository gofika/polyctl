package aliyun

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// casOnlyALBNote is printed with every reference check: other products
// that may use a CAS certificate cannot be checked.
const casOnlyALBNote = "note: only ALB listeners were checked for references"

func newCASCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cas",
		Short: "Certificate Management Service (CAS)",
		Long: `Certificate Management Service (CAS): the certificates uploaded to the
account, which ALB listeners reference by id.

An account has two separate certificate stores: cas.aliyuncs.com and
cas.ap-southeast-1.aliyuncs.com; a certificate uploaded to one is missing
from the other. polyctl uses the Singapore store for a profile whose region
is cn-hongkong (ALB listeners there take "<id>-ap-southeast-1"), the central
store otherwise. defaults.aliyun.cas_region and defaults.aliyun.cas_endpoint
in config.yaml override the region and the endpoint.`,
	}
	cert := &cobra.Command{Use: "certificate", Short: "Uploaded certificates (account-wide)"}
	cert.AddCommand(casListCmd(rt), casUploadCmd(rt), casDeleteCmd(rt))
	cmd.AddCommand(cert)
	return cmd
}

// casCertView is a row of `cas certificate list`.
type casCertView struct {
	ID           string `json:"id" yaml:"id"`
	Name         string `json:"name" yaml:"name"`
	CommonName   string `json:"common_name" yaml:"common_name"`
	StartDate    string `json:"start_date" yaml:"start_date"`
	EndDate      string `json:"end_date" yaml:"end_date"`
	DaysToExpire int    `json:"days_to_expire" yaml:"days_to_expire"`
	Expired      bool   `json:"expired" yaml:"expired"`
	Fingerprint  string `json:"fingerprint_sha1" yaml:"fingerprint_sha1"`
	Sans         string `json:"sans" yaml:"sans"`
}

func casTarget(profile string, c *client) platform.Target {
	return platform.Target{Platform: platform.Aliyun, Profile: profile, Region: c.region}
}

func casResource(id string) string { return "cas/certificate/" + id }

// sortCAS orders certificates by end date, then name, then id.
func sortCAS(certs []casCertificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		a, b := certs[i], certs[j]
		if a.EndDate != b.EndDate {
			return a.EndDate < b.EndDate
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
}

func casSet(profile string) inventory.Set {
	return inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResCertificate}
}

// storeCAS records an uploaded certificate in the inventory.
func storeCAS(ctx context.Context, rt *app.Runtime, profile string, ct casCertificate) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	if err := db.Upsert(ctx, casSet(profile), ct.resource(), cfg.TTLFor(platform.ResCertificate)); err != nil {
		rt.Verbosef("inventory: %v", err)
	}
}

// dropCAS removes a deleted certificate from the inventory.
func dropCAS(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		if err := db.Delete(ctx, casSet(profile), platform.ResCertificate, id); err != nil {
			rt.Verbosef("inventory: %v", err)
		}
	}
}

func casListCmd(rt *app.Runtime) *cobra.Command {
	var name string
	var expired bool
	var within int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the uploaded certificates with their expiry (cached locally)",
		Long: `List the certificates uploaded to CAS (OrderType UPLOAD: neither the free
nor the bought certificate orders), every page, with their common name,
start and end dates (UTC dates, as CAS reports them) and the whole days to
their end date. The list is cached in the local inventory.

A certificate counts as expired from 00:00 UTC of its end date on (CAS keeps
dates only), and so does one without an end date. --expired keeps the
expired ones, --expires-within <days> those with at most that many days
left (expired ones included), --name those whose name holds the text. No
certificate is [], a note on stderr and exit code 0. A RAM user without CAS
permissions is exit code 3.`,
		Example: "  polyctl aliyun cas certificate list --expires-within 30",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			filterWithin := cmd.Flags().Changed("expires-within")
			if filterWithin && within < 0 {
				return app.UsageErrf("--expires-within must not be negative, got %d", within)
			}
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			rows, cached, err := rt.EnsureSet(cmd.Context(), casSet(prof), func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.casResources(ctx, c.account)
			})
			if err != nil {
				return err
			}
			certs := make([]casCertificate, 0, len(rows))
			for _, r := range rows {
				var ct casCertificate
				if err := r.Decode(&ct); err != nil {
					return fmt.Errorf("decode cached certificate %s: %w", r.ID, err)
				}
				certs = append(certs, ct)
			}
			sortCAS(certs)
			now := casNow()
			views := []casCertView{}
			for _, ct := range certs {
				v := casCertView{ID: ct.ID, Name: ct.Name, CommonName: ct.CommonName, StartDate: ct.StartDate, EndDate: ct.EndDate,
					DaysToExpire: ct.daysToExpire(now), Expired: ct.expired(now), Fingerprint: ct.Fingerprint, Sans: ct.Sans}
				switch {
				case name != "" && !strings.Contains(v.Name, name),
					expired && !v.Expired,
					filterWithin && v.DaysToExpire > within:
					continue
				}
				views = append(views, v)
			}
			if len(views) == 0 {
				rt.Infof("note: no uploaded certificates%s via aliyun/%s%s", casFilterNote(name, expired, filterWithin, within), prof, cacheNote(cached))
			} else {
				rt.Infof("%d certificate(s) via aliyun/%s%s", len(views), prof, cacheNote(cached))
			}
			return rt.Render(views, func() output.Grid {
				g := output.Grid{Headers: []string{"ID", "NAME", "COMMON_NAME", "START", "END", "DAYS"}, Empty: "no certificates"}
				for _, v := range views {
					g.Rows = append(g.Rows, []string{v.ID, v.Name, v.CommonName, dashIfEmpty(v.StartDate), dashIfEmpty(v.EndDate), strconv.Itoa(v.DaysToExpire)})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "only the certificates whose name holds this text")
	cmd.Flags().BoolVar(&expired, "expired", false, "only the expired certificates")
	cmd.Flags().IntVar(&within, "expires-within", 0, "only the certificates with at most this many days left (expired ones included)")
	return cmd
}

func casFilterNote(name string, expired, within bool, days int) string {
	var parts []string
	if name != "" {
		parts = append(parts, fmt.Sprintf("named like %q", name))
	}
	if expired {
		parts = append(parts, "expired")
	}
	if within {
		parts = append(parts, fmt.Sprintf("expiring within %d days", days))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// readCASMaterial reads --cert and --key ("-" reads stdin, for one of
// them) and checks them locally: a chain whose first certificate the
// unencrypted key belongs to. Every problem is a usage error (exit code
// 2), raised before any request.
func readCASMaterial(rt *app.Runtime, certFile, keyFile string) (*platform.CertMaterial, error) {
	switch {
	case certFile == "" || keyFile == "":
		return nil, app.UsageErrf("--cert and --key are required (PEM files; - reads stdin)")
	case certFile == "-" && keyFile == "-":
		return nil, app.UsageErrf("--cert and --key cannot both read stdin (-)")
	}
	read := func(flag, path string) ([]byte, error) {
		var b []byte
		var err error
		if path == "-" {
			b, err = io.ReadAll(rt.Stdin)
		} else {
			b, err = os.ReadFile(path)
		}
		if err != nil {
			return nil, app.UsageErrf("--%s: %v", flag, err)
		}
		return b, nil
	}
	c, err := read("cert", certFile)
	if err != nil {
		return nil, err
	}
	k, err := read("key", keyFile)
	if err != nil {
		return nil, err
	}
	return platform.ParseCertMaterial(c, k, casNow())
}

func casUploadCmd(rt *app.Runtime) *cobra.Command {
	var certFile, keyFile string
	cmd := &cobra.Command{
		Use:   "upload <name>",
		Short: "Upload a certificate, or reuse the one of that name",
		Long: `Upload the certificate chain --cert (PEM, leaf first: fullchain.pem) with its
unencrypted PEM private key --key under <name>; "-" reads one of them from
stdin. The files are checked before anything is sent: unreadable PEM, an
encrypted key, a key that does not belong to the first certificate and an
expired certificate are exit code 2.

Names are unique within a CAS store, and certificates are told apart by
name only: when an uploaded certificate has the name already, it is reused
as it is (unchanged, with its id), whatever it holds. Name certificates
after their expiry, upload_<root domain>_<YYYY-MM-DD> (the date of NotAfter,
UTC), so that a renewed certificate gets a new name and is uploaded while
the same one is reused. CAS does not refuse the same certificate under
another name.

The upload is synchronous: the id can be used by ALB listeners at once.
-o json prints the change report; --dry-run checks the files, reads the
list and reports what it would do.`,
		Example: `  polyctl aliyun cas certificate upload upload_example.com_2027-02-01 --cert fullchain.pem --key privkey.pem --dry-run
  polyctl aliyun cas certificate upload upload_example.com_2027-02-01 --cert fullchain.pem --key privkey.pem -o json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := strings.TrimSpace(args[0])
			if name == "" {
				return app.UsageErrf("the certificate name is empty")
			}
			mat, err := readCASMaterial(rt, certFile, keyFile)
			if err != nil {
				return err
			}
			c, p, err := openClient(rt, ctx)
			if err != nil {
				return err
			}
			target := casTarget(p.Name, c)
			end := mat.Leaf.NotAfter.UTC().Format("2006-01-02")
			existing, err := casByName(ctx, c, name)
			if err != nil {
				return err
			}
			if existing != nil {
				return casUnchanged(rt, target, *existing)
			}
			change := platform.Change{Resource: casResource(name), Action: platform.Created, ID: platform.Pending, Detail: "end " + end}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			id, err := c.uploadCASCertificate(ctx, name, string(mat.Fullchain), string(mat.PrivKey))
			if platform.HasErrorCode(err, casCodeNameRepeat) {
				// Uploaded meanwhile by someone else: reuse it.
				if again, lerr := casByName(ctx, c, name); lerr == nil && again != nil {
					return casUnchanged(rt, target, *again)
				}
				return fmt.Errorf("certificate name %q is taken in the CAS store, but no uploaded certificate of that name is listed: %w", name, err)
			}
			if err != nil {
				return err
			}
			s, _ := c.cas()
			storeCAS(ctx, rt, p.Name, casCertificate{ID: id, Name: name, CommonName: mat.Leaf.Subject.CommonName,
				StartDate: mat.Leaf.NotBefore.UTC().Format("2006-01-02"), EndDate: end, NotAfter: end,
				Fingerprint: casSHA1(mat), Sans: strings.Join(mat.Names(), ","), Endpoint: s.Endpoint, Account: c.account, Source: "cas"})
			change.ID = id
			rt.Infof("uploaded certificate %s (id %s) to %s via aliyun/%s", name, id, s.Endpoint, p.Name)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&certFile, "cert", "", "PEM certificate chain, leaf first (fullchain.pem); - reads stdin")
	cmd.Flags().StringVar(&keyFile, "key", "", "unencrypted PEM private key; - reads stdin")
	return cmd
}

// casByName returns the uploaded certificate of the name (exact match), or
// nil.
func casByName(ctx context.Context, c *client, name string) (*casCertificate, error) {
	certs, _, err := c.listCASCertificates(ctx)
	if err != nil {
		return nil, err
	}
	for _, ct := range certs {
		if ct.Name == name {
			return &ct, nil
		}
	}
	return nil, nil
}

func casUnchanged(rt *app.Runtime, target platform.Target, ct casCertificate) error {
	detail := "already uploaded"
	if ct.EndDate != "" {
		detail += ", end " + ct.EndDate
	}
	rep := platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{{Resource: casResource(ct.Name), Action: platform.Unchanged, ID: ct.ID, Detail: detail}}}
	return rt.RenderReport(rep)
}

func casDeleteCmd(rt *app.Runtime) *cobra.Command {
	var expired, force bool
	var regions []string
	cmd := &cobra.Command{
		Use:   "delete [<cert-id>]",
		Short: "Delete an uploaded certificate no ALB listener uses, or every expired one (asks first)",
		Long: `Delete the uploaded certificate <cert-id> (an integer), or with --expired
(and no id) every uploaded certificate that has expired (from 00:00 UTC of
its end date on).

CAS deletes a certificate that a listener still uses without a word, and
the listener keeps a dangling id. So polyctl first reads the HTTPS and QUIC
listeners of the account's ALB load balancers, in every region of the
account or in the --region ones, and refuses to delete a certificate one of
them holds: exit code 1, naming every listener. With --expired such a
certificate is skipped (and reported), and the others are deleted. When the
listeners of a region cannot be read, nothing is deleted: exit code 3 for a
permission denial, 1 otherwise, naming the region. Only ALB listeners are
checked (classic load balancers, API gateways, WAF and other products are
not), which a note on stderr says.

--force deletes without the check: listeners that use the certificate stop
working. A confirmation is asked first (default no; --yes skips it, and the
non-interactive flow needs --yes). A missing certificate is exit code 4; a
deletion of --expired that fails is reported, the others go on, and the
command ends with exit code 1. --dry-run runs the check (it only reads) and
reports what would be deleted, skipped or refused, without asking.`,
		Example: `  polyctl aliyun cas certificate delete 1234567
  polyctl aliyun cas certificate delete --expired -y`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var id string
			switch {
			case expired && len(args) == 1:
				return app.UsageErrf("--expired deletes every expired certificate: pass either <cert-id> or --expired")
			case !expired && len(args) == 0:
				return app.UsageErrf("pass the id of the certificate to delete, or --expired")
			case len(args) == 1:
				id = strings.TrimSpace(args[0])
				if n, err := strconv.ParseInt(id, 10, 64); err != nil || n <= 0 {
					return app.UsageErrf("certificate id %q is not a positive integer", args[0])
				}
			}
			if !rt.DryRun() {
				what := "delete certificate " + id
				if expired {
					what = "delete the expired certificates"
				}
				if err := rt.CanConfirm(what); err != nil {
					return err
				}
			}
			c, p, err := openClient(rt, ctx)
			if err != nil {
				return err
			}
			certs, s, err := c.listCASCertificates(ctx)
			if err != nil {
				return err
			}
			d := casDeleter{rt: rt, c: c, profile: p.Name, store: s, force: force, regions: regions}
			if expired {
				return d.expired(ctx, certs)
			}
			for _, ct := range certs {
				if ct.ID == id {
					return d.one(ctx, ct)
				}
			}
			return fmt.Errorf("%w: certificate %s is not in the CAS store %s (aliyun/%s)", platform.ErrNotFound, id, s.Endpoint, p.Name)
		},
	}
	cmd.Flags().BoolVar(&expired, "expired", false, "delete every expired uploaded certificate (without <cert-id>)")
	cmd.Flags().BoolVar(&force, "force", false, "delete without checking whether ALB listeners use the certificate")
	cmd.Flags().StringSliceVar(&regions, "region", nil, "regions whose ALB listeners are checked (default: every region of the account)")
	return cmd
}

// casDeleter deletes uploaded certificates after the reference check.
type casDeleter struct {
	rt      *app.Runtime
	c       *client
	profile string
	store   casScope
	force   bool
	regions []string
}

func (d *casDeleter) target() platform.Target { return casTarget(d.profile, d.c) }

// references reads the ALB listeners once for every certificate of the
// command; nil with --force.
func (d *casDeleter) references(ctx context.Context) (*casReferences, error) {
	if d.force {
		return nil, nil
	}
	regions, err := d.c.albRegions(ctx, d.regions)
	if err != nil {
		return nil, err
	}
	d.rt.Verbosef("checking the ALB listeners of %s", strings.Join(regions, ", "))
	refs, err := d.c.casCertificateReferences(ctx, regions)
	if err != nil {
		return nil, err
	}
	d.rt.Infof("%s", casOnlyALBNote)
	return refs, nil
}

func casLabel(ct casCertificate) string {
	label := ct.ID
	if ct.Name != "" {
		label += " (" + ct.Name
		if ct.EndDate != "" {
			label += ", end " + ct.EndDate
		}
		label += ")"
	}
	return label
}

func casRefList(refs []casReference) string {
	parts := make([]string, 0, len(refs))
	for _, r := range refs {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, "; ")
}

func (d *casDeleter) deleteStep(ct casCertificate) platform.Step {
	return platform.Step{Resource: casResource(ct.ID), Action: platform.Deleted, ID: ct.ID, Desc: ct.Name,
		Apply: func(ctx context.Context) (platform.Change, error) {
			if err := d.c.deleteCASCertificate(ctx, ct.ID); err != nil {
				return platform.Change{ID: ct.ID}, err
			}
			dropCAS(ctx, d.rt, d.profile, ct.ID)
			return platform.Change{}, nil
		}}
}

func (d *casDeleter) one(ctx context.Context, ct casCertificate) error {
	refs, err := d.references(ctx)
	if err != nil {
		return err
	}
	if used := refs.of(ct.ID); len(used) > 0 {
		if d.rt.DryRun() {
			d.rt.Infof("dry run: would refuse %s: used by %s", casResource(ct.ID), casRefList(used))
			return d.rt.RenderReport(platform.Report{Target: d.target(), DryRun: true, Changes: []platform.Change{{Resource: casResource(ct.ID),
				Action: platform.Skipped, ID: ct.ID, Detail: "would refuse: used by " + casRefList(used)}}})
		}
		for _, r := range used {
			d.rt.Infof("cannot delete certificate %s: used by %s", ct.ID, r)
		}
		return fmt.Errorf("certificate %s is used by %d ALB listener(s): switch them to another certificate first, or pass --force to delete it anyway", ct.ID, len(used))
	}
	change := platform.Change{Resource: casResource(ct.ID), Action: platform.Deleted, ID: ct.ID, Detail: ct.Name}
	if done, err := d.rt.WouldWrite(d.target(), change); done || err != nil {
		return err
	}
	question := fmt.Sprintf("Delete certificate %s from %s?", casLabel(ct), d.store.Endpoint)
	if d.force {
		question = fmt.Sprintf("Delete certificate %s from %s without checking ALB listeners? Listeners that use it stop working", casLabel(ct), d.store.Endpoint)
	}
	ok, err := d.rt.Confirm(ctx, question, false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: certificate %s was not deleted", platform.ErrNothingToDo, ct.ID)
	}
	plan := platform.Plan{Steps: []platform.Step{d.deleteStep(ct)}}
	rep, err := d.rt.RunPlan(ctx, d.target(), &plan)
	if err != nil {
		return err
	}
	d.rt.Infof("deleted certificate %s via aliyun/%s", casLabel(ct), d.profile)
	return d.rt.RenderReport(rep)
}

func (d *casDeleter) expired(ctx context.Context, certs []casCertificate) error {
	now := casNow()
	var old []casCertificate
	for _, ct := range certs {
		if ct.expired(now) {
			old = append(old, ct)
		}
	}
	sortCAS(old)
	if len(old) == 0 {
		d.rt.Infof("note: no expired uploaded certificates in %s via aliyun/%s", d.store.Endpoint, d.profile)
		return d.rt.RenderReport(platform.Report{Target: d.target(), DryRun: d.rt.DryRun()})
	}
	refs, err := d.references(ctx)
	if err != nil {
		return err
	}
	plan := platform.Plan{ContinueOnError: true}
	var doomed []casCertificate
	for _, ct := range old {
		if used := refs.of(ct.ID); len(used) > 0 {
			plan.Add(platform.Step{Resource: casResource(ct.ID), Action: platform.Skipped, ID: ct.ID, Desc: "used by " + casRefList(used)})
			continue
		}
		doomed = append(doomed, ct)
		plan.Add(d.deleteStep(ct))
	}
	if len(doomed) > 0 && !d.rt.DryRun() {
		d.rt.Infof("expired certificates to delete from %s:", d.store.Endpoint)
		for _, ct := range doomed {
			d.rt.Infof("  %s", casLabel(ct))
		}
		question := fmt.Sprintf("Delete %d expired certificate(s)?", len(doomed))
		if d.force {
			question = fmt.Sprintf("Delete %d expired certificate(s) without checking ALB listeners?", len(doomed))
		}
		ok, err := d.rt.Confirm(ctx, question, false)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: no certificate was deleted", platform.ErrNothingToDo)
		}
	}
	rep, err := d.rt.RunPlan(ctx, d.target(), &plan)
	sum := platform.Summarize(rep.Changes)
	rep.Summary = &sum
	if rerr := d.rt.RenderReport(rep); rerr != nil && err == nil {
		err = rerr
	}
	var pe *platform.PartialError
	if errors.As(err, &pe) {
		return fmt.Errorf("%d of %d expired certificate deletion(s) failed; first error: %v", pe.Failed, len(doomed), pe.First)
	}
	return err
}

// casSHA1 is the SHA-1 fingerprint of the leaf as CAS writes it:
// upper-case hexadecimal without colons.
func casSHA1(m *platform.CertMaterial) string {
	sum := sha1.Sum(m.Leaf.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}
