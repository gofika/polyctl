package gcp

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// coverage is what the clients of one opened account share, whatever
// project each is bound to (inProject, pin): the account they belong to
// and what one run learned about its projects.
type coverage struct {
	// profile names the account in notes; def is its default project.
	profile, def string
	// disabled are the projects the user disabled: never synced, listed
	// or searched.
	disabled []string

	// listMu guards the list of the visible projects, asked once
	// (visibleProjects): visible are the active projects the credentials
	// see, canList is false, and cannotList the answer, when they may not
	// list projects.
	listMu     sync.Mutex
	listed     bool
	visible    []*cloudresourcemanager.Project
	canList    bool
	cannotList error

	mu sync.Mutex
	// held are the projects the inventory holds rows of, as a command
	// found: the syncs cover them, which saves asking (cacheable).
	held map[string]bool
	// off holds "<project>/<api>" of the projects that answered that the
	// API is not enabled (or billing is off), so that the later types of
	// one sync do not ask them again.
	off map[string]bool
	// skipped are the projects a live list left out because the API is
	// not enabled in them, so that its status line counts the projects
	// that answered (projectsLabel).
	skipped map[string]bool
	// zones holds the managed zones the zone sync listed, per project,
	// for the record sync that follows it.
	zones map[string][]platform.Zone
}

// The APIs a project may have switched off, as coverage.off names them.
const (
	apiDNS     = "dns"
	apiCompute = "compute"
)

// apiOfType is the API that holds a resource type.
func apiOfType(rt platform.ResourceType) string {
	switch rt {
	case platform.ResZone, platform.ResDNSRecord:
		return apiDNS
	}
	return apiCompute
}

// isOff reports whether the project already answered, in this run, that
// the API is not enabled.
func (c *client) isOff(project, api string) bool {
	if c.cov == nil {
		return false
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	return c.cov.off[project+"/"+api]
}

// markOff remembers that the API is not enabled in the project.
func (c *client) markOff(project, api string) {
	if c.cov == nil {
		return
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	if c.cov.off == nil {
		c.cov.off = map[string]bool{}
	}
	c.cov.off[project+"/"+api] = true
}

// markSkipped remembers that a live list left the project out.
func (c *client) markSkipped(project string) {
	if c.cov == nil {
		return
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	if c.cov.skipped == nil {
		c.cov.skipped = map[string]bool{}
	}
	c.cov.skipped[project] = true
}

// answered are the projects of the list that no live list left out; all
// of them when none answered, since the label has to name a place.
func (c *client) answered(projects []string) []string {
	if c.cov == nil {
		return projects
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	var out []string
	for _, p := range projects {
		if !c.cov.skipped[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return projects
	}
	return out
}

// keepZones stores the managed zones just listed of the client's project
// for the record sync of the same run.
func (c *client) keepZones(zones []platform.Zone) {
	if c.cov == nil {
		return
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	if c.cov.zones == nil {
		c.cov.zones = map[string][]platform.Zone{}
	}
	c.cov.zones[c.project] = zones
}

// takeZones returns the zones keepZones stored for the client's project,
// once: a later record sync lists them again, since zones may have been
// created or deleted in between.
func (c *client) takeZones() ([]platform.Zone, bool) {
	if c.cov == nil {
		return nil, false
	}
	c.cov.mu.Lock()
	defer c.cov.mu.Unlock()
	zones, ok := c.cov.zones[c.project]
	delete(c.cov.zones, c.project)
	return zones, ok
}

// accountLabel names the account of the client: "gcp/<profile>".
func (c *client) accountLabel() string {
	if c.cov == nil || c.cov.profile == "" {
		return string(platform.GCP)
	}
	return string(platform.GCP) + "/" + c.cov.profile
}

// profileFlag is " --profile <name>" for the account label
// "gcp/<profile>", "" for a label that names no profile. A hint that
// names a command carries it: the note may be about an account of
// another profile than the one the command would pick (a sync walks
// every profile), and the command copied as it is has to reach the
// account the note is about.
func profileFlag(account string) string {
	if _, profile, ok := strings.Cut(account, "/"); ok && profile != "" {
		return " --profile " + profile
	}
	return ""
}

// notef prints a note about projects that were left out (stderr). Tests
// replace it to capture the output.
var notef = func(format string, args ...any) {
	fmt.Fprintln(os.Stderr, output.Clean(fmt.Sprintf(format, args...)))
}

// offProject is a project that was skipped because an API is not enabled
// in it, waiting to be named in a note.
type offProject struct {
	project, api string
	isDefault    bool
}

// offNotes are the skipped projects of this run: named holds
// "<account>/<project>" of those already told to the user, who is told
// once about each, and pending those of each account not told yet.
var offNotes = struct {
	mu      sync.Mutex
	named   map[string]bool
	pending map[string][]offProject
}{named: map[string]bool{}, pending: map[string][]offProject{}}

// resetOffNotes forgets what the run already told (tests).
func resetOffNotes() {
	offNotes.mu.Lock()
	defer offNotes.mu.Unlock()
	offNotes.named, offNotes.pending = map[string]bool{}, map[string][]offProject{}
}

// apiNameRE finds the API in the answer of a project that does not have
// it: "Compute Engine API has not been used in project 12 before ...".
var apiNameRE = regexp.MustCompile(`([A-Z][A-Za-z0-9 ]*API) has not been used`)

// apiNameOf names the API an isAPIDisabled answer is about, "an API" when
// the answer does not tell.
func apiNameOf(err error) string {
	var ge *googleapi.Error
	if errors.As(err, &ge) {
		if m := apiNameRE.FindStringSubmatch(ge.Message); m != nil {
			return m[1]
		}
	}
	return "an API"
}

// noteOff records that a sweep skipped the project because of err, an
// isAPIDisabled answer. flushOff tells the user.
func (c *client) noteOff(project string, err error) {
	account := c.accountLabel()
	offNotes.mu.Lock()
	defer offNotes.mu.Unlock()
	if key := account + "/" + project; !offNotes.named[key] {
		offNotes.named[key] = true
		offNotes.pending[account] = append(offNotes.pending[account],
			offProject{project: project, api: apiNameOf(err), isDefault: c.cov != nil && project == c.cov.def})
	}
}

// flushOff tells, in one note, the projects of the client's account that
// were skipped since the last note, and how to stop asking them (the
// command names the profile of the account). The default project cannot
// be disabled, so the hint leaves it out.
func (c *client) flushOff() { flushOffNotes(c.accountLabel()) }

func flushOffNotes(account string) {
	offNotes.mu.Lock()
	list := offNotes.pending[account]
	delete(offNotes.pending, account)
	offNotes.mu.Unlock()
	if len(list) == 0 {
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].project < list[j].project })
	var names, others []string
	for _, p := range list {
		names = append(names, p.project+" ("+p.api+")")
		if !p.isDefault {
			others = append(others, p.project)
		}
	}
	msg := fmt.Sprintf("note: %s: skipped %d project(s) in which an API is not enabled or billing is off: %s; they hold nothing there.",
		account, len(list), strings.Join(names, ", "))
	if len(others) > 0 {
		msg += " To stop asking them: polyctl gcp project disable " + strings.Join(others, " ") + profileFlag(account)
	}
	notef("%s", msg)
}
