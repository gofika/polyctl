package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
)

// readDoc reads a document of the repository, given relative to its root,
// with the line endings of a checkout on Windows made those of the source.
func readDoc(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

// The documents describe the projects and accounts of a login as enabled,
// disabled and default: sentences that described behaviour which changed
// since must not come back. gone are phrases a document no longer holds,
// has phrases it holds instead.
func TestDocsDescribeEnabledProjectsAndAccounts(t *testing.T) {
	for _, tc := range []struct {
		doc       string
		gone, has []string
	}{
		{
			doc: "docs/platforms/cloudflare.md",
			gone: []string{
				"the selection of the login", "an account that was added",
				"the list of `enable` / `disable` are not available to it",
				"credentials that can list their accounts (exit code 2 otherwise",
				"`enable` and `disable` open the same list", "polyctl cf account disable   ", "account disable [<account>...]",
				"the list of `enable` / `disable`",
			},
			has: []string{
				"or the disabled accounts of the login changed", "an account that was enabled again is seen",
				"Credentials that cannot list their accounts are offered the accounts read off their zones",
				"it counts as enabled already (exit code 0)",
				"`enable` manages which accounts are enabled", "`disable` never opens the list",
			},
		},
		{
			doc: "docs/platforms/gcp.md",
			gone: []string{
				"A disabled API or a missing permission (", "one note per run on stderr names the skipped projects", "acme-dns (Compute Engine API), acme-lab (Cloud DNS API)",
				"`enable` and `disable` open the same list", "polyctl gcp project disable   ", "disable [<project-id>...]",
				"the list of `enable` / `disable`", "with `polyctl gcp project disable`.",
			},
			has: []string{
				"Each project is named once per run. The projects one listing skipped share a note",
				"A command that works on one project (a change, or a list or lookup of the project named with `--project`) and meets a disabled API is exit code 3",
				"A list, lookup or sync over the enabled projects does not fail for it",
				"`enable` manages which projects are enabled", "`disable` never opens the list",
				"To stop asking them: polyctl gcp project disable acme-lab --profile acme",
			},
		},
		{
			doc:  "docs/interactive.md",
			gone: []string{"`enable` and `disable` without", "in both commands"},
			has:  []string{"`gcp project disable` never opens the list", "`cloudflare account disable` never opens the list"},
		},
		{
			doc:  "docs/accounts.md",
			gone: []string{"both commands open one list"},
			has:  []string{"`polyctl gcp project enable` and `polyctl cloudflare account enable` manage which ones are enabled", "`disable` always needs them (exit code 2 without)"},
		},
	} {
		text := readDoc(t, tc.doc)
		for _, phrase := range tc.gone {
			if strings.Contains(text, phrase) {
				t.Errorf("%s still says %q", tc.doc, phrase)
			}
		}
		for _, phrase := range tc.has {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s does not say %q", tc.doc, phrase)
			}
		}
	}
}

// What dns ensure changes is stated where a user meets it: the help of dns
// ensure and dns add, and the documents.
func TestDNSEnsureRulesAreDocumented(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	ensure, add := find(root, "dns ensure"), find(root, "dns add")
	help := strings.Join(strings.Fields(ensure.Long), " ")
	for _, phrase := range []string{
		"What ensure changes",
		"No record: the record is created.",
		"One record of the type: unchanged when it is as desired, else updated in place",
		"One record of another type: replaced, which deletes it and then creates the record. A terminal shows it and asks first (default no); a script needs --yes",
		"the records of other types are left alone",
		"several records of a name are never deleted without a terminal",
		"Several records of the type (duplicates)",
		"For more than one record on a name, or records of several types, use `polyctl dns add`.",
		"the error names them with the `polyctl dns add` commands that restore them",
		"A record that belongs to another service of the platform (the CNAME of a Cloudflare R2 custom domain) is never replaced",
	} {
		if !strings.Contains(help, phrase) {
			t.Errorf("dns ensure --help does not say %q", phrase)
		}
	}
	if !strings.Contains(ensure.Short, "replace the one record of another type") || !strings.Contains(ensure.Example, "--yes   # replaces the A record of www") {
		t.Errorf("dns ensure short %q / examples %q", ensure.Short, ensure.Example)
	}
	if h := strings.Join(strings.Fields(add.Long), " "); !strings.Contains(h, "records of several types on one name") || !strings.Contains(h, "dns ensure is for a name with one record") {
		t.Errorf("dns add --help does not point to it for several records of a name:\n%s", add.Long)
	}
	for _, tc := range []struct {
		doc       string
		gone, has []string
	}{
		{
			doc:  "docs/commands.md",
			gone: []string{"A CNAME whose name already has A / AAAA records (or the reverse) fails before anything is written"},
			has: []string{"#### What ensure changes", "| one record of another type | replaces it: deletes it, then creates the record.",
				"A script stops with exit code 5, with or without `--yes`", "Several records of a name are never deleted without a terminal",
				"prints the `polyctl dns add ...` command that restores it (exit code 1)", "`replaced_by`",
				"for more than one record on a name, or records of several types, use `dns add`",
				"(the CNAME of a Cloudflare R2 custom domain, which the DNS API cannot delete) is never replaced"},
		},
		{doc: "docs/interactive.md", has: []string{"- Core: `dns ensure` before it replaces the records of another type on a name", "| `dns ensure` on a name that holds several records of other types"}},
		{doc: "docs/configuration.md", has: []string{"or a name with several records of other types (also with `--yes`", "also `dns ensure` replacing the record of another type on a name"}},
		{doc: "README.md", has: []string{"# replaces the one record of www (asks first; --yes in scripts)"}},
	} {
		text := readDoc(t, tc.doc)
		for _, phrase := range tc.gone {
			if strings.Contains(text, phrase) {
				t.Errorf("%s still says %q", tc.doc, phrase)
			}
		}
		for _, phrase := range tc.has {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s does not say %q", tc.doc, phrase)
			}
		}
	}
}
