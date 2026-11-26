package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
