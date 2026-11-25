package cloudflare

import (
	"context"
	"slices"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
)

// ---------------------------------------------------------------- account

func newAccountCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Cloudflare accounts of the login: the selected ones and the default",
		Long: `A Cloudflare login works on the accounts selected for it: the inventory, name
lookups and domain routing cover all of them. One of them is the default
account, where new zones are created. The login selects them.

An account that is not selected can still be named with --account on the
cloudflare zone, dns, cache, redirect, dev-mode, ssl-mode and r2 commands: it
is read live and nothing of it is cached.`,
	}
	cmd.AddCommand(newAccountListCmd(rt))
	return cmd
}

// accountRow is an account as account list shows it. The first three
// fields are the account as Cloudflare lists it.
type accountRow struct {
	ID       string `json:"id" yaml:"id"`
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Selected bool   `json:"selected" yaml:"selected"`
	Default  bool   `json:"default" yaml:"default"`
}

type accountListResult struct {
	Profile  string       `json:"profile" yaml:"profile"`
	Accounts []accountRow `json:"accounts" yaml:"accounts"`
}

// accountRows marks the selection of a login in the accounts its
// credentials list. A selected account the list does not show is appended
// without a type, and returned as unseen.
func accountRows(accounts []account, def, defName string, selected []string) (rows []accountRow, unseen []string) {
	rows = make([]accountRow, 0, len(accounts))
	seen := map[string]bool{}
	for _, a := range accounts {
		seen[a.ID] = true
		rows = append(rows, accountRow{ID: a.ID, Name: a.Name, Type: a.Type, Selected: slices.Contains(selected, a.ID), Default: a.ID == def})
	}
	for _, id := range selected {
		if seen[id] {
			continue
		}
		row := accountRow{ID: id, Selected: true, Default: id == def}
		if row.Default {
			row.Name = defName
		}
		rows = append(rows, row)
		unseen = append(unseen, id)
	}
	return rows, unseen
}

// accountGrid is the table of account list: * marks the default account.
func accountGrid(rows []accountRow) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "ID", "SELECTED"}, Empty: "no accounts"}
	for _, r := range rows {
		name, sel := r.Name, ""
		if r.Default {
			name += " *"
		}
		if r.Selected {
			sel = "yes"
		}
		g.Rows = append(g.Rows, []string{name, r.Type, r.ID, sel})
	}
	return g
}

// listedAccounts reads the accounts the credentials of a profile list,
// with the selection of its login marked.
func listedAccounts(ctx context.Context, rt *app.Runtime, s *session) ([]accountRow, []string, error) {
	accounts, err := s.client.api.listAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	def, defName, selected, err := loginAccounts(rt, s.profile)
	if err != nil {
		return nil, nil, err
	}
	rows, unseen := accountRows(accounts, def, defName, selected)
	return rows, unseen, nil
}

func newAccountListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the accounts visible to the credentials, with the selected and the default ones marked",
		Long: `List the accounts visible to the profile's credentials (API token:
Account:Read; browser login: the account-settings.read scope). SELECTED marks
the accounts the login works on, and * the default one; a selected account the
credentials do not list is shown without a type, with a note.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rows, unseen, err := listedAccounts(cmd.Context(), rt, s)
			if err != nil {
				return err
			}
			selected := 0
			for _, r := range rows {
				if r.Selected {
					selected++
				}
			}
			for _, id := range unseen {
				rt.Infof("note: selected account %s is not visible to the credentials (to take it out: polyctl cloudflare account remove %s)", id, id)
			}
			rt.Infof("%d account(s) via cloudflare/%s, %d selected", len(rows), s.profile, selected)
			return rt.Render(accountListResult{Profile: s.profile, Accounts: rows}, func() output.Grid { return accountGrid(rows) })
		},
	}
}
