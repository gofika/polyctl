package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// Secrets returns (once) the store of instance login credentials: sealed
// rows in the inventory database, with the data key in the credential
// store.
func (rt *Runtime) Secrets() (*secrets.Store, error) {
	if rt.secrets != nil {
		return rt.secrets, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	st, err := rt.Creds()
	if err != nil {
		return nil, err
	}
	rt.secrets = secrets.New(db, st)
	return rt.secrets, nil
}

// PrepareSecrets makes sure credentials can be stored before an instance
// is created: the database opens and the data key exists (it is created
// on first use). A create that generates a password calls it before its
// first write, so that the password is never lost to a store that turns
// out to be unusable once the instance exists. It writes the data key, so
// a dry run must not call it.
func (rt *Runtime) PrepareSecrets() error {
	if rt.DryRun() {
		return nil
	}
	st, err := rt.Secrets()
	if err != nil {
		return err
	}
	return st.Ready()
}

// PasswordCommandLine is the command that shows the stored password of an
// instance, for notes: tree is the instance group ("aliyun ecs instance").
func PasswordCommandLine(tree, instance string) string {
	return "polyctl " + tree + " password " + instance
}

// SaveCredentials stores the login credentials of an instance a create
// made and shows them as ShowCredentials does. A dry run stores and shows
// nothing. When they cannot be stored, the interactive flow still shows
// them (with a warning, as they are shown only this once) and the command
// succeeds; the non-interactive flow, which never prints a password, fails
// with an error that says so (without the password).
func (rt *Runtime) SaveCredentials(ctx context.Context, c secrets.Credentials, tree string) error {
	if rt.DryRun() {
		return nil
	}
	st, err := rt.Secrets()
	if err == nil {
		err = st.Put(ctx, c)
	}
	if err != nil {
		if rt.Interactive() && c.Password != "" {
			rt.Infof("warning: the credentials of instance %s could not be stored (%v): note them now, polyctl cannot show them again", label(c), err)
			rt.showCredentials(c, tree, false)
			return nil
		}
		return fmt.Errorf("instance %s was created, but its login credentials could not be stored: %w (reset the password in the platform's console)", label(c), err)
	}
	rt.ShowCredentials(c, tree)
	return nil
}

// ShowCredentials tells the user the login of an instance after a create.
// In the interactive flow the user name and the password are printed,
// clearly labelled: on stdout when the output is a table, on stderr (the
// terminal) with -o json or -o yaml, so that stdout stays one document. In
// the non-interactive flow the password is never printed: a note on stderr
// names the user and the command that shows the password.
func (rt *Runtime) ShowCredentials(c secrets.Credentials, tree string) {
	if rt.DryRun() {
		return
	}
	rt.showCredentials(c, tree, true)
}

func (rt *Runtime) showCredentials(c secrets.Credentials, tree string, stored bool) {
	cmd := PasswordCommandLine(tree, instanceArg(c))
	if !rt.Interactive() {
		if c.Password == "" {
			rt.Infof("note: the Windows password of instance %s is not available yet; `%s` shows it once the instance has generated it (user %s)", label(c), cmd, c.User)
			return
		}
		rt.Infof("note: the Windows login of instance %s is stored encrypted in polyctl's database: user %s; `%s` shows the password", label(c), c.User, cmd)
		return
	}
	var w io.Writer = rt.Stdout
	if rt.format != output.Table && rt.format != "" {
		w = rt.Stderr
	}
	fmt.Fprintf(w, "\nWindows login of instance %s:\n", label(c))
	fmt.Fprintf(w, "  user:     %s\n", c.User)
	if c.Password == "" {
		fmt.Fprintf(w, "  password: not available yet; `%s` shows it once the instance has generated it\n", cmd)
		return
	}
	fmt.Fprintf(w, "  password: %s\n", c.Password)
	if stored {
		fmt.Fprintf(w, "Stored encrypted in polyctl's database; `%s` shows it again.\n", cmd)
	}
}

// label names an instance in messages: "name (id)".
func label(c secrets.Credentials) string {
	if c.Name == "" || c.Name == c.InstanceID {
		return c.InstanceID
	}
	return c.Name + " (" + c.InstanceID + ")"
}

// instanceArg is how the password command is told the instance: its id,
// which is unique (names need not be).
func instanceArg(c secrets.Credentials) string { return c.InstanceID }

// ForgetCredentials removes the stored credentials of an instance after it
// was deleted. It is best effort: a failure is a warning, the delete
// stands. A dry run removes nothing.
func (rt *Runtime) ForgetCredentials(ctx context.Context, ref secrets.Ref) {
	if rt.DryRun() {
		return
	}
	st, err := rt.Secrets()
	if err == nil {
		err = st.Delete(ctx, ref)
	}
	if err != nil {
		rt.Infof("warning: the stored credentials of deleted instance %s could not be removed: %v", ref.InstanceID, err)
	}
}

// InstanceLogin is the result of an `instance password` command.
type InstanceLogin struct {
	Instance  string      `json:"instance" yaml:"instance"`
	ID        string      `json:"id" yaml:"id"`
	User      string      `json:"user" yaml:"user"`
	Password  string      `json:"password" yaml:"password"`
	Platform  platform.ID `json:"platform" yaml:"platform"`
	Profile   string      `json:"profile" yaml:"profile"`
	Location  string      `json:"location" yaml:"location"`
	UpdatedAt time.Time   `json:"updated_at" yaml:"updated_at"`
}

// PasswordCommand describes the `instance password` command of a platform.
type PasswordCommand struct {
	Platform platform.ID
	// Tree is the instance group ("aliyun ecs instance").
	Tree string
	// LocationFlag is the flag that narrows the lookup to one location
	// ("region" or "zone"); "" registers none.
	LocationFlag string
	// Detail is the platform's paragraph of the help.
	Detail string
	// Retrieve, when set, fetches credentials the store cannot answer
	// with: no row for the instance (stored is nil), or a row whose
	// password is not known yet (an AWS password still being generated).
	// It returns an error wrapping platform.ErrNotFound when there is
	// nothing to fetch. It is never called with --offline. A password it
	// returns is stored before it is shown.
	Retrieve func(ctx context.Context, profile, location, instance string, stored *secrets.Credentials) (*secrets.Credentials, error)
}

// InstancePasswordCommand builds `<tree> password <name|id>`: it shows the
// Windows user name and password polyctl stored when it created the
// instance (table: INSTANCE, USER, PASSWORD; -o json / -o yaml: an object
// with instance, id, user, password, platform, profile, location and
// updated_at).
func InstancePasswordCommand(rt *Runtime, pc PasswordCommand) *cobra.Command {
	var location string
	long := "Show the Windows user name and password of an instance created by polyctl\n" +
		"with --os windows. create stores them encrypted in polyctl's database\n" +
		"(inventory.db, AES-256-GCM, with the data key in the OS keyring or\n" +
		"credentials.json); this command decrypts and prints them. It is the only\n" +
		"command besides an interactive create that prints a password: treat its\n" +
		"output as a secret. It reads nothing but the local database"
	if pc.Retrieve != nil {
		long += ",\nunless the platform has to be asked (see below)"
	}
	long += ".\n\nThe instance is given by its id or its name; a name stored for several\n" +
		"instances is exit code 5 (pass the id"
	if pc.LocationFlag != "" {
		long += " or --" + pc.LocationFlag
	}
	long += "). An instance with no\nstored credentials is exit code 4; credentials that cannot be decrypted (the\n" +
		"data key was removed from the credential store) are exit code 1."
	if pc.Detail != "" {
		long += "\n\n" + pc.Detail
	}
	cmd := &cobra.Command{
		Use:   "password <name|id>",
		Short: "Show the stored Windows user name and password of an instance",
		Long:  long,
		Example: "  polyctl " + pc.Tree + " password win-1\n" +
			"  polyctl " + pc.Tree + " password win-1 -o json",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 || args[0] == "" {
				return UsageErrf("the instance name or id is required: %s", cmd.UseLine())
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref := args[0]
			profile, err := rt.ProfileFor(pc.Platform)
			if err != nil {
				return err
			}
			st, err := rt.Secrets()
			if err != nil {
				return err
			}
			found, err := st.Find(ctx, pc.Platform, profile, location, ref)
			if err != nil {
				return err
			}
			if len(found) > 1 {
				cands := make([]string, 0, len(found))
				for _, c := range found {
					cands = append(cands, c.InstanceID+" ("+c.Location+")")
				}
				hint := "pass the instance id"
				if pc.LocationFlag != "" {
					hint += " or --" + pc.LocationFlag
				}
				return &AmbiguousError{What: "instance " + ref, Candidates: cands, Hint: hint}
			}
			var cur *secrets.Credentials
			if len(found) == 1 {
				cur = &found[0]
			}
			if (cur == nil || cur.Password == "") && pc.Retrieve != nil && !rt.Flags.Offline {
				got, err := pc.Retrieve(ctx, profile, location, ref, cur)
				switch {
				case err == nil && got != nil:
					if got.Password != "" && (cur == nil || cur.Password != got.Password) {
						if err := st.Put(ctx, *got); err != nil {
							rt.Infof("warning: the retrieved credentials could not be stored: %v", err)
						}
					}
					cur = got
				case err != nil && !errors.Is(err, platform.ErrNotFound):
					return err
				}
			}
			if cur == nil {
				return fmt.Errorf("%w: no Windows credentials stored for instance %q in profile %s: polyctl stores them when it creates an instance with --os windows; for another instance reset the password in the platform's console",
					platform.ErrNotFound, ref, profile)
			}
			if cur.Password == "" {
				return fmt.Errorf("%w: the Windows password of instance %s is not available yet (the instance generates it a few minutes after launch); run the command again later",
					platform.ErrNotFound, label(*cur))
			}
			v := InstanceLogin{Instance: cur.Name, ID: cur.InstanceID, User: cur.User, Password: cur.Password,
				Platform: cur.Platform, Profile: cur.Profile, Location: cur.Location, UpdatedAt: cur.UpdatedAt}
			if v.Instance == "" {
				v.Instance = v.ID
			}
			return rt.Render(v, func() output.Grid {
				return output.Grid{Headers: []string{"INSTANCE", "USER", "PASSWORD"}, Rows: [][]string{{label(*cur), v.User, v.Password}}}
			})
		},
	}
	if pc.LocationFlag != "" {
		cmd.Flags().StringVar(&location, pc.LocationFlag, "", "look only at the instances of this "+pc.LocationFlag+" (default: every "+pc.LocationFlag+")")
	}
	return cmd
}
