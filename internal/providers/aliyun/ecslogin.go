package aliyun

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// ecsInstanceTree is the command group of ECS instances, as the notes
// about the password command name it.
const ecsInstanceTree = "aliyun ecs instance"

// windowsUser is the login of an ECS Windows instance: RunInstances sets
// the password of Administrator.
const windowsUser = "Administrator"

// windowsLogin is the login of a Windows instance a create or ensure
// makes. The run step generates the password right before RunInstances
// (never in a dry run) and stores it, sealed, as soon as the instance id
// is known; finish shows it once the plan has run.
type windowsLogin struct {
	rt   *app.Runtime
	s    *ecsScope
	name string

	password string
	id       string
	// stored reports that the credentials were stored when the instance
	// was created; finish stores them again (and reports a failure) when
	// not.
	stored bool
}

func newWindowsLogin(rt *app.Runtime, s *ecsScope, name string) *windowsLogin {
	return &windowsLogin{rt: rt, s: s, name: name}
}

// generate returns the password of the instance, generated on the first
// call: a RunInstances asked again (under a new client token) sends the
// same password.
func (w *windowsLogin) generate() (string, error) {
	if w.password != "" {
		return w.password, nil
	}
	p, err := secrets.GeneratePassword()
	if err != nil {
		return "", err
	}
	w.password = p
	return p, nil
}

func (w *windowsLogin) credentials() secrets.Credentials {
	return secrets.Credentials{Ref: secrets.Ref{Platform: platform.Aliyun, Profile: w.s.profile, Location: w.s.region, InstanceID: w.id},
		Name: w.name, User: windowsUser, Password: w.password}
}

// created stores the credentials of the instance RunInstances made. A
// failure is left to finish, which tries again and reports it.
func (w *windowsLogin) created(ctx context.Context, id string) {
	w.id = id
	st, err := w.rt.Secrets()
	if err == nil {
		err = st.Put(ctx, w.credentials())
	}
	w.stored = err == nil
}

// pendingInstancePrefix starts the instance id under which the login of an
// instance whose RunInstances result is unknown is stored: the password
// command finds it by the instance name.
const pendingInstancePrefix = "pending-"

// pending stores the password of an instance whose RunInstances result is
// unknown, under the client token of the request and the instance name, so
// that it survives the run. Nothing is shown: finish has no instance id.
// A cancelled or timed out run (one way the result becomes unknown) still
// stores it.
func (w *windowsLogin) pending(ctx context.Context, token string) {
	if w.password == "" {
		return
	}
	w.id = pendingInstancePrefix + token
	st, err := w.rt.Secrets()
	if err == nil {
		err = st.Put(context.WithoutCancel(ctx), w.credentials())
	}
	w.id = ""
	if err != nil {
		w.rt.Infof("warning: the generated password could not be stored: if instance %s exists, reset its password in the ECS console", w.name)
		return
	}
	w.rt.Infof("note: the generated password is stored: if instance %s exists, `%s` shows it", w.name, app.PasswordCommandLine(ecsInstanceTree, w.name))
}

// finish shows the login once the plan has run, whether or not a later
// step failed: the instance exists from RunInstances on. Nothing happens
// when no instance was created (a dry run, an earlier failure, a Linux
// instance).
func (w *windowsLogin) finish(ctx context.Context) error {
	if w == nil || w.id == "" || w.password == "" {
		return nil
	}
	if w.stored {
		w.rt.ShowCredentials(w.credentials(), ecsInstanceTree)
		return nil
	}
	return w.rt.SaveCredentials(ctx, w.credentials(), ecsInstanceTree, nil)
}

// forgetLogin removes the stored credentials of a deleted instance.
func forgetLogin(ctx context.Context, rt *app.Runtime, s *ecsScope, id string) {
	rt.ForgetCredentials(ctx, secrets.Ref{Platform: platform.Aliyun, Profile: s.profile, Location: s.region, InstanceID: id})
}

func ecsPasswordCmd(rt *app.Runtime) *cobra.Command {
	return app.InstancePasswordCommand(rt, app.PasswordCommand{
		Platform:     platform.Aliyun,
		Tree:         ecsInstanceTree,
		LocationFlag: "region",
		Detail: `Alibaba Cloud ECS: create and ensure of a Windows instance (--os windows,
or an --image whose OSType is windows) generate the password of
Administrator (20 characters from crypto/rand) and set it in RunInstances,
so the instance is ready to log in to (RDP) once it is Running. Alibaba
Cloud never shows an instance password: for an instance polyctl did not
create, or whose stored credentials are gone, reset the password in the
ECS console. Deleting the instance with polyctl removes its stored
credentials.`,
	})
}
