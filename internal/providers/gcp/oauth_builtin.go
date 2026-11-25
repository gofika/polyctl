package gcp

// The OAuth client polyctl identifies itself with at Google when the user
// logs in through the browser without a client of their own
// (`polyctl auth login gcp`, method oauth without client_id).
//
// It is the OAuth client the Google Cloud SDK uses for its
// application-default login (the one whose credentials Google's client
// libraries pick up), a client of type "Desktop app": the consent screen
// names "Google Auth Library". Google documents that
// the secret of such a client is not confidential: an installed application
// cannot keep one, so the secret is distributed with the program and the
// flow is protected by PKCE and the loopback redirect instead
// (https://developers.google.com/identity/protocols/oauth2/native-app).
// That is why both values may live in the source.
//
// A build in which both are empty has no built-in client and its login
// falls back to what needs none (Application Default Credentials, a
// service account key, an OAuth client of the user). Fill in both, or
// neither.
//
// Neither value is ever written to config.yaml or the credential store: an
// account logged in with this client stores the marker oauth_client=builtin
// and its refresh token only, so a release with another client id here
// changes the client of every such account.
const (
	builtinClientID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
	builtinClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty"
)

// oauthClient is an OAuth client: its id and its secret.
type oauthClient struct {
	ID     string
	Secret string
}

// set reports whether the client can be used.
func (c oauthClient) set() bool { return c.ID != "" && c.Secret != "" }

// builtinClient is the built-in client the login and the token refresh
// use. Tests replace it.
var builtinClient = oauthClient{ID: builtinClientID, Secret: builtinClientSecret}

// oauthClientBuiltin is the value of the oauth_client metadata of an
// account that was logged in with the built-in client.
const oauthClientBuiltin = "builtin"
