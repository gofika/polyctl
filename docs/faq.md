# FAQ

Questions that come up when using polyctl, by platform.

- [AWS: why does the IAM Identity Center login expire, and how long does it last?](#aws-why-does-the-iam-identity-center-login-expire-and-how-long-does-it-last)
- [AWS: where is the session duration set?](#aws-where-is-the-session-duration-set)
- [AWS: can I log in once and keep using it?](#aws-can-i-log-in-once-and-keep-using-it)

## AWS: why does the IAM Identity Center login expire, and how long does it last?

A login with `--set method=sso` (the default of `polyctl auth login aws`) opens a session of IAM Identity Center. polyctl stores its access token and refresh token and renews what it can without asking:

- the role credentials of the account, before they expire, also during a long wait in one command;
- the access token, with the refresh token, when it has expired.

The refresh token is only good for as long as the session lasts. When the session is over, IAM Identity Center refuses the refresh, no client can renew it, and every AWS command of that account fails with exit code 3:

```
unauthorized: the SSO session has expired (<code>); run `polyctl auth login aws --profile <name>`
```

`polyctl auth status` shows the same text in the row of the account. Log in again with the command it names.

How long a session lasts is a setting of the IAM Identity Center instance, not of polyctl: 8 hours by default, from 15 minutes to 90 days. An administrator can also end a session before that.

## AWS: where is the session duration set?

In the IAM Identity Center console, by an administrator of the instance ([Configure the session duration](https://docs.aws.amazon.com/singlesignon/latest/userguide/user-interactive-sessions.html) in the AWS documentation):

1. Open the IAM Identity Center console and choose **Settings**.
2. Choose the **Authentication** tab.
3. Next to **Session duration**, choose **Configure**.
4. Under **User interactive sessions**, choose the duration (up to 90 days) and **Save**.

Things to know:

- The change applies to new sessions only. Run `polyctl auth login aws --profile <name>` once more after it; the session that is open keeps the duration it started with.
- The setting is for every user of the instance, and for the AWS access portal as well as for command-line tools.
- With Microsoft Active Directory as the identity source the session is at most as long as the Kerberos ticket of the user (10 hours with AWS Managed Microsoft AD). With an external identity provider that sends `SessionNotOnOrAfter` in its SAML assertion, the shorter of the two durations counts. See [Session duration considerations](https://docs.aws.amazon.com/singlesignon/latest/userguide/user-session-duration-prereqs-considerations.html).

## AWS: can I log in once and keep using it?

Not with IAM Identity Center: 90 days is the longest session, and after it a new login is needed. The choices are:

| Choice | Lasts | Notes |
| --- | --- | --- |
| `method=sso` with a longer session duration | up to 90 days per login | Needs an administrator of the IAM Identity Center instance to change the setting. |
| `method=keys` with the access key of an IAM user | until the key is deleted or deactivated | `polyctl auth login aws --profile <name> --set method=keys`. Suits scripts and machines nobody logs in on. |
| `method=profile` | as the profile of `~/.aws/config` it names | Nothing is gained when that profile is an IAM Identity Center one: its session has the same duration. |

See [Accounts: AWS](accounts.md#aws) for the login flows.
