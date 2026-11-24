// Package sshremote connects to a Linux instance over SSH to manage the
// authorized_keys file of one of its users: the client (authentication with
// an identity file, the SSH agent or the default ~/.ssh keys), the host key
// rules (~/.ssh/known_hosts, never overwritten), the trial of the login
// users an image may have, and the POSIX sh script that lists, adds and
// removes keys with an atomic replace of the file.
//
// It never stores a private key, never enables or uses password
// authentication, and never prints key material other than public keys.
package sshremote
