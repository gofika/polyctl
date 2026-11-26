// Package shellquote writes arguments for a POSIX shell: the commands polyctl
// runs on a remote host, and the commands it prints for a person to run.
package shellquote

import "strings"

// Quote quotes s for a POSIX shell: in single quotes, with each single quote
// written as '\”.
func Quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Arg is s as one argument of a command line: as it is when it holds only
// characters no shell treats specially, quoted with Quote otherwise.
func Arg(s string) string {
	if s == "" {
		return "''"
	}
	for _, r := range s {
		plain := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("@%+=:,./_-", r)
		if !plain {
			return Quote(s)
		}
	}
	return s
}

// Join is the command line of args, each written with Arg.
func Join(args ...string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = Arg(a)
	}
	return strings.Join(out, " ")
}
