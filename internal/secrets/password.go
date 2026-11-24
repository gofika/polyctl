package secrets

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// PasswordLength is the length of a generated password.
const PasswordLength = 20

// Character classes of a generated password. Characters that are easy to
// mistake for one another (0 O 1 l I) are left out. The specials are a
// subset of what Alibaba Cloud ECS accepts for an instance password
// (()`~!@#$%^&*-_+=|{}[]:;'<>,.?/), without quotes, backslash, space,
// backtick and the characters a shell or cmd.exe treats specially when the
// password is pasted unquoted ($ % ^ & | < > ! * ? ( ) ; ~ and brackets).
// They are valid on AWS and Compute Engine Windows images and meet the
// Windows complexity rules with any one of the other classes.
const (
	passwordUpper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	passwordLower   = "abcdefghijkmnopqrstuvwxyz"
	passwordDigits  = "23456789"
	PasswordSpecial = "@#-_+=.,:"
	passwordAlpha   = passwordUpper + passwordLower + passwordDigits + PasswordSpecial
)

// GeneratePassword returns a random password of PasswordLength characters
// from crypto/rand with at least one upper-case letter, one lower-case
// letter, one digit and one special character, starting with a letter or
// digit (so it is never taken for a command-line option and never starts
// with a slash, which Alibaba Cloud refuses).
func GeneratePassword() (string, error) {
	max := big.NewInt(int64(len(passwordAlpha)))
	for {
		var b strings.Builder
		for range PasswordLength {
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", err
			}
			b.WriteByte(passwordAlpha[n.Int64()])
		}
		if p := b.String(); ValidPassword(p) {
			return p, nil
		}
	}
}

// ValidPassword reports whether p has the shape GeneratePassword promises.
func ValidPassword(p string) bool {
	if len(p) != PasswordLength || strings.ContainsAny(p[:1], PasswordSpecial) {
		return false
	}
	for _, class := range []string{passwordUpper, passwordLower, passwordDigits, PasswordSpecial} {
		if !strings.ContainsAny(p, class) {
			return false
		}
	}
	for _, r := range p {
		if !strings.ContainsRune(passwordAlpha, r) {
			return false
		}
	}
	return true
}
