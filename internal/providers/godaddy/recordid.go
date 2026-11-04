package godaddy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// GoDaddy has no per-record identifiers. polyctl synthesizes a stable id
// from the three values that identify a record on GoDaddy's side:
//
//	<TYPE>|<relative name>|<data>
//
// Each field is percent-encoded (url.PathEscape) so the id contains no
// unescaped "|" and is safe to use in URLs and shell arguments.
// Example: TXT|@|v=spf1%20include:_spf.example.com%20~all

// EncodeRecordID builds a record id from the GoDaddy-native type, relative
// name ("@" for the apex) and data.
func EncodeRecordID(typ, name, data string) string {
	if name == "" {
		name = "@"
	}
	return url.PathEscape(strings.ToUpper(typ)) + "|" + url.PathEscape(name) + "|" + url.PathEscape(data)
}

// ErrBadRecordID is returned for ids not produced by EncodeRecordID.
var ErrBadRecordID = errors.New("invalid GoDaddy record id (expected TYPE|name|data)")

// DecodeRecordID splits an id produced by EncodeRecordID.
func DecodeRecordID(id string) (typ, name, data string, err error) {
	parts := strings.SplitN(id, "|", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("%w: %q", ErrBadRecordID, id)
	}
	if typ, err = url.PathUnescape(parts[0]); err != nil {
		return "", "", "", fmt.Errorf("%w: %q: %v", ErrBadRecordID, id, err)
	}
	if name, err = url.PathUnescape(parts[1]); err != nil {
		return "", "", "", fmt.Errorf("%w: %q: %v", ErrBadRecordID, id, err)
	}
	if data, err = url.PathUnescape(parts[2]); err != nil {
		return "", "", "", fmt.Errorf("%w: %q: %v", ErrBadRecordID, id, err)
	}
	typ = strings.ToUpper(typ)
	if typ == "" || name == "" {
		return "", "", "", fmt.Errorf("%w: %q", ErrBadRecordID, id)
	}
	return typ, name, data, nil
}
