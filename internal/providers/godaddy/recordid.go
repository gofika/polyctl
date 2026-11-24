package godaddy

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// GoDaddy has no per-record identifiers. polyctl synthesizes a stable id
// from the values that identify a record on GoDaddy's side:
//
//	<TYPE>|<relative name>|<data>                                       most types
//	<TYPE>|<relative name>|<data>|<priority>                            MX
//	<TYPE>|<relative name>|<data>|<service>|<protocol>|<port>|<weight>|<priority>  SRV
//
// GoDaddy keeps every SRV record of an owner in one type+name set (the
// service and protocol are separate fields), so two SRV records with the
// same target but another service, protocol, port, weight or priority
// would otherwise get the same id; the same goes for two MX records with
// the same host and another priority.
//
// Each field is percent-encoded (url.PathEscape) so the id contains no
// unescaped "|" and is safe to use in URLs and shell arguments.
// Example: TXT|@|v=spf1%20include:_spf.example.com%20~all
//
// An id without the trailing fields (TYPE|name|data, the only form polyctl
// wrote before) is still accepted: it selects the record by its data alone
// and is ambiguous when several records of the set have that data.

// recordKey is a decoded record id.
type recordKey struct {
	Type, Name, Data string
	// Ext holds the identity fields after the data: the priority of an
	// MX record; service, protocol, port, weight and priority of an SRV
	// record. Nil when the id does not carry them.
	Ext []string
}

// extFields is the number of identity fields after the data, by type.
func extFields(typ string) int {
	switch typ {
	case "MX":
		return 1
	case "SRV":
		return 5
	}
	return 0
}

func itoa(p *int) string {
	if p == nil {
		return "0"
	}
	return strconv.Itoa(*p)
}

// keyOf returns the full identity of a GoDaddy record.
func keyOf(r apiRecord) recordKey {
	typ := strings.ToUpper(r.Type)
	name := r.Name
	if name == "" {
		name = "@"
	}
	k := recordKey{Type: typ, Name: name, Data: r.Data}
	switch typ {
	case "MX":
		k.Ext = []string{itoa(r.Priority)}
	case "SRV":
		service, protocol, _ := srvLabels(r)
		k.Ext = []string{service, protocol, itoa(r.Port), itoa(r.Weight), itoa(r.Priority)}
	}
	return k
}

// recordID builds the id of a GoDaddy record.
func recordID(r apiRecord) string {
	return encodeKey(keyOf(r))
}

func encodeKey(k recordKey) string {
	parts := []string{strings.ToUpper(k.Type), k.Name, k.Data}
	if parts[1] == "" {
		parts[1] = "@"
	}
	parts = append(parts, k.Ext...)
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "|")
}

// ErrBadRecordID is returned for ids not produced by polyctl.
var ErrBadRecordID = errors.New("invalid GoDaddy record id (expected TYPE|name|value, as dns list shows it)")

// decodeRecordID splits an id produced by recordID, or an older
// TYPE|name|data id.
func decodeRecordID(id string) (recordKey, error) {
	bad := func(err error) (recordKey, error) {
		if err != nil {
			return recordKey{}, fmt.Errorf("%w: %q: %v", ErrBadRecordID, id, err)
		}
		return recordKey{}, fmt.Errorf("%w: %q", ErrBadRecordID, id)
	}
	parts := strings.Split(id, "|")
	if len(parts) < 3 {
		return bad(nil)
	}
	for i, p := range parts {
		v, err := url.PathUnescape(p)
		if err != nil {
			return bad(err)
		}
		parts[i] = v
	}
	k := recordKey{Type: strings.ToUpper(parts[0]), Name: parts[1], Data: parts[2]}
	if k.Type == "" || k.Name == "" {
		return bad(nil)
	}
	ext := parts[3:]
	if len(ext) == 0 {
		return k, nil
	}
	if len(ext) != extFields(k.Type) {
		return bad(nil)
	}
	// The numeric fields are compared in their canonical form.
	for i := range ext {
		if k.Type == "SRV" && i < 2 {
			continue
		}
		n, err := strconv.Atoi(ext[i])
		if err != nil {
			return bad(err)
		}
		ext[i] = strconv.Itoa(n)
	}
	k.Ext = ext
	return k, nil
}

// matches reports whether r, an entry of the type+name set of k, is the
// record k names.
func (k recordKey) matches(r apiRecord) bool {
	if r.Data != k.Data {
		return false
	}
	return k.Ext == nil || slices.Equal(keyOf(r).Ext, k.Ext)
}

// find returns the index of the record k names in set, -1 when there is
// none. An id without the identity fields after the data (an older id)
// that matches several records is ambiguous.
func (k recordKey) find(set []apiRecord, zone, id string) (int, error) {
	idx := -1
	var ids []string
	for i, r := range set {
		if !k.matches(r) {
			continue
		}
		if idx < 0 {
			idx = i
		}
		ids = append(ids, recordID(r))
	}
	if len(ids) > 1 && k.Ext == nil {
		return -1, fmt.Errorf("%w: record id %q matches %d %s records of %s in zone %s (%s); pass the id of one, as `polyctl dns list %s` shows it",
			platform.ErrAmbiguous, id, len(ids), k.Type, platform.FQDN(k.Name, zone), zone, strings.Join(ids, ", "), zone)
	}
	return idx, nil
}
