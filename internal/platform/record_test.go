package platform

import (
	"encoding/json"
	"strings"
	"testing"
)

// A record is written with "value" only; reading also accepts the "content"
// key polyctl 0.1.x stored, and "value" wins when both are there.
func TestRecordJSONReadsLegacyContent(t *testing.T) {
	for in, want := range map[string]string{
		`{"id":"r1","type":"A","value":"1.1.1.1"}`:                     "1.1.1.1",
		`{"id":"r1","type":"A","content":"2.2.2.2"}`:                   "2.2.2.2",
		`{"id":"r1","type":"A","value":"1.1.1.1","content":"2.2.2.2"}`: "1.1.1.1",
		`{"id":"r1","type":"A"}`:                                       "",
	} {
		var r Record
		if err := json.Unmarshal([]byte(in), &r); err != nil || r.Value != want || r.ID != "r1" || r.Type != "A" {
			t.Errorf("%s = %+v, %v; want value %q", in, r, err, want)
		}
	}
	var list []Record
	if err := json.Unmarshal([]byte(`[{"id":"a","content":"x","ttl":60,"proxied":true},{"id":"b","value":"y"}]`), &list); err != nil ||
		len(list) != 2 || list[0].Value != "x" || list[0].TTL != 60 || list[0].Proxied == nil || !*list[0].Proxied || list[1].Value != "y" {
		t.Errorf("list = %+v, %v", list, err)
	}
	out, err := json.Marshal(Record{ID: "r1", Value: "1.1.1.1"})
	if err != nil || !strings.Contains(string(out), `"value":"1.1.1.1"`) || strings.Contains(string(out), "content") {
		t.Errorf("marshal = %s, %v", out, err)
	}
}

type optionProvider struct{ Provider }

func (optionProvider) ID() ID                 { return Aliyun }
func (optionProvider) LoginOptions() []string { return []string{"region", "site"} }

func TestCheckLoginOption(t *testing.T) {
	if err := CheckLoginOption(optionProvider{}, "site"); err != nil {
		t.Errorf("known option: %v", err)
	}
	err := CheckLoginOption(optionProvider{}, "from_cli")
	if err == nil || err.Error() != `unknown login option "from_cli" for aliyun (valid: region, site)` {
		t.Errorf("unknown option: %v", err)
	}
}
