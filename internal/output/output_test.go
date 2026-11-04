package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/gofika/polyctl/internal/output"
)

func TestParseFormat(t *testing.T) {
	ok := map[string]output.Format{
		"": output.Table, "table": output.Table, "TABLE": output.Table,
		"json": output.JSON, "JSON": output.JSON,
		"yaml": output.YAML, "yml": output.YAML, "YAML": output.YAML,
	}
	for in, want := range ok {
		got, err := output.ParseFormat(in)
		if err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"xml", "csv", "text"} {
		if got, err := output.ParseFormat(in); err == nil {
			t.Errorf("ParseFormat(%q) = %q, want error", in, got)
		}
	}
}

type item struct {
	Name  string `json:"name" yaml:"name"`
	Count int    `json:"count" yaml:"count"`
}

func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	gridCalled := false
	err := output.Render(&buf, output.JSON, []item{{"a", 1}, {"b", 2}}, func() output.Grid {
		gridCalled = true
		return output.Grid{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if gridCalled {
		t.Error("grid builder must not be called for json")
	}
	var got []item
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}
	if !reflect.DeepEqual(got, []item{{"a", 1}, {"b", 2}}) {
		t.Errorf("decoded %v", got)
	}
	if !strings.Contains(buf.String(), "\n  ") {
		t.Errorf("json must be indented:\n%s", buf.String())
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("json output must end with a newline")
	}
}

func TestRenderYAML(t *testing.T) {
	var buf bytes.Buffer
	err := output.Render(&buf, output.YAML, item{"a", 1}, func() output.Grid {
		t.Error("grid builder must not be called for yaml")
		return output.Grid{}
	})
	if err != nil {
		t.Fatal(err)
	}
	var got item
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid YAML %q: %v", buf.String(), err)
	}
	if got != (item{"a", 1}) {
		t.Errorf("decoded %+v", got)
	}
	if !strings.Contains(buf.String(), "name: a") || !strings.Contains(buf.String(), "count: 1") {
		t.Errorf("unexpected yaml:\n%s", buf.String())
	}
}

func TestRenderTable(t *testing.T) {
	var buf bytes.Buffer
	err := output.Render(&buf, output.Table, nil, func() output.Grid {
		return output.Grid{
			Headers: []string{"NAME", "TYPE"},
			Rows: [][]string{
				{"www.example.com", "A"},
				{"multi\nline", "TXT\twith tab"},
			},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), buf.String())
	}
	if !strings.HasPrefix(lines[0], "NAME") || !strings.Contains(lines[0], "TYPE") {
		t.Errorf("header line = %q", lines[0])
	}
	// Columns are aligned: TYPE starts at the same offset on every line.
	col := strings.Index(lines[0], "TYPE")
	if col <= len("www.example.com") {
		t.Errorf("TYPE column at %d, expected after the widest NAME cell", col)
	}
	if lines[1][col:] != "A" {
		t.Errorf("row 1 = %q, TYPE cell not aligned at %d", lines[1], col)
	}
	if strings.ContainsAny(lines[2], "\t") || !strings.HasPrefix(lines[2], "multi line") || !strings.HasSuffix(lines[2], "TXT with tab") {
		t.Errorf("newlines and tabs in cells must be flattened: %q", lines[2])
	}
	if strings.Contains(buf.String(), "\t") {
		t.Errorf("rendered table must not contain raw tabs:\n%q", buf.String())
	}
}

func TestRenderGridEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := output.RenderGrid(&buf, output.Grid{Headers: []string{"A"}, Empty: "nothing here"}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "nothing here\n" {
		t.Errorf("empty message: got %q", buf.String())
	}

	buf.Reset()
	if err := output.RenderGrid(&buf, output.Grid{}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "" {
		t.Errorf("empty grid without headers or message must print nothing, got %q", buf.String())
	}

	buf.Reset()
	if err := output.RenderGrid(&buf, output.Grid{Headers: []string{"A", "B"}}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(buf.String()) != "A  B" {
		t.Errorf("headers-only grid: got %q", buf.String())
	}
}

func TestKV(t *testing.T) {
	g := output.KV("DOMAIN", "example.com", "STATUS", "active", "dangling")
	want := [][]string{{"DOMAIN", "example.com"}, {"STATUS", "active"}}
	if !reflect.DeepEqual(g.Rows, want) {
		t.Errorf("KV rows = %v, want %v (odd trailing value dropped)", g.Rows, want)
	}
	if len(g.Headers) != 0 {
		t.Errorf("KV must not add headers: %v", g.Headers)
	}
	var buf bytes.Buffer
	if err := output.RenderGrid(&buf, g); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "DOMAIN  example.com\n") {
		t.Errorf("KV rendering = %q", buf.String())
	}
	if len(output.KV().Rows) != 0 {
		t.Error("KV() must be empty")
	}
}

func TestStr(t *testing.T) {
	yes, n := true, 42
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"plain", "plain"},
		{(*bool)(nil), ""},
		{&yes, "true"},
		{(*int)(nil), ""},
		{&n, "42"},
		{[]string{"ns1", "ns2"}, "ns1,ns2"},
		{[]string{}, ""},
		{7, "7"},
		{3.5, "3.5"},
		{false, "false"},
	}
	for _, c := range cases {
		if got := output.Str(c.in); got != c.want {
			t.Errorf("Str(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}
