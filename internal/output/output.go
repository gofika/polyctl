// Package output renders command results as table, json or yaml.
package output

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

// Format is an output format.
type Format string

const (
	Table Format = "table"
	JSON  Format = "json"
	YAML  Format = "yaml"
)

// ParseFormat validates a format name.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "", "table":
		return Table, nil
	case "json":
		return JSON, nil
	case "yaml", "yml":
		return YAML, nil
	}
	return "", fmt.Errorf("unknown output format %q (expected table, json or yaml)", s)
}

// Grid is a tabular view of a result.
type Grid struct {
	Headers []string
	Rows    [][]string
	// Empty is printed instead of the grid when there are no rows.
	Empty string
}

// Render writes value in the requested format. For Table, grid() is called
// to build the rows; for json/yaml the value itself is encoded.
func Render(w io.Writer, f Format, value any, grid func() Grid) error {
	value = nonNilSlice(value)
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case YAML:
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		defer enc.Close()
		return enc.Encode(value)
	default:
		return RenderGrid(w, grid())
	}
}

// nonNilSlice returns v with every nil slice turned into an empty one, at
// the top level and inside structs (embedded ones included), pointers,
// interfaces, maps, arrays and slices, so JSON prints [] not null. v itself
// is not modified: what holds a nil slice is copied. Values that marshal
// themselves (json, yaml or text marshalers) and byte slices are left
// alone.
func nonNilSlice(v any) any {
	if v == nil {
		return nil
	}
	rv, changed := fillSlices(reflect.ValueOf(v), 0)
	if !changed {
		return v
	}
	return rv.Interface()
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	yamlMarshaler = reflect.TypeFor[yaml.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// marshalsItself reports whether values of t encode themselves.
func marshalsItself(t reflect.Type) bool {
	for _, m := range []reflect.Type{jsonMarshaler, yamlMarshaler, textMarshaler} {
		if t.Implements(m) || reflect.PointerTo(t).Implements(m) {
			return true
		}
	}
	return false
}

// maxFillDepth bounds the recursion of fillSlices (a cyclic value).
const maxFillDepth = 64

// fillSlices returns v with its nil slices made empty, and whether
// anything changed; v is returned as is when nothing did.
func fillSlices(v reflect.Value, depth int) (reflect.Value, bool) {
	if !v.IsValid() || depth > maxFillDepth {
		return v, false
	}
	t := v.Type()
	if t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer && marshalsItself(t) {
		return v, false
	}
	switch t.Kind() {
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return v, false
		}
		if v.IsNil() {
			return reflect.MakeSlice(t, 0, 0), true
		}
		var out reflect.Value
		for i := 0; i < v.Len(); i++ {
			e, ok := fillSlices(v.Index(i), depth+1)
			if !ok {
				continue
			}
			if !out.IsValid() {
				out = reflect.MakeSlice(t, v.Len(), v.Len())
				reflect.Copy(out, v)
			}
			out.Index(i).Set(e)
		}
		if out.IsValid() {
			return out, true
		}
	case reflect.Array:
		var out reflect.Value
		for i := 0; i < v.Len(); i++ {
			e, ok := fillSlices(v.Index(i), depth+1)
			if !ok {
				continue
			}
			if !out.IsValid() {
				out = reflect.New(t).Elem()
				out.Set(v)
			}
			out.Index(i).Set(e)
		}
		if out.IsValid() {
			return out, true
		}
	case reflect.Pointer:
		if v.IsNil() || marshalsItself(t.Elem()) {
			return v, false
		}
		e, ok := fillSlices(v.Elem(), depth+1)
		if ok {
			p := reflect.New(t.Elem())
			p.Elem().Set(e)
			return p, true
		}
	case reflect.Interface:
		if v.IsNil() {
			return v, false
		}
		e, ok := fillSlices(v.Elem(), depth+1)
		if ok {
			out := reflect.New(t).Elem()
			out.Set(e)
			return out, true
		}
	case reflect.Map:
		if v.IsNil() {
			return v, false
		}
		var out reflect.Value
		iter := v.MapRange()
		for iter.Next() {
			e, ok := fillSlices(iter.Value(), depth+1)
			if !ok {
				continue
			}
			if !out.IsValid() {
				out = reflect.MakeMapWithSize(t, v.Len())
				all := v.MapRange()
				for all.Next() {
					out.SetMapIndex(all.Key(), all.Value())
				}
			}
			out.SetMapIndex(iter.Key(), e)
		}
		if out.IsValid() {
			return out, true
		}
	case reflect.Struct:
		var out reflect.Value
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				// An unexported field cannot be set; its exported fields
				// promoted by embedding are left as they are.
				continue
			}
			if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag == "-" {
				continue
			}
			e, ok := fillSlices(v.Field(i), depth+1)
			if !ok {
				continue
			}
			if !out.IsValid() {
				out = reflect.New(t).Elem()
				out.Set(v)
			}
			out.Field(i).Set(e)
		}
		if out.IsValid() {
			return out, true
		}
	}
	return v, false
}

// RenderGrid prints a grid with aligned columns; control characters of the
// cells are escaped (see Clean).
func RenderGrid(w io.Writer, g Grid) error {
	if len(g.Rows) == 0 {
		if g.Empty != "" {
			_, err := fmt.Fprintln(w, Clean(g.Empty))
			return err
		}
		if len(g.Headers) == 0 {
			return nil
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(g.Headers) > 0 {
		fmt.Fprintln(tw, Clean(strings.Join(g.Headers, "\t")))
	}
	for _, r := range g.Rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = Clean(strings.ReplaceAll(strings.ReplaceAll(c, "\t", " "), "\n", " "))
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

// KV renders a two-column key/value grid (used for single-object views).
func KV(pairs ...string) Grid {
	g := Grid{}
	for i := 0; i+1 < len(pairs); i += 2 {
		g.Rows = append(g.Rows, []string{pairs[i], pairs[i+1]})
	}
	return g
}

// Str formats any scalar for a table cell.
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case *bool:
		if x == nil {
			return ""
		}
		return fmt.Sprint(*x)
	case *int:
		if x == nil {
			return ""
		}
		return fmt.Sprint(*x)
	case []string:
		return strings.Join(x, ",")
	default:
		return fmt.Sprint(v)
	}
}
