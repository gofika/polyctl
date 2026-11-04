// Package output renders command results as table, json or yaml.
package output

import (
	"encoding/json"
	"fmt"
	"io"
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

// RenderGrid prints a grid with aligned columns.
func RenderGrid(w io.Writer, g Grid) error {
	if len(g.Rows) == 0 {
		if g.Empty != "" {
			_, err := fmt.Fprintln(w, g.Empty)
			return err
		}
		if len(g.Headers) == 0 {
			return nil
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(g.Headers) > 0 {
		fmt.Fprintln(tw, strings.Join(g.Headers, "\t"))
	}
	for _, r := range g.Rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = strings.ReplaceAll(strings.ReplaceAll(c, "\t", " "), "\n", " ")
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
