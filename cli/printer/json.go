package printer

import (
	"encoding/json"
	"fmt"
	"io"
)

func AsJson(w io.Writer, in interface{}) error {
	out, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, string(out)); err != nil {
		return err
	}
	return nil
}
