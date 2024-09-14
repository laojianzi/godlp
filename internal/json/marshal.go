package json

import (
	"bytes"
	"encoding/json"
)

// SyntaxError as encoding/json SyntaxError
type SyntaxError = json.SyntaxError

// Marshal as encoding/json Marshal
func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal as encoding/json Unmarshal but fixed the number value loss issues
func Unmarshal(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	return d.Decode(v)
}
