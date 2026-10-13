// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxJSONBytes = 1000000
const MaxHistoryBytes = 4000000
const MaxDepth = 32
const MaxArrayItems = 4096

// Errors deliberately omit untrusted values, filenames and decoder diagnostics.
var ErrInvalid = errors.New("INVALID_INPUT")
var ErrLimit = errors.New("LIMIT_EXCEEDED")
var ErrSchema = errors.New("SCHEMA_MISMATCH")

// Parse reads at most limit+1 bytes. A caller must set its own transport deadline.
// Container depth counts the root container as one. Keys are compared decoded.
func Parse(r io.Reader, limit int64) (any, error) {
	if limit < 1 || limit > MaxHistoryBytes {
		return nil, ErrLimit
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, ErrInvalid
	}
	if int64(len(b)) > limit {
		return nil, ErrLimit
	}
	if !utf8.Valid(b) || !validEscapes(b) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, err := parseValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

func parseValue(d *json.Decoder, depth int) (any, error) {
	t, err := d.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	switch x := t.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, ErrLimit
		}
		switch x {
		case '{':
			m := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, ErrInvalid
				}
				k, ok := key.(string)
				if !ok || strings.ContainsRune(k, 0) {
					return nil, ErrInvalid
				}
				if _, exists := m[k]; exists {
					return nil, ErrInvalid
				}
				// A byte bound alone still allows many tiny object members.
				if len(m) >= MaxArrayItems {
					return nil, ErrLimit
				}
				v, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := make([]any, 0)
			for d.More() {
				if len(a) >= MaxArrayItems {
					return nil, ErrLimit
				}
				v, err := parseValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	case string:
		if strings.ContainsRune(x, 0) {
			return nil, ErrInvalid
		}
		return x, nil
	case json.Number:
		if i := strings.IndexAny(string(x), "eE"); i >= 0 {
			exp, e := strconv.ParseInt(string(x)[i+1:], 10, 32)
			if e != nil || exp < -324 || exp > 324 {
				return nil, ErrInvalid
			}
		}
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return nil, ErrInvalid
		}
		if f == 0 { // Reject nonzero underflow before exact schema arithmetic.
			mantissa := strings.Split(strings.ToLower(string(x)), "e")[0]
			for _, r := range mantissa {
				if r >= '1' && r <= '9' {
					return nil, ErrInvalid
				}
			}
		}
		return x, nil
	default:
		return t, nil
	}
}

// encoding/json replaces unpaired UTF-16 surrogates with U+FFFD. Reject them
// before decoding instead of silently changing an identity or parameter.
func validEscapes(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
