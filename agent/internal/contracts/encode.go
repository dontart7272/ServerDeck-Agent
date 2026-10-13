// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"encoding/json"
	"reflect"
	"strings"
)

// Preflight bounds the logical value before encoding/json allocates its buffer.
// Escaping may use up to six bytes per source byte; the final exact byte limit
// is checked by Validate. Arbitrary MarshalJSON code is never executed.
func guardEncode(v any, limit int64) error {
	if limit < 1 || limit > MaxHistoryBytes {
		return ErrLimit
	}
	budget := limit
	marshaler := reflect.TypeFor[json.Marshaler]()
	var walk func(reflect.Value, int) error
	spend := func(n int64) error {
		budget -= n
		if budget < 0 {
			return ErrLimit
		}
		return nil
	}
	walk = func(rv reflect.Value, depth int) error {
		if !rv.IsValid() {
			return spend(4)
		}
		if rv.Kind() == reflect.Interface {
			if rv.IsNil() {
				return spend(4)
			}
			return walk(rv.Elem(), depth)
		}
		if rv.Kind() == reflect.Pointer {
			if rv.IsNil() {
				return spend(4)
			}
			if depth > MaxDepth {
				return ErrLimit
			}
			return walk(rv.Elem(), depth+1)
		}
		if rv.Type() == reflect.TypeFor[json.RawMessage]() {
			return spend(int64(rv.Len()))
		}
		if rv.Type() == reflect.TypeFor[Timestamp]() || rv.Type() == reflect.TypeFor[U64]() {
			b, e := json.Marshal(rv.Interface())
			if e != nil {
				return ErrInvalid
			}
			return spend(int64(len(b)))
		}
		if rv.Type().Implements(marshaler) || reflect.PointerTo(rv.Type()).Implements(marshaler) {
			return ErrInvalid
		}
		if depth > MaxDepth {
			return ErrLimit
		}
		switch rv.Kind() {
		case reflect.String:
			return spend(int64(rv.Len()) + 2)
		case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
			b, e := json.Marshal(rv.Interface())
			if e != nil {
				return ErrInvalid
			}
			return spend(int64(len(b)))
		case reflect.Map:
			if rv.Type().Key().Kind() != reflect.String {
				return ErrInvalid
			}
			if rv.Len() > MaxArrayItems {
				return ErrLimit
			}
			if e := spend(2); e != nil {
				return e
			}
			iter := rv.MapRange()
			for iter.Next() {
				if e := spend(int64(iter.Key().Len()) + 3); e != nil {
					return e
				}
				if e := walk(iter.Value(), depth+1); e != nil {
					return e
				}
			}
			return nil
		case reflect.Slice, reflect.Array:
			if rv.Len() > MaxArrayItems {
				return ErrLimit
			}
			if e := spend(2); e != nil {
				return e
			}
			for i := 0; i < rv.Len(); i++ {
				if i > 0 {
					if e := spend(1); e != nil {
						return e
					}
				}
				if e := walk(rv.Index(i), depth+1); e != nil {
					return e
				}
			}
			return nil
		case reflect.Struct:
			if e := spend(2); e != nil {
				return e
			}
			for i := 0; i < rv.NumField(); i++ {
				f := rv.Type().Field(i)
				if !f.IsExported() {
					continue
				}
				if f.Anonymous {
					return ErrInvalid
				}
				tag := strings.Split(f.Tag.Get("json"), ",")
				if tag[0] == "-" {
					continue
				}
				field := rv.Field(i)
				omit := false
				for _, option := range tag[1:] {
					if option == "omitempty" {
						switch field.Kind() {
						case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
							omit = field.Len() == 0
						default:
							omit = field.IsZero()
						}
					}
				}
				if omit {
					continue
				}
				name := tag[0]
				if name == "" {
					name = f.Name
				}
				if e := spend(int64(len(name)) + 3); e != nil {
					return e
				}
				if e := walk(field, depth+1); e != nil {
					return e
				}
			}
			return nil
		default:
			return ErrInvalid
		}
	}
	return walk(reflect.ValueOf(v), 0)
}
