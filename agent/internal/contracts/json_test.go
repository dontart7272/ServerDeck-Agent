// SPDX-License-Identifier: Apache-2.0
package contracts

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseBoundaries(t *testing.T) {
	for _, s := range []string{"[" + strings.Repeat("0,", 4095) + "0]", `"` + strings.Repeat("a", MaxJSONBytes-2) + `"`} {
		if _, e := Parse(strings.NewReader(s), MaxJSONBytes); e != nil {
			t.Fatal("exact boundary rejected")
		}
	}
	for _, s := range []string{`null`, `{"a":0,"b":[true,"😀"]}`, `"\ud83d\ude00"`, strings.Repeat("[", 32) + "0" + strings.Repeat("]", 32)} {
		if _, e := Parse(strings.NewReader(s), int64(len(s))); e != nil {
			t.Errorf("valid JSON: %v", e)
		}
	}
	for _, s := range []string{``, `{} {}`, `{"a":1,"\u0061":2}`, `{"nested":{"x":0,"x":1}}`, `"\u0000"`, `{"\u0000":0}`, `"\ud800"`, `"\udc00"`, `"\ud800x"`, string([]byte{'"', 0xff, '"'}), `NaN`, `1e9999`, `[1,]`, strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33), "[" + strings.Repeat("0,", 4096) + "0]"} {
		if _, e := Parse(strings.NewReader(s), MaxJSONBytes); e == nil {
			t.Errorf("invalid JSON accepted (%d bytes)", len(s))
		}
	}
	if _, e := Parse(strings.NewReader(`null `), 4); !errors.Is(e, ErrLimit) {
		t.Fatal("size+1 must fail")
	}
	if _, e := Parse(strings.NewReader(`null`), 0); !errors.Is(e, ErrLimit) {
		t.Fatal("zero limit")
	}
}

type countingReader struct{ count int }

func (r *countingReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = ' '
	}
	r.count += len(b)
	return len(b), nil
}
func TestReadBounded(t *testing.T) {
	r := &countingReader{}
	_, e := Parse(r, 100)
	if !errors.Is(e, ErrLimit) || r.count != 101 {
		t.Fatalf("read %d bytes: %v", r.count, e)
	}
}

func TestNonzeroUnderflow(t *testing.T) {
	if _, e := Parse(strings.NewReader(`1e-999999999`), MaxJSONBytes); e == nil {
		t.Fatal("unbounded exact exponent accepted")
	}
	if _, e := Parse(strings.NewReader(`0e-999999999`), MaxJSONBytes); e == nil {
		t.Fatal("unbounded zero exponent accepted")
	}
}
func TestU64(t *testing.T) {
	for _, s := range []string{`"0"`, `"18446744073709551615"`} {
		var n U64
		if json.Unmarshal([]byte(s), &n) != nil {
			t.Fatal("boundary rejected")
		}
		b, _ := json.Marshal(n)
		if string(b) != s {
			t.Fatal("roundtrip changed")
		}
	}
	for _, s := range []string{`0`, `"00"`, `"-1"`, `"+1"`, `"1.0"`, `"18446744073709551616"`, `null`} {
		var n U64
		if json.Unmarshal([]byte(s), &n) == nil {
			t.Fatal("invalid U64 accepted")
		}
	}
}
func TestTimestamp(t *testing.T) {
	for _, s := range []string{`"2026-02-29T00:00:00Z"`, `"2026-01-01T00:00:00+00:00"`, `null`} {
		var ts Timestamp
		if json.Unmarshal([]byte(s), &ts) == nil {
			t.Fatal("invalid timestamp accepted")
		}
	}
	var ts Timestamp
	if e := json.Unmarshal([]byte(`"2024-02-29T00:00:00.123456789Z"`), &ts); e != nil {
		t.Fatal(e)
	}
}
func TestLocation(t *testing.T) {
	for _, s := range []string{"", "Lg", "Li4", "Lw", "AA", "YQ=", "YR"} {
		if (Location{Components: []string{s}}).Validate() == nil {
			t.Fatalf("component %q accepted", s)
		}
	}
	for _, s := range []string{"YQ", "_w", strings.Repeat("YWFh", 85)} {
		if (Location{Components: []string{s}}).Validate() != nil {
			t.Fatal("valid byte component rejected")
		}
	}
	if (Location{Components: []string{strings.Repeat("YWFh", 86)}}).Validate() == nil {
		t.Fatal("256+ component accepted")
	}
}

type shortWriter struct{}

type forbiddenMarshaler struct{ called *bool }

func (m forbiddenMarshaler) MarshalJSON() ([]byte, error) {
	*m.called = true
	return []byte(`null`), nil
}
func TestEncodePreflight(t *testing.T) {
	called := false
	var out bytes.Buffer
	if e := Encode(&out, Target{"config", ""}, forbiddenMarshaler{&called}, MaxJSONBytes); e != ErrInvalid || called {
		t.Fatal("arbitrary marshaler executed")
	}
	if e := Encode(&out, Target{"config", ""}, map[string]any{"large": strings.Repeat("x", MaxJSONBytes+1)}, MaxJSONBytes); e != ErrLimit || out.Len() != 0 {
		t.Fatal("oversized value encoded")
	}
	cycle := map[string]any{}
	cycle["self"] = cycle
	if e := Encode(&out, Target{"config", ""}, cycle, MaxJSONBytes); e != ErrLimit {
		t.Fatal("cyclic input not bounded")
	}
}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }
func TestFrames(t *testing.T) {
	payload := map[string]any{"jsonrpc": "2.0", "id": "h1", "method": "heartbeat", "params": map[string]any{"session_id": "11111111-1111-4111-8111-111111111111", "sequence": "1"}}
	target := Target{"ipc", "Request"}
	var b bytes.Buffer
	if e := WriteFrame(&b, target, payload); e != nil {
		t.Fatal(e)
	}
	wire := append([]byte(nil), b.Bytes()...)
	b.Write(wire)
	for i := 0; i < 2; i++ {
		if _, e := ReadFrame(&b, target); e != nil {
			t.Fatal(e)
		}
	}
	if b.Len() != 0 {
		t.Fatal("frame boundaries lost")
	}
	for _, n := range []uint32{0, MaxJSONBytes + 1, 0xffffffff} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		if _, e := ReadFrame(bytes.NewReader(h[:]), target); !errors.Is(e, ErrLimit) {
			t.Fatal("frame length not bounded")
		}
	}
	for _, cut := range []int{0, 3, len(wire) - 1} {
		if _, e := ReadFrame(bytes.NewReader(wire[:cut]), target); e == nil {
			t.Fatal("truncated frame accepted")
		}
	}
	if e := WriteFrame(shortWriter{}, target, payload); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal("short write ignored")
	}
	if _, e := ReadFrame(bytes.NewReader(wire), Target{"api", "QueryRequest"}); !errors.Is(e, ErrSchema) {
		t.Fatal("wrong family")
	}
}

func TestPendingResponse(t *testing.T) {
	response := map[string]any{"jsonrpc": "2.0", "id": "h1", "result": map[string]any{"session_id": "11111111-1111-4111-8111-111111111111", "sequence": "1"}}
	var wire bytes.Buffer
	if e := WriteFrame(&wire, Target{"ipc", "Response"}, response); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		id, def string
		good    bool
	}{{"h1", "HeartbeatResult", true}, {"h2", "HeartbeatResult", false}, {"h1", "ShutdownResult", false}, {"h1", "QueryRequest", false}} {
		_, e := ReadResponse(bytes.NewReader(wire.Bytes()), tc.id, tc.def)
		if (e == nil) != tc.good {
			t.Fatalf("pending id/type mismatch: %v", e)
		}
	}
}
