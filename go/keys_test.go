package main

import (
	"bytes"
	"testing"
)

func TestMapKeyTable(t *testing.T) {
	cases := []struct {
		spec string
		want []byte
	}{
		{"ctrl+c", []byte{0x03}},
		{"ctrl+x", []byte{0x18}},
		{"CTRL+C", []byte{0x03}},
		{"shift+tab", []byte{0x1b, '[', 'Z'}},
		{"f5", []byte{0x1b, '[', '1', '5', '~'}},
		{"alt+x", []byte{0x1b, 'x'}},
		{"up", []byte{0x1b, '[', 'A'}},
		{"enter", []byte{0x0d}},
		{"q", []byte{'q'}},
		{"shift+a", []byte{'A'}},
		{"alt+ctrl+d", []byte{0x1b, 0x04}},
	}
	for _, c := range cases {
		got, err := MapKey(c.spec)
		if err != nil {
			t.Fatalf("%s: %v", c.spec, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Fatalf("%s: got %v want %v", c.spec, got, c.want)
		}
	}
}

func TestMapKeyInvalid(t *testing.T) {
	if _, err := MapKey("ctrl+banana"); err == nil || !bytes.Contains([]byte(err.Error()), []byte("f1-f12")) {
		t.Fatalf("error should list valid keys: %v", err)
	}
	for _, spec := range []string{"ctrl+up", "ctrl+1", ""} {
		if _, err := MapKey(spec); err == nil {
			t.Fatalf("%s should error", spec)
		}
	}
}
