package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testServersTOML = "[servers.box]\nhost = \"1.2.3.4\"\nuser = \"deploy\"\n"

func TestParseServersPlainUTF8(t *testing.T) {
	f, err := parseServersBytes([]byte(testServersTOML), "x")
	if err != nil {
		t.Fatal(err)
	}
	if f.Servers["box"].Host != "1.2.3.4" {
		t.Fatalf("%+v", f.Servers["box"])
	}
}

func TestParseServersUTF8BOM(t *testing.T) {
	b := append([]byte{0xEF, 0xBB, 0xBF}, []byte(testServersTOML)...)
	if _, err := parseServersBytes(b, "x"); err != nil {
		t.Fatal(err)
	}
}

func TestParseServersUTF16LEBOM(t *testing.T) {
	var b []byte
	b = append(b, 0xFF, 0xFE)
	for _, u := range utf16Of(testServersTOML) {
		b = append(b, byte(u), byte(u>>8))
	}
	f, err := parseServersBytes(b, "x")
	if err != nil {
		t.Fatal(err)
	}
	if f.Servers["box"].User != "deploy" {
		t.Fatalf("%+v", f.Servers["box"])
	}
}

func TestParseServersUTF16NoBOM(t *testing.T) {
	for _, le := range []bool{true, false} {
		var b []byte
		for _, u := range utf16Of(testServersTOML) {
			if le {
				b = append(b, byte(u), byte(u>>8))
			} else {
				b = append(b, byte(u>>8), byte(u))
			}
		}
		f, err := parseServersBytes(b, "x")
		if err != nil {
			t.Fatal(err)
		}
		if f.Servers["box"].Host != "1.2.3.4" || f.Servers["box"].User != "deploy" {
			t.Fatalf("le=%v %+v", le, f.Servers["box"])
		}
	}
}

func utf16Of(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r > 0xFFFF {
			r1, r2 := surrogatePair(r)
			out = append(out, r1, r2)
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

func surrogatePair(r rune) (uint16, uint16) {
	r -= 0x10000
	return uint16(0xD800 + (r >> 10)), uint16(0xDC00 + (r & 0x3FF))
}

func TestParseServersGarbage(t *testing.T) {
	_, err := parseServersBytes([]byte("[servers"), "x")
	if err == nil || !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("got %v", err)
	}
}

func TestValidateServerName(t *testing.T) {
	if err := ValidateServerName("good-name_2"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"a b", "", " a", "a[1]", `a"b`} {
		if err := ValidateServerName(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

func TestAddServerAppendAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, ".ssh-pty-mcp", "servers.toml")
	t.Setenv("SSH_PTY_MCP_SERVERS", cfg)
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("# my hosts\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	port := 2222
	s := AddServerFields{Host: "10.0.0.1", Port: &port, User: "root", PrivateKey: "~/.ssh/id_ed25519", Mode: "readonly"}
	ov, _, err := AddServer("box", s, false)
	if err != nil || ov {
		t.Fatalf("ov=%v err=%v", ov, err)
	}
	text, _ := os.ReadFile(cfg)
	if !strings.HasPrefix(string(text), "# my hosts\n") || !strings.Contains(string(text), "[servers.box]") || !strings.Contains(string(text), "port = 2222") {
		t.Fatalf("got:\n%s", text)
	}
	if _, _, err := AddServer("box", s, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("got %v", err)
	}
	s2 := AddServerFields{Host: "10.0.0.2"}
	ov, _, err = AddServer("box", s2, true)
	if err != nil || !ov {
		t.Fatalf("ov=%v err=%v", ov, err)
	}
	text, _ = os.ReadFile(cfg)
	if !strings.HasPrefix(string(text), "# my hosts\n") || !strings.Contains(string(text), `host = "10.0.0.2"`) || strings.Contains(string(text), "10.0.0.1") {
		t.Fatalf("got:\n%s", text)
	}
	f, err := parseServersBytes(text, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if f.Servers["box"].Host != "10.0.0.2" || f.Servers["box"].Mode != "" {
		t.Fatalf("%+v", f.Servers["box"])
	}
}
