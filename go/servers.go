// Named server registry: ~/.ssh-pty-mcp/servers.toml (override with the
// SSH_PTY_MCP_SERVERS env var). Merges below explicit ssh_open params and
// above ~/.ssh/config.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// ServerEntry is one [servers.<name>] block.
type ServerEntry struct {
	Host          string   `toml:"host"`
	Port          *int     `toml:"port"`
	User          string   `toml:"user"`
	Password      string   `toml:"password"`
	PrivateKey    string   `toml:"private_key"`
	Passphrase    string   `toml:"passphrase"`
	ProxyJump     string   `toml:"proxy_jump"`
	UseAgent      *bool    `toml:"use_agent"`
	HostKeyPolicy string   `toml:"host_key_policy"`
	Mode          string   `toml:"mode"`
	Allow         []string `toml:"allow"`
}

// ServersFile is the whole registry.
type ServersFile struct {
	Servers map[string]ServerEntry `toml:"servers"`
}

// ServerSummary is a redacted listing entry.
type ServerSummary struct {
	Name      string `json:"name"`
	Host      string `json:"host,omitempty"`
	Port      *int   `json:"port,omitempty"`
	User      string `json:"user,omitempty"`
	ProxyJump string `json:"proxy_jump,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Source    string `json:"source"`
}

// ServersPath returns the registry path (env override or default).
func ServersPath() string {
	if p := os.Getenv("SSH_PTY_MCP_SERVERS"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	return filepath.Join(home, ".ssh-pty-mcp", "servers.toml")
}

// LoadServers reads the registry; errors become an empty file.
func LoadServers() ServersFile {
	f, _ := LoadServersVerbose()
	return f
}

// LoadServersVerbose loads with diagnostics: the second return describes why
// the registry is empty (missing file, unreadable, parse error).
func LoadServersVerbose() (ServersFile, *string) {
	path := ServersPath()
	bytes, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ServersFile{}, nil
	}
	if err != nil {
		msg := fmt.Sprintf("cannot read %s: %v", path, err)
		return ServersFile{}, &msg
	}
	f, err := parseServersBytes(bytes, path)
	if err != nil {
		msg := err.Error()
		return ServersFile{}, &msg
	}
	return f, nil
}

// parseServersBytes accepts UTF-8, UTF-8 BOM, and UTF-16 (BOM or sniffed).
func parseServersBytes(bytes []byte, path string) (ServersFile, error) {
	var text string
	rest := bytes
	switch {
	case len(bytes) >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF:
		rest = bytes[3:]
		s, err := decodeUTF8(rest, path)
		if err != nil {
			return ServersFile{}, err
		}
		text = s
	case len(bytes) >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE:
		text = decodeUTF16(bytes[2:], true)
	case len(bytes) >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF:
		text = decodeUTF16(bytes[2:], false)
	default:
		if s, err := decodeUTF8(bytes, path); err == nil {
			var f ServersFile
			if _, err := tomlDecode(s, &f); err == nil {
				return f, nil
			}
			// UTF-16LE ASCII text is also valid UTF-8 (chars + NULs) but fails
			// TOML with "invalid key" — sniff and re-decode.
			if _, le, ok := sniffUTF16(bytes); ok {
				text = decodeUTF16(bytes, le)
			} else {
				text = s
			}
		} else if _, le, ok := sniffUTF16(bytes); ok {
			text = decodeUTF16(bytes, le)
		} else {
			preview := bytes
			if len(preview) > 64 {
				preview = preview[:64]
			}
			return ServersFile{}, fmt.Errorf("%s is not valid UTF-8 or UTF-16: %q", path, preview)
		}
	}
	var f ServersFile
	if _, err := tomlDecode(text, &f); err != nil {
		return ServersFile{}, fmt.Errorf("failed to parse %s: %v", path, err)
	}
	return f, nil
}

func decodeUTF8(b []byte, path string) (string, error) {
	s, err := decodeValidUTF8(b)
	if err != nil {
		return "", fmt.Errorf("%s is not valid UTF-8: %v", path, err)
	}
	return s, nil
}

// sniffUTF16 detects NUL-pattern UTF-16 without BOM.
func sniffUTF16(bytes []byte) ([]byte, bool, bool) {
	n := len(bytes)
	if n > 4096 {
		n = 4096
	}
	sample := bytes[:n]
	evenNuls, oddNuls := 0, 0
	for i, b := range sample {
		if b == 0 {
			if i%2 == 0 {
				evenNuls++
			} else {
				oddNuls++
			}
		}
	}
	pairs := n / 2
	if oddNuls > 32 && oddNuls > evenNuls*4 && oddNuls*2 > pairs {
		return bytes, true, true // little-endian: zeros at odd offsets
	}
	if evenNuls > 32 && evenNuls > oddNuls*4 && evenNuls*2 > pairs {
		return bytes, false, true // big-endian: zeros at even offsets
	}
	return nil, false, false
}

func decodeUTF16(units []byte, le bool) string {
	u16 := make([]uint16, 0, len(units)/2)
	for i := 0; i+1 < len(units); i += 2 {
		if le {
			u16 = append(u16, uint16(units[i])|uint16(units[i+1])<<8)
		} else {
			u16 = append(u16, uint16(units[i])<<8|uint16(units[i+1]))
		}
	}
	return string(utf16Decode(u16))
}

// ValidateServerName checks a server/session name for TOML-breaking chars.
func ValidateServerName(name string) error {
	if name == "" || strings.TrimSpace(name) != name {
		return errors.New("name must be non-empty and have no leading/trailing whitespace")
	}
	for _, c := range name {
		if c == ' ' || c == '\t' || c == '[' || c == ']' || c == '"' || c == '=' || c == '#' {
			return errors.New(`name must not contain whitespace or the characters [ ] " = #`)
		}
	}
	return nil
}

// AddServerFields carries optional entry fields; empty strings are omitted.
type AddServerFields struct {
	Host       string
	Port       *int
	User       string
	Password   string
	PrivateKey string
	Passphrase string
	ProxyJump  string
	Mode       string
	Allow      []string
}

// AddServer appends (or replaces, with overwrite) a [servers.<name>] block,
// preserving all other content. Returns (overwritten, path).
func AddServer(name string, s AddServerFields, overwrite bool) (bool, string, error) {
	if err := ValidateServerName(name); err != nil {
		return false, "", err
	}
	path := ServersPath()
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return false, "", fmt.Errorf("cannot create %s: %v", dir, err)
		}
	}
	var existing string
	switch b, err := os.ReadFile(path); {
	case err == nil:
		t, err := parseServersTextBytes(b, path)
		if err != nil {
			return false, "", err
		}
		existing = t
	case errors.Is(err, os.ErrNotExist):
	default:
		return false, "", fmt.Errorf("cannot read %s: %v", path, err)
	}
	header := "[servers." + name + "]"
	block := entryBlock(name, s)
	var text string
	var overwritten bool
	lines := strings.Split(existing, "\n")
	pos := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == header {
			pos = i
			break
		}
	}
	if pos >= 0 {
		if !overwrite {
			return false, "", fmt.Errorf("server '%s' already exists in %s; pass overwrite=true to replace it", name, path)
		}
		end := len(lines)
		for i := pos + 1; i < len(lines); i++ {
			if strings.HasPrefix(strings.TrimLeft(lines[i], " \t"), "[") {
				end = i
				break
			}
		}
		out := strings.Join(lines[:pos], "\n")
		if out != "" {
			out += "\n"
		}
		out += block
		if end < len(lines) {
			out += strings.Join(lines[end:], "\n")
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}
		}
		text, overwritten = out, true
	} else {
		out := existing
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		text, overwritten = out+block, false
	}
	tmp := path + ".tmp"
	perm := os.FileMode(0o644)
	if s.Password != "" {
		perm = 0o600
	}
	if err := os.WriteFile(tmp, []byte(text), perm); err != nil {
		return false, "", fmt.Errorf("cannot write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, "", fmt.Errorf("cannot replace %s: %v", path, err)
	}
	return overwritten, path, nil
}

func entryBlock(name string, s AddServerFields) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[servers.%s]\n", name)
	emit := func(k, v string) { fmt.Fprintf(&b, "%s = %s\n", k, tomlQuote(v)) }
	emit("host", s.Host)
	if s.Port != nil {
		fmt.Fprintf(&b, "port = %d\n", *s.Port)
	}
	if s.User != "" {
		emit("user", s.User)
	}
	if s.Password != "" {
		emit("password", s.Password)
	}
	if s.PrivateKey != "" {
		emit("private_key", s.PrivateKey)
	}
	if s.Passphrase != "" {
		emit("passphrase", s.Passphrase)
	}
	if s.ProxyJump != "" {
		emit("proxy_jump", s.ProxyJump)
	}
	if s.Mode != "" {
		emit("mode", s.Mode)
	}
	if len(s.Allow) > 0 {
		parts := make([]string, len(s.Allow))
		for i, a := range s.Allow {
			parts[i] = tomlQuote(a)
		}
		fmt.Fprintf(&b, "allow = [%s]\n", strings.Join(parts, ", "))
	}
	return b.String()
}

// tomlQuote renders a TOML basic string.
func tomlQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// parseServersTextBytes decodes existing file bytes to editable text.
func parseServersTextBytes(bytes []byte, path string) (string, error) {
	switch {
	case len(bytes) >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF:
		s, err := decodeValidUTF8(bytes[3:])
		if err != nil {
			return "", fmt.Errorf("%s is not valid UTF-8: %v", path, err)
		}
		return s, nil
	case len(bytes) >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE:
		return decodeUTF16(bytes[2:], true), nil
	case len(bytes) >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF:
		return decodeUTF16(bytes[2:], false), nil
	default:
		if s, err := decodeValidUTF8(bytes); err == nil {
			return s, nil
		}
		if _, le, ok := sniffUTF16(bytes); ok {
			return decodeUTF16(bytes, le), nil
		}
		return string(bytes), nil
	}
}

// ListServerSummaries merges the registry with ~/.ssh/config aliases.
func ListServerSummaries() []ServerSummary {
	out := []ServerSummary{}
	for name, e := range LoadServers().Servers {
		out = append(out, ServerSummary{
			Name:      name,
			Host:      e.Host,
			Port:      e.Port,
			User:      e.User,
			ProxyJump: e.ProxyJump,
			Mode:      e.Mode,
			Source:    "servers.toml",
		})
	}
	if cfg := loadSSHConfig(); cfg != nil {
		for _, alias := range sshConfigAliases(cfg) {
			q := querySSHConfig(alias)
			out = append(out, ServerSummary{
				Name:   alias,
				Host:   q.HostName,
				Port:   q.Port,
				User:   q.User,
				Source: "~/.ssh/config",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func tomlDecode(s string, v any) (toml.MetaData, error) {
	return toml.Decode(s, v)
}
