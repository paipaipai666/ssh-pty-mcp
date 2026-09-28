// Virtual keyboard: maps human key specs (ctrl+c, f5, shift+tab) to the
// byte sequences a terminal expects, so agents never deal with raw escapes.
package main

import (
	"fmt"
	"strings"
)

const validKeys = "single characters, or: enter, esc, tab, backspace, delete, insert, space, home, end, pgup, pgdn, up, down, left, right, f1-f12; modifiers: ctrl+ (letters), alt+ (char), shift+tab"

var namedKeys = map[string][]byte{
	"enter":     {0x0d},
	"esc":       {0x1b},
	"escape":    {0x1b},
	"tab":       {0x09},
	"backspace": {0x7f},
	"space":     {0x20},
	"delete":    {0x1b, '[', '3', '~'},
	"insert":    {0x1b, '[', '2', '~'},
	"home":      {0x1b, '[', 'H'},
	"end":       {0x1b, '[', 'F'},
	"pgup":      {0x1b, '[', '5', '~'},
	"pageup":    {0x1b, '[', '5', '~'},
	"pgdn":      {0x1b, '[', '6', '~'},
	"pagedown":  {0x1b, '[', '6', '~'},
	"up":        {0x1b, '[', 'A'},
	"down":      {0x1b, '[', 'B'},
	"right":     {0x1b, '[', 'C'},
	"left":      {0x1b, '[', 'D'},
	"f1":        {0x1b, 'O', 'P'},
	"f2":        {0x1b, 'O', 'Q'},
	"f3":        {0x1b, 'O', 'R'},
	"f4":        {0x1b, 'O', 'S'},
	"f5":        {0x1b, '[', '1', '5', '~'},
	"f6":        {0x1b, '[', '1', '7', '~'},
	"f7":        {0x1b, '[', '1', '8', '~'},
	"f8":        {0x1b, '[', '1', '9', '~'},
	"f9":        {0x1b, '[', '2', '0', '~'},
	"f10":       {0x1b, '[', '2', '1', '~'},
	"f11":       {0x1b, '[', '2', '3', '~'},
	"f12":       {0x1b, '[', '2', '4', '~'},
}

// MapKey parses `mod+mod+key` (case-insensitive) into bytes for the PTY.
func MapKey(spec string) ([]byte, error) {
	lower := strings.ToLower(strings.TrimSpace(spec))
	parts := strings.Split(lower, "+")
	base := parts[len(parts)-1]
	if base == "" {
		return nil, fmt.Errorf("invalid key '%s'; valid keys: %s", spec, validKeys)
	}
	var ctrl, alt, shift bool
	for _, m := range parts[:len(parts)-1] {
		switch {
		case m == "ctrl" && !ctrl:
			ctrl = true
		case m == "alt" && !alt:
			alt = true
		case m == "shift" && !shift:
			shift = true
		default:
			return nil, fmt.Errorf("unknown or duplicate modifier '%s' in '%s'; valid keys: %s", m, spec, validKeys)
		}
	}

	// Named keys: only shift+tab carries a modifier encoding.
	if seq, ok := namedKeys[base]; ok {
		if shift && base == "tab" && !ctrl && !alt {
			return []byte{0x1b, '[', 'Z'}, nil
		}
		if ctrl || alt || shift {
			return nil, fmt.Errorf("modifiers not supported for '%s' (except shift+tab); valid keys: %s", base, validKeys)
		}
		return append([]byte(nil), seq...), nil
	}

	// Single character.
	runes := []rune(base)
	if len(runes) == 1 {
		c := runes[0]
		out := make([]byte, 0, 3)
		if alt {
			out = append(out, 0x1b)
		}
		if ctrl {
			if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') {
				return nil, fmt.Errorf("ctrl+ only supports letters, got '%c'; valid keys: %s", c, validKeys)
			}
			out = append(out, byte(c)&0x1f)
		} else if shift {
			out = append(out, []byte(strings.ToUpper(string(c)))...)
		} else {
			out = append(out, []byte(string(c))...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown key '%s'; valid keys: %s", spec, validKeys)
}
