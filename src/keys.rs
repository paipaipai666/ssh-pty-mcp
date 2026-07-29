//! Virtual keyboard: maps human key specs (`ctrl+c`, `f5`, `shift+tab`) to the
//! byte sequences a terminal expects, so agents never deal with raw escapes.

const VALID: &str = "single characters, or: enter, esc, tab, backspace, delete, insert, space, home, end, pgup, pgdn, up, down, left, right, f1-f12; modifiers: ctrl+ (letters), alt+ (char), shift+tab";

fn named_key(name: &str) -> Option<&'static [u8]> {
    Some(match name {
        "enter" => b"\r",
        "esc" | "escape" => b"\x1b",
        "tab" => b"\t",
        "backspace" => b"\x7f",
        "space" => b" ",
        "delete" => b"\x1b[3~",
        "insert" => b"\x1b[2~",
        "home" => b"\x1b[H",
        "end" => b"\x1b[F",
        "pgup" | "pageup" => b"\x1b[5~",
        "pgdn" | "pagedown" => b"\x1b[6~",
        "up" => b"\x1b[A",
        "down" => b"\x1b[B",
        "right" => b"\x1b[C",
        "left" => b"\x1b[D",
        "f1" => b"\x1bOP",
        "f2" => b"\x1bOQ",
        "f3" => b"\x1bOR",
        "f4" => b"\x1bOS",
        "f5" => b"\x1b[15~",
        "f6" => b"\x1b[17~",
        "f7" => b"\x1b[18~",
        "f8" => b"\x1b[19~",
        "f9" => b"\x1b[20~",
        "f10" => b"\x1b[21~",
        "f11" => b"\x1b[23~",
        "f12" => b"\x1b[24~",
        _ => return None,
    })
}

/// Parse `mod+mod+key` (case-insensitive) into bytes to write to the PTY.
pub fn map_key(spec: &str) -> Result<Vec<u8>, String> {
    let lower = spec.trim().to_ascii_lowercase();
    let mut parts: Vec<&str> = lower.split('+').collect();
    let base = parts.pop().unwrap_or("");
    if base.is_empty() {
        return Err(format!("invalid key '{spec}'; valid keys: {VALID}"));
    }
    let mut ctrl = false;
    let mut alt = false;
    let mut shift = false;
    for m in parts {
        match m {
            "ctrl" if !ctrl => ctrl = true,
            "alt" if !alt => alt = true,
            "shift" if !shift => shift = true,
            _ => {
                return Err(format!(
                    "unknown or duplicate modifier '{m}' in '{spec}'; valid keys: {VALID}"
                ));
            }
        }
    }

    // Named keys: only shift+tab carries a modifier encoding.
    if let Some(seq) = named_key(base) {
        if shift && base == "tab" && !ctrl && !alt {
            return Ok(b"\x1b[Z".to_vec());
        }
        if ctrl || alt || shift {
            return Err(format!(
                "modifiers not supported for '{base}' (except shift+tab); valid keys: {VALID}"
            ));
        }
        return Ok(seq.to_vec());
    }

    // Single character.
    let mut chars = base.chars();
    match (chars.next(), chars.next()) {
        (Some(c), None) => {
            let mut out = Vec::with_capacity(3);
            if alt {
                out.push(0x1b);
            }
            if ctrl {
                if !c.is_ascii_alphabetic() {
                    return Err(format!(
                        "ctrl+ only supports letters, got '{c}'; valid keys: {VALID}"
                    ));
                }
                out.push((c as u8) & 0x1f);
            } else if shift {
                out.extend(c.to_uppercase().to_string().as_bytes());
            } else {
                out.push(c as u8);
            }
            Ok(out)
        }
        _ => Err(format!("unknown key '{spec}'; valid keys: {VALID}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        assert_eq!(map_key("ctrl+c").unwrap(), vec![0x03]);
        assert_eq!(map_key("ctrl+x").unwrap(), vec![0x18]);
        assert_eq!(map_key("CTRL+C").unwrap(), vec![0x03]);
        assert_eq!(map_key("shift+tab").unwrap(), b"\x1b[Z");
        assert_eq!(map_key("f5").unwrap(), b"\x1b[15~");
        assert_eq!(map_key("alt+x").unwrap(), b"\x1bx");
        assert_eq!(map_key("up").unwrap(), b"\x1b[A");
        assert_eq!(map_key("enter").unwrap(), b"\r");
        assert_eq!(map_key("q").unwrap(), b"q");
        assert_eq!(map_key("shift+a").unwrap(), b"A");
        assert_eq!(map_key("alt+ctrl+d").unwrap(), vec![0x1b, 0x04]);
    }

    #[test]
    fn invalid_lists_valid_keys() {
        let err = map_key("ctrl+banana").unwrap_err();
        assert!(
            err.contains("f1-f12"),
            "error should list valid keys: {err}"
        );
        assert!(map_key("ctrl+up").is_err());
        assert!(map_key("ctrl+1").is_err());
        assert!(map_key("").is_err());
    }
}
