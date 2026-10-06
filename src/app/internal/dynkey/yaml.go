package dynkey

import (
	"net"
	"strconv"
	"strings"
)

// A deliberately tiny YAML reader. It understands ONLY what an Outline transport description needs:
// nested mappings made of "key: value" lines, indented with spaces; scalars that are plain, 'single' or
// "double" quoted; comments and blank lines. Everything else YAML can express (lists, flow collections
// {..} and [..], anchors and aliases, tags, block scalars, several documents, tabs) is REFUSED with a
// sentence naming what was found. We do not claim to read arbitrary YAML.

type yline struct {
	indent int
	key    string
	val    string // raw value text after "key:" (comments removed), may be empty
	no     int
}

// parseYAML returns the mapping, or a short description of what is not supported (empty string = ok).
func parseYAML(text string) (map[string]any, string) {
	var lines []yline
	for i, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.Contains(raw, "\t") && strings.TrimLeft(raw, " ") != strings.TrimLeft(raw, " \t") {
			return nil, "YAML с отступами табуляцией не поддерживается"
		}
		line := stripComment(raw)
		t := strings.TrimSpace(line)
		if t == "" || t == "---" && i == 0 {
			continue
		}
		if t == "---" || t == "..." {
			return nil, "YAML из нескольких документов не поддерживается"
		}
		if strings.HasPrefix(t, "- ") || t == "-" {
			return nil, "списки в YAML не поддерживаются"
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		c := strings.Index(t, ":")
		if c < 1 {
			return nil, "строка YAML не вида «ключ: значение»"
		}
		key := strings.TrimSpace(t[:c])
		if !validKey(key) {
			return nil, "ключ YAML со сложной записью не поддерживается"
		}
		val := strings.TrimSpace(t[c+1:])
		if val != "" && c+1 < len(t) && t[c+1] != ' ' {
			return nil, "строка YAML не вида «ключ: значение»"
		}
		if val != "" {
			if _, msg := scalar(val); msg != "" { // report block scalars, flow collections, anchors... where they start
				return nil, msg
			}
		}
		lines = append(lines, yline{indent: indent, key: key, val: val, no: i + 1})
	}
	if len(lines) == 0 {
		return nil, "пустой YAML"
	}
	pos := 0
	m, msg := parseBlock(lines, &pos, lines[0].indent)
	if msg != "" {
		return nil, msg
	}
	if pos != len(lines) {
		return nil, "неожиданные отступы в YAML"
	}
	return m, ""
}

func validKey(k string) bool {
	for _, r := range k {
		if !(r == '$' || r == '_' || r == '-' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return k != ""
}

func parseBlock(lines []yline, pos *int, indent int) (map[string]any, string) {
	m := map[string]any{}
	for *pos < len(lines) {
		l := lines[*pos]
		if l.indent < indent {
			break
		}
		if l.indent > indent {
			return nil, "неожиданные отступы в YAML"
		}
		if _, dup := m[l.key]; dup {
			return nil, "повторяющийся ключ в YAML"
		}
		*pos++
		if l.val == "" { // a nested mapping follows
			if *pos < len(lines) && lines[*pos].indent > indent {
				sub, msg := parseBlock(lines, pos, lines[*pos].indent)
				if msg != "" {
					return nil, msg
				}
				m[l.key] = sub
			} else {
				m[l.key] = ""
			}
			continue
		}
		v, msg := scalar(l.val)
		if msg != "" {
			return nil, msg
		}
		m[l.key] = v
	}
	return m, ""
}

// stripComment removes "# ..." that starts a line or follows whitespace outside quotes.
func stripComment(s string) string {
	var q rune
	esc := false // inside "..." the character after a backslash never closes the string
	for i, r := range s {
		switch {
		case q != 0:
			switch {
			case esc:
				esc = false
			case q == '"' && r == '\\':
				esc = true
			case r == q:
				q = 0
			}
		case r == '"' || r == '\'':
			q = r
		case r == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func scalar(v string) (any, string) {
	switch v[0] {
	case '"':
		if len(v) < 2 || v[len(v)-1] != '"' {
			return nil, "строка в кавычках не закрыта"
		}
		u, ok := unquoteDouble(v[1 : len(v)-1])
		if !ok {
			return nil, "строка в кавычках содержит неподдерживаемые экранирования"
		}
		return u, ""
	case '\'':
		if len(v) < 2 || v[len(v)-1] != '\'' {
			return nil, "строка в кавычках не закрыта"
		}
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), ""
	case '[', '{':
		return nil, "вложенные коллекции {…} и […] в YAML не поддерживаются"
	case '|', '>':
		return nil, "многострочные значения YAML не поддерживаются"
	case '&', '*', '!', '%', '@', '`':
		return nil, "якоря, ссылки и теги YAML не поддерживаются"
	}
	return v, ""
}

// unquoteDouble reads the inside of a YAML 1.2 double-quoted scalar. The escapes are YAML's own (\xHH, \uHHHH
// and \UHHHHHHHH name a CODE POINT, which is what an Outline "prefix" is written with), not Go's, where \xHH
// would be a raw byte. An unescaped quote or a bad escape is refused.
func unquoteDouble(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		if c == '"' {
			return "", false
		}
		if c != '\\' {
			b.WriteByte(c)
			i++
			continue
		}
		i++
		if i >= len(s) {
			return "", false
		}
		e := s[i]
		i++
		simple := map[byte]rune{'0': 0, 'a': 7, 'b': 8, 't': 9, '\t': 9, 'n': 10, 'v': 11, 'f': 12, 'r': 13, 'e': 27, ' ': ' ',
			'"': '"', '/': '/', '\\': '\\', 'N': 0x85, '_': 0xA0, 'L': 0x2028, 'P': 0x2029}
		if r, ok := simple[e]; ok {
			b.WriteRune(r)
			continue
		}
		n := 0
		switch e {
		case 'x':
			n = 2
		case 'u':
			n = 4
		case 'U':
			n = 8
		default:
			return "", false
		}
		if i+n > len(s) {
			return "", false
		}
		cp, err := strconv.ParseUint(s[i:i+n], 16, 32)
		if err != nil || cp > 0x10FFFF || (cp >= 0xD800 && cp < 0xE000) {
			return "", false
		}
		b.WriteRune(rune(cp))
		i += n
	}
	return b.String(), true
}

func splitHostPort(s string) (string, int, bool) {
	h, p, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil || h == "" {
		return "", 0, false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, false
	}
	return h, n, true
}
