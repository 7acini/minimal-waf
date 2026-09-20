package waf

import "regexp"

type Rule struct {
	ID          string
	Category    string
	Description string
	pattern     *regexp.Regexp
}

func (r Rule) Match(value string) bool {
	return r.pattern.MatchString(value)
}

func DefaultRules() []Rule {
	return []Rule{
		newRule("LFI-001", "lfi", "path traversal sequence", `(?:^|/)\.\.(?:/|$)`),
		newRule("LFI-002", "lfi", "Unix sensitive file path", `(?:^|/)(?:etc/(?:passwd|shadow|hosts|group)|proc/(?:self|[0-9]+)/(?:environ|cmdline|fd)|var/log/(?:apache2|httpd|nginx))`),
		newRule("LFI-003", "lfi", "Windows sensitive file path", `(?:^|/)(?:windows/(?:win\.ini|system\.ini|system32)|boot\.ini)(?:/|$)`),
		newRule("LFI-004", "lfi", "PHP stream wrapper", `\b(?:php|file|glob|phar|zip|data|expect)://`),
		newRule("SQLI-001", "sqli", "UNION-based SQL injection", `\bunion\s+(?:all\s+)?select\b`),
		newRule("SQLI-002", "sqli", "SQL boolean tautology", `(?:['\"]|\b)\s*(?:or|and)\s+(?:[0-9]+\s*=\s*[0-9]+|'[^']{0,40}'\s*=\s*'[^']{0,40}')`),
		newRule("SQLI-003", "sqli", "time-based SQL injection", `\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(`),
		newRule("SQLI-004", "sqli", "stacked destructive SQL statement", `;\s*(?:drop|alter|truncate|delete|update|insert)\b`),
		newRule("SQLI-005", "sqli", "database metadata access", `\b(?:information_schema|pg_catalog|sqlite_master)\b`),
		newRule("SQLI-006", "sqli", "SQL statement in parameter", "\\b(?:select\\s+(?:\\*|[a-z0-9_.`]+(?:\\s*,\\s*[a-z0-9_.`]+)*)\\s+from\\s+[a-z0-9_.`]+|insert\\s+into|update\\s+[a-z0-9_.`]+\\s+set|delete\\s+from|drop\\s+table)\\b"),
		newRule("XSS-001", "xss", "script element", `<\s*/?\s*script\b`),
		newRule("XSS-002", "xss", "inline event handler", `<[^>]{0,300}\bon[a-z][a-z0-9_-]*\s*=`),
		newRule("XSS-003", "xss", "JavaScript URI", `\bjavascript\s*:`),
		newRule("XSS-004", "xss", "HTML data URI", `\bdata\s*:\s*text/html`),
		newRule("XSS-005", "xss", "CSS expression", `\bexpression\s*\(`),
	}
}

func newRule(id, category, description, pattern string) Rule {
	return Rule{
		ID:          id,
		Category:    category,
		Description: description,
		pattern:     regexp.MustCompile(`(?is)` + pattern),
	}
}
