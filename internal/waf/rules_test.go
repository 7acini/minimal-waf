package waf

import "testing"

func TestDefaultRules(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		category string
	}{
		{"path traversal", `../../../../etc/passwd`, "lfi"},
		{"encoded traversal", `%252e%252e%252f%252e%252e%252fetc%252fpasswd`, "lfi"},
		{"Windows path", `..\\..\\windows\\win.ini`, "lfi"},
		{"PHP filter", `php://filter/convert.base64-encode/resource=index.php`, "lfi"},
		{"UNION SQLi", `' UNION ALL SELECT password FROM users--`, "sqli"},
		{"boolean SQLi", `' OR 1=1`, "sqli"},
		{"time SQLi", `1; SELECT pg_sleep(5)`, "sqli"},
		{"script XSS", `<script>alert(1)</script>`, "xss"},
		{"event XSS", `<img src=x onerror=alert(1)>`, "xss"},
		{"URI XSS", `javascript:alert(document.domain)`, "xss"},
	}
	inspector := &Inspector{rules: DefaultRules(), maxDecodePasses: 3}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detections := inspector.inspectValue("test", "payload", test.payload)
			for _, detection := range detections {
				if detection.Category == test.category {
					return
				}
			}
			t.Fatalf("payload %q did not trigger category %s; detections: %#v", test.payload, test.category, detections)
		})
	}
}

func TestBenignValuesDoNotMatch(t *testing.T) {
	values := []string{
		"summer sale 2026",
		"user@example.com",
		"https://example.com/products/42",
		"select your preferred color from the list",
		`{"message":"hello world"}`,
	}
	inspector := &Inspector{rules: DefaultRules(), maxDecodePasses: 3}
	for _, value := range values {
		if detections := inspector.inspectValue("test", "value", value); len(detections) != 0 {
			t.Errorf("benign value %q produced detections: %#v", value, detections)
		}
	}
}
