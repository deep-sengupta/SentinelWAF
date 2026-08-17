package rules

import (
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"sentinelwaf/internal/config"
)

type Rule struct {
	ID       string
	Name     string
	Category string
	Severity string
	Action   string
	Targets  []string
	Patterns []string
	Paranoia int
	Tags     []string
}

type Detection struct {
	RuleID       string   `json:"rule_id"`
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	Severity     string   `json:"severity"`
	Reason       string   `json:"reason"`
	Target       string   `json:"target"`
	Evidence     string   `json:"evidence"`
	AnomalyScore int      `json:"anomaly_score"`
	MatchedRules []string `json:"matched_rules,omitempty"`
}

type Engine struct {
	rules     []compiledRule
	threshold int
	paranoia  int
}

type compiledRule struct {
	rule     Rule
	patterns []compiledPattern
}

type compiledPattern struct {
	raw string
	re  *regexp.Regexp
}

func New(custom []config.RuleConfig, disabled []string, threshold, paranoia int) (*Engine, error) {
	all := DefaultRules()
	for _, item := range custom {
		all = append(all, Rule{
			ID:       item.ID,
			Name:     item.Name,
			Category: item.Category,
			Severity: item.Severity,
			Action:   item.Action,
			Targets:  item.Targets,
			Patterns: item.Patterns,
			Paranoia: item.Paranoia,
			Tags:     item.Tags,
		})
	}
	if threshold <= 0 {
		threshold = 4
	}
	if paranoia <= 0 {
		paranoia = 1
	}
	if paranoia > 4 {
		paranoia = 4
	}
	disabledSet := map[string]struct{}{}
	for _, id := range disabled {
		disabledSet[id] = struct{}{}
	}
	compiled := make([]compiledRule, 0, len(all))
	for _, rule := range all {
		if _, ok := disabledSet[rule.ID]; ok {
			continue
		}
		if rule.Action == "" {
			rule.Action = "block"
		}
		if rule.Severity == "" {
			rule.Severity = "medium"
		}
		if rule.Paranoia <= 0 {
			rule.Paranoia = 1
		}
		if len(rule.Targets) == 0 {
			rule.Targets = []string{"all"}
		}
		item := compiledRule{rule: rule}
		for _, pattern := range rule.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
			}
			item.patterns = append(item.patterns, compiledPattern{raw: pattern, re: re})
		}
		compiled = append(compiled, item)
	}
	return &Engine{rules: compiled, threshold: threshold, paranoia: paranoia}, nil
}

func (e *Engine) Inspect(inputs map[string]string) *Detection {
	var matches []Detection
	score := 0
	for _, rule := range e.rules {
		if rule.rule.Paranoia > e.paranoia || strings.ToLower(rule.rule.Action) != "block" {
			continue
		}
		matched := false
		var targetName string
		var evidence string
		for _, target := range rule.rule.Targets {
			values := targetValues(inputs, target)
			for _, value := range values {
				if value == "" {
					continue
				}
				scan := normalize(value)
				for _, pattern := range rule.patterns {
					if loc := pattern.re.FindStringIndex(scan); loc != nil {
						matched = true
						targetName = target
						evidence = sample(scan, loc)
						break
					}
				}
				if matched {
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			continue
		}
		score += severityScore(rule.rule.Severity)
		matches = append(matches, Detection{
			RuleID:   rule.rule.ID,
			Name:     rule.rule.Name,
			Category: rule.rule.Category,
			Severity: rule.rule.Severity,
			Reason:   rule.rule.Name,
			Target:   targetName,
			Evidence: evidence,
		})
	}
	if score < e.threshold || len(matches) == 0 {
		return nil
	}
	sort.SliceStable(matches, func(i, j int) bool {
		left := severityScore(matches[i].Severity)
		right := severityScore(matches[j].Severity)
		return left > right
	})
	primary := matches[0]
	primary.AnomalyScore = score
	primary.Reason = fmt.Sprintf("%s (anomaly score %d)", primary.Name, score)
	primary.MatchedRules = make([]string, 0, len(matches))
	for _, match := range matches {
		primary.MatchedRules = append(primary.MatchedRules, match.RuleID)
	}
	return &primary
}

func severityScore(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 5
	case "high", "error":
		return 4
	case "medium", "warning":
		return 3
	case "low", "notice":
		return 2
	default:
		return 1
	}
}

func DefaultRules() []Rule {
	return []Rule{
		{ID: "920-001", Name: "HTTP protocol CRLF injection", Category: "OWASP CRS 920 HTTP Protocol Attack", Severity: "high", Paranoia: 1, Tags: []string{"protocol", "crlf"}, Targets: []string{"path", "query", "headers", "body"}, Patterns: []string{`(?i)(?:%0d%0a|%0a|%0d|\r\n|\n\r)`}},
		{ID: "920-002", Name: "HTTP request smuggling marker", Category: "OWASP CRS 920 HTTP Protocol Attack", Severity: "critical", Paranoia: 2, Tags: []string{"protocol", "smuggling"}, Targets: []string{"headers"}, Patterns: []string{`(?i)(?:transfer-encoding\s*:[^\n]*,|content-length\s*:[^\n]+\n[^\n]*content-length\s*:)`}},
		{ID: "921-001", Name: "HTTP method or URI abuse", Category: "OWASP CRS 921 Protocol Attack", Severity: "medium", Paranoia: 2, Tags: []string{"protocol"}, Targets: []string{"method", "url"}, Patterns: []string{`(?i)(?:\bTRACE\b|\bTRACK\b|\bCONNECT\b\s+[^\s]+\s+HTTP)`, `(?i)%00|%ff%ff%ff|%c0%af`}},
		{ID: "930-001", Name: "local file inclusion attempt", Category: "OWASP CRS 930 LFI", Severity: "high", Paranoia: 1, Tags: []string{"attack-lfi"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:/etc/(?:passwd|shadow|hosts)|/proc/(?:self|version)|/var/log/[^\s]+|boot\.ini|win\.ini|system32)`, `(?i)(?:file|php|zip|data|expect|input)://`}},
		{ID: "931-001", Name: "remote file inclusion attempt", Category: "OWASP CRS 931 RFI", Severity: "high", Paranoia: 1, Tags: []string{"attack-rfi"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:https?|ftp)://[^\s]+(?:\.(?:php|asp|aspx|jsp|cgi)|(?:[/?#]|$))`, `(?i)\b(?:include|require)(?:_once)?\b\s*[=(]\s*https?://`}},
		{ID: "932-001", Name: "Unix or Windows command injection", Category: "OWASP CRS 932 RCE", Severity: "critical", Paranoia: 1, Tags: []string{"attack-rce", "platform-unix", "platform-windows"}, Targets: []string{"path", "query", "body", "headers"}, Patterns: []string{`(?i)(?:;|\|\||&&|\|)\s*(?:cat|id|whoami|uname|wget|curl|bash|sh|python|python3|perl|nc|netcat|powershell|cmd|certutil)\b`, `(?i)(?:/bin/(?:sh|bash)|cmd\.exe|powershell(?:\.exe)?)`, `(?:\$\(|%60)`}},
		{ID: "932-002", Name: "server-side template or expression injection", Category: "OWASP CRS 932 RCE", Severity: "high", Paranoia: 2, Tags: []string{"attack-rce", "ssti"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?:\{\{\s*[^}]+\s*\}\}|\$\{[^}]+\}|<%=?[^%]*%>)`, `(?i)(?:Runtime\.getRuntime\(\)|ProcessBuilder\s*\(|eval\s*\(|exec\s*\()`}},
		{ID: "933-001", Name: "PHP code injection marker", Category: "OWASP CRS 933 PHP", Severity: "critical", Paranoia: 2, Tags: []string{"attack-php"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)<\?(?:php|=)?`, `(?i)(?:phpinfo|assert|passthru|shell_exec|system|proc_open|popen)\s*\(`, `(?i)preg_replace\s*\(.*?/e["']`}},
		{ID: "934-001", Name: "Node.js deserialization or prototype pollution", Category: "OWASP CRS 934 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-node", "deserialization"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:__proto__|constructor\s*\[?\s*["']prototype["']|prototype\s*:)`, `(?i)(?:node-serialize|funcster|ObjectInputStream|serialize-javascript)`}},
		{ID: "934-002", Name: "Java deserialization or reflection exploit", Category: "OWASP CRS 934 Generic", Severity: "critical", Paranoia: 2, Tags: []string{"attack-java", "deserialization"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:java\.lang\.Runtime|java\.lang\.ProcessBuilder|InvokerTransformer|commons-collections|ysoserial)`, `(?i)rO0AB[A-Za-z0-9+/=]{8,}`}},
		{ID: "934-003", Name: "generic code execution marker", Category: "OWASP CRS 934 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-rce"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:String\.fromCharCode|Function\s*\(|constructor\s*\(|Reflect\.apply|Class\.forName)`}},
		{ID: "941-001", Name: "cross-site scripting HTML/script injection", Category: "OWASP CRS 941 XSS", Severity: "high", Paranoia: 1, Tags: []string{"attack-xss"}, Targets: []string{"path", "query", "body", "headers"}, Patterns: []string{`(?i)<\s*script\b`, `(?i)<\s*(?:iframe|object|embed|svg|img|body|meta|link)\b[^>]*(?:on\w+\s*=|javascript:)`, `(?i)javascript\s*:`}},
		{ID: "941-002", Name: "cross-site scripting event handler or DOM sink", Category: "OWASP CRS 941 XSS", Severity: "high", Paranoia: 2, Tags: []string{"attack-xss"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)on(?:error|load|click|mouseover|focus|submit)\s*=`, `(?i)(?:document\.cookie|window\.location|localStorage|sessionStorage)`, `(?i)(?:eval|setTimeout|setInterval)\s*\(`}},
		{ID: "942-001", Name: "SQL injection union/select attack", Category: "OWASP CRS 942 SQLi", Severity: "high", Paranoia: 1, Tags: []string{"attack-sqli"}, Targets: []string{"path", "query", "body", "headers"}, Patterns: []string{`(?i)\bunion\b\s+(?:all\s+)?\bselect\b`, `(?i)\bselect\b.+\bfrom\b`, `(?i)\binsert\b\s+into|\bupdate\b.+\bset\b|\bdelete\b\s+from`}},
		{ID: "942-002", Name: "SQL injection boolean or comment attack", Category: "OWASP CRS 942 SQLi", Severity: "high", Paranoia: 1, Tags: []string{"attack-sqli"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+`, `(?i)(?:--|#|/\*)\s*(?:$|[\w-])`}},
		{ID: "942-003", Name: "SQL injection time-based or file access function", Category: "OWASP CRS 942 SQLi", Severity: "critical", Paranoia: 2, Tags: []string{"attack-sqli"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)`, `(?i)(?:load_file\s*\(|into\s+outfile|xp_cmdshell|@@version|information_schema)`}},
		{ID: "943-001", Name: "session fixation marker", Category: "OWASP CRS 943 Session Fixation", Severity: "medium", Paranoia: 2, Tags: []string{"attack-session-fixation"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i);(?:jsessionid|phpsessid|sessionid)=`, `(?i)(?:jsessionid|phpsessid|sessionid)=.{1,128}`}},
		{ID: "944-001", Name: "XML external entity injection", Category: "OWASP CRS 944 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-xxe"}, Targets: []string{"body"}, Patterns: []string{`(?i)<!doctype[^>]*(?:\[|>)`, `(?i)<!entity\s+[^>]+(?:system|public)`, `(?i)(?:system|public)\s+["']file://`}},
		{ID: "944-002", Name: "LDAP or XPath injection", Category: "OWASP CRS 944 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-ldap", "attack-xpath"}, Targets: []string{"query", "body"}, Patterns: []string{`(?i)\b(?:ldap|ldaps)://`, `(?i)(?:\*\)|\(\|\(|\&\(|\bxpath\b).*(?:=|\*)`}},
		{ID: "944-003", Name: "NoSQL injection operator", Category: "OWASP CRS 944 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-nosqli"}, Targets: []string{"query", "body"}, Patterns: []string{`(?i)(?:\"?\$(?:where|regex|ne|gt|gte|lt|lte|in|nin|exists)\"?\s*:)`, `(?i)(?:\$where\s*:\s*(?:function|\{))`}},
		{ID: "944-004", Name: "Server-side request forgery URL scheme", Category: "OWASP CRS 944 Generic", Severity: "high", Paranoia: 2, Tags: []string{"attack-ssrf"}, Targets: []string{"path", "query", "body"}, Patterns: []string{`(?i)(?:https?|gopher|dict|ftp)://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|::1)(?::|/|$)`, `(?i)http://(?:2130706433|0x7f000001|0177\.0\.0\.1)`}},
		{ID: "944-005", Name: "file upload executable content marker", Category: "OWASP CRS 944 Generic", Severity: "high", Paranoia: 3, Tags: []string{"attack-upload"}, Targets: []string{"body", "headers"}, Patterns: []string{`(?i)content-disposition:[^\n]*filename=[^\n]+\.(?:php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|exe|dll)(?:\W|$)`, `(?i)(?:MZ.{1,16}This program cannot be run|<\?php)`}},
		{ID: "949-001", Name: "scanner and automated attack client", Category: "OWASP CRS 949 Blocking Evaluation", Severity: "high", Paranoia: 1, Tags: []string{"attack-scanner"}, Targets: []string{"user_agent"}, Patterns: []string{`(?i)(?:sqlmap|nikto|acunetix|nmap|masscan|zgrab|wpscan|dirbuster|gobuster|ffuf|hydra|nessus|openvas|burpsuite|havij)`}},
		{ID: "920-003", Name: "malformed payload or NUL byte", Category: "OWASP CRS 920 HTTP Protocol Attack", Severity: "medium", Paranoia: 1, Tags: []string{"protocol"}, Targets: []string{"path", "query", "body", "headers"}, Patterns: []string{`(?:%00|\x00)`}},
	}
}

func targetValues(inputs map[string]string, target string) []string {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" || target == "all" {
		values := make([]string, 0, len(inputs))
		for _, value := range inputs {
			values = append(values, value)
		}
		return values
	}
	if value, ok := inputs[target]; ok {
		return []string{value}
	}
	return nil
}

func normalize(value string) string {
	current := value
	for i := 0; i < 4; i++ {
		decoded, err := url.QueryUnescape(current)
		if err != nil || decoded == current {
			break
		}
		current = decoded
	}
	current = html.UnescapeString(current)
	return strings.TrimSpace(current)
}

func sample(value string, loc []int) string {
	start := loc[0] - 60
	if start < 0 {
		start = 0
	}
	end := loc[1] + 60
	if end > len(value) {
		end = len(value)
	}
	return value[start:end]
}
