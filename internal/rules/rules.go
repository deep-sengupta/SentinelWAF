package rules

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

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
	Action       string   `json:"action"`
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
	var logMatches []Detection
	score := 0
	for _, rule := range e.rules {
		if rule.rule.Paranoia > e.paranoia {
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
				for _, scan := range normalizations(value) {
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
			if matched {
				break
			}
		}
		if !matched {
			continue
		}
		detection := Detection{
			RuleID:   rule.rule.ID,
			Name:     rule.rule.Name,
			Category: rule.rule.Category,
			Severity: rule.rule.Severity,
			Action:   strings.ToLower(rule.rule.Action),
			Reason:   rule.rule.Name,
			Target:   targetName,
			Evidence: evidence,
		}
		if detection.Action == "log" {
			logMatches = append(logMatches, detection)
			continue
		}
		score += severityScore(rule.rule.Severity)
		matches = append(matches, detection)
	}
	if score >= e.threshold && len(matches) > 0 {
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
	if len(logMatches) > 0 {
		sort.SliceStable(logMatches, func(i, j int) bool {
			left := severityScore(logMatches[i].Severity)
			right := severityScore(logMatches[j].Severity)
			return left > right
		})
		primary := logMatches[0]
		primary.MatchedRules = make([]string, 0, len(logMatches))
		for _, match := range logMatches {
			primary.MatchedRules = append(primary.MatchedRules, match.RuleID)
		}
		return &primary
	}
	return nil
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
	for i := 0; i < 8; i++ {
		changed := false
		if decoded, err := url.QueryUnescape(current); err == nil && decoded != current {
			current = decoded
			changed = true
		}
		delimited := html.UnescapeString(current)
		if delimited != current {
			current = delimited
			changed = true
		}
		if !changed {
			break
		}
	}
	return canonicalize(current)
}

func normalizations(value string) []string {
	seen := make(map[string]struct{})
	values := make([]string, 0, 8)
	add := func(candidate string) {
		if candidate == "" {
			return
		}
		if _, ok := seen[candidate]; ok {
			return
		}
		seen[candidate] = struct{}{}
		values = append(values, candidate)
	}
	add(value)
	decoded := normalize(value)
	add(decoded)
	add(canonicalize(value))
	add(canonicalize(decoded))
	for _, candidate := range append([]string{}, values...) {
		for _, extracted := range jsonStrings(candidate) {
			add(extracted)
			add(normalize(extracted))
			add(canonicalize(extracted))
		}
	}
	return values
}

func canonicalize(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		if unicode.IsSpace(r) {
			return ' '
		}
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u2060':
			return -1
		default:
			return r
		}
	}, value)
}

func jsonStrings(value string) []string {
	var decoded any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return nil
	}
	var values []string
	var collect func(any)
	collect = func(item any) {
		switch typed := item.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, child := range typed {
				collect(child)
			}
		case map[string]any:
			for key, child := range typed {
				values = append(values, key)
				collect(child)
			}
		}
	}
	collect(decoded)
	return values
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
