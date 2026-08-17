package config

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const ServiceName = "SentinelWAF"

type Config struct {
	BaseDir         string            `json:"-"`
	WAF             WAFConfig         `json:"waf"`
	Runtime         RuntimeConfig     `json:"runtime"`
	Allowlist       ListConfig        `json:"allowlist"`
	Blocklist       BlocklistConfig   `json:"blocklist"`
	SecurityHeaders map[string]string `json:"security_headers"`
	CustomRules     []RuleConfig      `json:"custom_rules"`
	DisabledRules   []string          `json:"disabled_rules"`
}

type WAFConfig struct {
	ListenAddress            string   `json:"listen_address"`
	TargetURL                string   `json:"target_url"`
	MaxBodyBytes             int64    `json:"max_body_bytes"`
	MaxHeaders               int      `json:"max_headers"`
	MaxHeaderValueBytes      int      `json:"max_header_value_bytes"`
	MaxHeaderBytes           int      `json:"max_header_bytes"`
	ReadTimeoutSeconds       int      `json:"read_timeout_seconds"`
	WriteTimeoutSeconds      int      `json:"write_timeout_seconds"`
	IdleTimeoutSeconds       int      `json:"idle_timeout_seconds"`
	RateLimitRequests        int      `json:"rate_limit_requests"`
	RateLimitWindowSeconds   int      `json:"rate_limit_window_seconds"`
	RateLimitBurst           int      `json:"rate_limit_burst"`
	RateLimitBlockSeconds    int      `json:"rate_limit_block_seconds"`
	TrustProxyHeaders        bool     `json:"trust_proxy_headers"`
	PreserveHost             bool     `json:"preserve_host"`
	CSRFProtectionEnabled    bool     `json:"csrf_protection_enabled"`
	CSRFTokenHeader          string   `json:"csrf_token_header"`
	CSRFCookieName           string   `json:"csrf_cookie_name"`
	CSRFExemptPaths          []string `json:"csrf_exempt_paths"`
	BlockingAnomalyThreshold int      `json:"blocking_anomaly_threshold"`
	BlockingParanoiaLevel    int      `json:"blocking_paranoia_level"`
}

type RuntimeConfig struct {
	StateFile string `json:"state_file"`
	PidDir    string `json:"pid_dir"`
	LogFile   string `json:"log_file"`
}

type ListConfig struct {
	IPs   []string `json:"ips"`
	Paths []string `json:"paths"`
}

type BlocklistConfig struct {
	IPs        []string `json:"ips"`
	Paths      []string `json:"paths"`
	UserAgents []string `json:"user_agents"`
}

type RuleConfig struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Action   string   `json:"action"`
	Targets  []string `json:"targets"`
	Patterns []string `json:"patterns"`
	Paranoia int      `json:"paranoia"`
	Tags     []string `json:"tags"`
}

func Default() Config {
	return Config{
		WAF: WAFConfig{
			ListenAddress:            "127.0.0.1:8080",
			TargetURL:                "http://127.0.0.1:9000",
			MaxBodyBytes:             1048576,
			MaxHeaders:               100,
			MaxHeaderValueBytes:      8192,
			MaxHeaderBytes:           1048576,
			ReadTimeoutSeconds:       10,
			WriteTimeoutSeconds:      30,
			IdleTimeoutSeconds:       60,
			RateLimitRequests:        120,
			RateLimitWindowSeconds:   60,
			RateLimitBurst:           30,
			RateLimitBlockSeconds:    120,
			CSRFTokenHeader:          "X-CSRF-Token",
			CSRFCookieName:           "sentinelwaf_csrf",
			CSRFExemptPaths:          []string{"/api/*", "/healthz"},
			BlockingAnomalyThreshold: 4,
			BlockingParanoiaLevel:    2,
		},
		Runtime: RuntimeConfig{
			StateFile: "runtime/state.json",
			PidDir:    "runtime",
			LogFile:   "logs/sentinelwaf.log",
		},
		Allowlist: ListConfig{Paths: []string{"/healthz"}},
		Blocklist: BlocklistConfig{UserAgents: []string{"sqlmap", "nikto", "acunetix", "nmap", "masscan", "zgrab", "wpscan", "dirbuster", "gobuster", "ffuf", "hydra", "nessus", "openvas"}},
		SecurityHeaders: map[string]string{
			"Content-Security-Policy":   "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
			"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
			"Referrer-Policy":           "no-referrer",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "DENY",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	cfg.BaseDir = cwd
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, err
		}
	}
	cfg.BaseDir = cwd
	cfg.normalize()
	if cfg.WAF.TargetURL == "" {
		return nil, errors.New("waf target_url is required")
	}
	target, err := url.Parse(cfg.WAF.TargetURL)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, errors.New("waf target_url must be a valid absolute URL")
	}
	return &cfg, nil
}

func (c *Config) ResolvePath(path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	base := c.BaseDir
	if base == "" {
		base = "."
	}
	return filepath.Join(base, path)
}

func (c *Config) IsIPAllowlisted(ip string) bool     { return matchIP(ip, c.Allowlist.IPs) }
func (c *Config) IsIPBlocklisted(ip string) bool     { return matchIP(ip, c.Blocklist.IPs) }
func (c *Config) IsPathAllowlisted(path string) bool { return pathListed(path, c.Allowlist.Paths) }
func (c *Config) IsPathBlocklisted(path string) bool { return pathListed(path, c.Blocklist.Paths) }
func (c *Config) IsCSRFExempt(path string) bool      { return pathListed(path, c.WAF.CSRFExemptPaths) }

func (c *Config) IsUserAgentBlocklisted(userAgent string) bool {
	ua := strings.ToLower(userAgent)
	for _, item := range c.Blocklist.UserAgents {
		item = strings.TrimSpace(strings.ToLower(item))
		if item != "" && strings.Contains(ua, item) {
			return true
		}
	}
	return false
}

func (c *Config) normalize() {
	if c.WAF.ListenAddress == "" {
		c.WAF.ListenAddress = "127.0.0.1:8080"
	}
	if c.WAF.MaxBodyBytes <= 0 {
		c.WAF.MaxBodyBytes = 1048576
	}
	if c.WAF.MaxHeaders <= 0 {
		c.WAF.MaxHeaders = 100
	}
	if c.WAF.MaxHeaderValueBytes <= 0 {
		c.WAF.MaxHeaderValueBytes = 8192
	}
	if c.WAF.MaxHeaderBytes <= 0 {
		c.WAF.MaxHeaderBytes = 1048576
	}
	if c.WAF.ReadTimeoutSeconds <= 0 {
		c.WAF.ReadTimeoutSeconds = 10
	}
	if c.WAF.WriteTimeoutSeconds <= 0 {
		c.WAF.WriteTimeoutSeconds = 30
	}
	if c.WAF.IdleTimeoutSeconds <= 0 {
		c.WAF.IdleTimeoutSeconds = 60
	}
	if c.WAF.RateLimitRequests <= 0 {
		c.WAF.RateLimitRequests = 120
	}
	if c.WAF.RateLimitWindowSeconds <= 0 {
		c.WAF.RateLimitWindowSeconds = 60
	}
	if c.WAF.RateLimitBurst < 0 {
		c.WAF.RateLimitBurst = 0
	}
	if c.WAF.RateLimitBlockSeconds <= 0 {
		c.WAF.RateLimitBlockSeconds = 120
	}
	if c.WAF.BlockingAnomalyThreshold <= 0 {
		c.WAF.BlockingAnomalyThreshold = 4
	}
	if c.WAF.BlockingParanoiaLevel <= 0 {
		c.WAF.BlockingParanoiaLevel = 1
	}
	if c.WAF.BlockingParanoiaLevel > 4 {
		c.WAF.BlockingParanoiaLevel = 4
	}
	if c.WAF.CSRFTokenHeader == "" {
		c.WAF.CSRFTokenHeader = "X-CSRF-Token"
	}
	if c.WAF.CSRFCookieName == "" {
		c.WAF.CSRFCookieName = "sentinelwaf_csrf"
	}
	if c.Runtime.StateFile == "" {
		c.Runtime.StateFile = "runtime/state.json"
	}
	if c.Runtime.PidDir == "" {
		c.Runtime.PidDir = "runtime"
	}
	if c.Runtime.LogFile == "" {
		c.Runtime.LogFile = "logs/sentinelwaf.log"
	}
	if c.SecurityHeaders == nil {
		c.SecurityHeaders = Default().SecurityHeaders
	}
	c.WAF.TrustProxyHeaders = false
}

func matchIP(ip string, entries []string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(parsed) {
			return true
		}
		if exact := net.ParseIP(entry); exact != nil && exact.Equal(parsed) {
			return true
		}
	}
	return false
}

func pathListed(path string, entries []string) bool {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		if !strings.HasPrefix(entry, "/") && !strings.HasPrefix(entry, "*") {
			entry = "/" + entry
		}
		if strings.HasSuffix(entry, "*") {
			prefix := strings.TrimSuffix(entry, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
			continue
		}
		if path == entry {
			return true
		}
	}
	return false
}
