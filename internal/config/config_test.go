package config

import (
	"net"
	"testing"
)

func TestDefaultWAFConfig(t *testing.T) {
	cfg := Default()
	if cfg.WAF.ListenAddress != "127.0.0.1:8080" {
		t.Fatalf("unexpected WAF listen address: %s", cfg.WAF.ListenAddress)
	}
	if cfg.WAF.TargetURL != "http://127.0.0.1:9000" {
		t.Fatalf("unexpected WAF target URL: %s", cfg.WAF.TargetURL)
	}
}

func TestProxyHeadersAreDisabled(t *testing.T) {
	cfg := Default()
	cfg.WAF.TrustProxyHeaders = true
	cfg.normalize()
	if cfg.WAF.TrustProxyHeaders {
		t.Fatal("unsafe client-supplied proxy identity headers must remain disabled")
	}
}

func TestMatchIPCIDR(t *testing.T) {
	if !matchIP(net.ParseIP("192.0.2.10").String(), []string{"192.0.2.0/24"}) {
		t.Fatal("CIDR should match an address in the network")
	}
	if matchIP("198.51.100.10", []string{"192.0.2.0/24"}) {
		t.Fatal("CIDR should not match an address outside the network")
	}
}
