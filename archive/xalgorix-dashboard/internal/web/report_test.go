package web

import (
	"testing"
)

func TestCollectReconReportSummary_DNSRecords(t *testing.T) {
	tests := []struct {
		name      string
		events    []WSEvent
		wantDNS   []string
		wantNoDNS bool
	}{
		{
			name: "real dig output",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "example.com.\t\t300\tIN\tA\t93.184.216.34\nexample.com.\t\t3600\tIN\tMX\t10 mail.example.com.",
			}},
			wantDNS: []string{
				"example.com. A 93.184.216.34",
				"example.com. MX 10 mail.example.com.",
			},
		},
		{
			name: "lowercase dns output",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "sub.example.com 300 in a 10.0.0.1",
			}},
			wantDNS: []string{"sub.example.com A 10.0.0.1"},
		},
		{
			name: "FQDN with trailing dot",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "example.com. IN AAAA 2001:db8::1",
			}},
			wantDNS: []string{"example.com. AAAA 2001:db8::1"},
		},
		{
			name: "CNAME record",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "www.example.com.\t300\tIN\tCNAME\texample.com.",
			}},
			wantDNS: []string{"www.example.com. CNAME example.com."},
		},
		{
			name: "TXT record with quotes",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "example.com.\t3600\tIN\tTXT\t\"v=spf1 include:_spf.google.com ~all\"",
			}},
			wantDNS: []string{`example.com. TXT "v=spf1 include:_spf.google.com ~all"`},
		},
		{
			name: "NS record",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "example.com.\t86400\tIN\tNS\tns1.example.com.",
			}},
			wantDNS: []string{"example.com. NS ns1.example.com."},
		},
		{
			name: "SOA record",
			events: []WSEvent{{
				Type:   "tool_result",
				Output: "example.com.\t86400\tIN\tSOA\tns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400",
			}},
			wantDNS: []string{"example.com. SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
		},
		{
			name:      "agent prose does not match",
			events:    []WSEvent{{Type: "agent", Content: "The target has a vulnerability in the A record configuration"}},
			wantNoDNS: true,
		},
		{
			name:      "agent thought does not match",
			events:    []WSEvent{{Type: "thought", Content: "I should check the CNAME records for subdomain takeover"}},
			wantNoDNS: true,
		},
		{
			name:      "natural language in prose does not match",
			events:    []WSEvent{{Type: "agent", Content: "found a CNAME pointing to dangling cloud resource"}},
			wantNoDNS: true,
		},
		{
			name:      "bare hostname without dot does not match",
			events:    []WSEvent{{Type: "tool_result", Output: "localhost A 127.0.0.1"}},
			wantNoDNS: true,
		},
		{
			name:      "command template does not match",
			events:    []WSEvent{{Type: "tool_call", ToolName: "terminal", ToolArgs: map[string]string{"command": "dnsx -silent -a -resp -threads 50"}}},
			wantNoDNS: true,
		},
		{
			name: "tool_call with real DNS in command output",
			events: []WSEvent{{
				Type:     "tool_call",
				ToolName: "terminal",
				ToolArgs: map[string]string{"command": "dig example.com ANY +noall +answer"},
				Output:   "example.com.\t300\tIN\tA\t93.184.216.34\nexample.com.\t300\tIN\tMX\t10 mail.example.com.",
			}},
			wantDNS: []string{
				"example.com. A 93.184.216.34",
				"example.com. MX 10 mail.example.com.",
			},
		},
		{
			name: "mixed events - agent prose skipped, tool output parsed",
			events: []WSEvent{
				{Type: "agent", Content: "The site uses WordPress and has a CNAME record"},
				{Type: "tool_result", Output: "www.example.com.\t300\tIN\tCNAME\texample.com."},
				{Type: "thought", Content: "I found an A record pointing to 10.0.0.1"},
			},
			wantDNS: []string{"www.example.com. CNAME example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := collectReconReportSummary(tt.events)
			if tt.wantNoDNS {
				if len(summary.DNSRecords) != 0 {
					t.Errorf("expected no DNS records, got: %v", summary.DNSRecords)
				}
				return
			}
			if len(summary.DNSRecords) != len(tt.wantDNS) {
				t.Fatalf("DNS record count = %d, want %d\ngot:  %v\nwant: %v", len(summary.DNSRecords), len(tt.wantDNS), summary.DNSRecords, tt.wantDNS)
			}
			for i, want := range tt.wantDNS {
				if summary.DNSRecords[i] != want {
					t.Errorf("DNSRecord[%d] = %q, want %q", i, summary.DNSRecords[i], want)
				}
			}
		})
	}
}

func TestCollectReconReportSummary_IPAddresses(t *testing.T) {
	tests := []struct {
		name    string
		events  []WSEvent
		wantIPs []string
	}{
		{
			name:    "IP from tool output",
			events:  []WSEvent{{Type: "tool_result", Output: "Target resolved to 93.184.216.34"}},
			wantIPs: []string{"93.184.216.34"},
		},
		{
			name:    "IP from tool args",
			events:  []WSEvent{{Type: "tool_call", ToolArgs: map[string]string{"command": "nmap 10.0.0.1"}}},
			wantIPs: []string{"10.0.0.1"},
		},
		{
			name:    "IP in agent prose is skipped (agent events are filtered)",
			events:  []WSEvent{{Type: "agent", Content: "The server at 192.168.1.1 returned 200"}},
			wantIPs: nil,
		},
		{
			name:   "invalid octet rejected",
			events: []WSEvent{{Type: "tool_result", Output: "999.999.999.999 is not valid"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := collectReconReportSummary(tt.events)
			if len(summary.IPAddresses) != len(tt.wantIPs) {
				t.Fatalf("IP count = %d, want %d\ngot: %v", len(summary.IPAddresses), len(tt.wantIPs), summary.IPAddresses)
			}
			for i, want := range tt.wantIPs {
				if summary.IPAddresses[i] != want {
					t.Errorf("IP[%d] = %q, want %q", i, summary.IPAddresses[i], want)
				}
			}
		})
	}
}

func TestCollectReconReportSummary_OpenPorts(t *testing.T) {
	events := []WSEvent{{
		Type:   "tool_result",
		Output: "22/tcp   open  ssh     OpenSSH 8.9\n80/tcp   open  http    nginx 1.18\n443/tcp  open  https   Apache 2.4",
	}}
	summary := collectReconReportSummary(events)
	if len(summary.Ports) != 3 {
		t.Fatalf("port count = %d, want 3\ngot: %v", len(summary.Ports), summary.Ports)
	}
	// Ports are sorted; internal whitespace from tool output is preserved.
	want := []string{
		"22/tcp ssh     OpenSSH 8.9",
		"443/tcp https   Apache 2.4",
		"80/tcp http    nginx 1.18",
	}
	for i, w := range want {
		if summary.Ports[i] != w {
			t.Errorf("Port[%d] = %q, want %q", i, summary.Ports[i], w)
		}
	}
}

func TestCollectReconReportSummary_Technologies(t *testing.T) {
	tests := []struct {
		name     string
		events   []WSEvent
		wantTech []string
	}{
		{
			name:     "tech from tool output",
			events:   []WSEvent{{Type: "tool_result", Output: "Server: nginx/1.18.0\nX-Powered-By: PHP/8.1"}},
			wantTech: []string{"Nginx", "PHP"},
		},
		{
			name:     "tech from headers",
			events:   []WSEvent{{Type: "tool_result", Output: "x-powered-by: Express\nSet-Cookie: JSESSIONID=abc123"}},
			wantTech: []string{"Node.js", "Spring"},
		},
		{
			name:     "agent prose skipped for tech detection",
			events:   []WSEvent{{Type: "agent", Content: "The site uses WordPress and React"}},
			wantTech: nil,
		},
		{
			name:     "tech from tool_call output only",
			events:   []WSEvent{{Type: "tool_call", ToolName: "terminal", Output: "Server: cloudflare\nCF-Ray: abc123"}},
			wantTech: []string{"Cloudflare"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := collectReconReportSummary(tt.events)
			if len(summary.Technologies) != len(tt.wantTech) {
				t.Fatalf("tech count = %d, want %d\ngot: %v", len(summary.Technologies), len(tt.wantTech), summary.Technologies)
			}
			for i, want := range tt.wantTech {
				if summary.Technologies[i] != want {
					t.Errorf("Tech[%d] = %q, want %q", i, summary.Technologies[i], want)
				}
			}
		})
	}
}

func TestCollectReconReportSummary_URLs(t *testing.T) {
	events := []WSEvent{{
		Type:   "tool_result",
		Output: "Found: https://example.com/login\nFound: https://example.com/api/v1/users",
	}}
	summary := collectReconReportSummary(events)
	if len(summary.URLs) != 2 {
		t.Fatalf("URL count = %d, want 2\ngot: %v", len(summary.URLs), summary.URLs)
	}
}

func TestCollectReconReportSummary_AgentProseExcluded(t *testing.T) {
	// This is the core regression test for the false positive fix.
	// Agent messages containing natural language should NOT produce
	// DNS records, technologies, or other recon findings.
	events := []WSEvent{
		{Type: "agent", Content: "The target has a vulnerability. Found a CNAME pointing to a dangling S3 bucket. The site uses WordPress and React. Let me check the MX records next."},
		{Type: "thought", Content: "I should verify if the A record resolves to an internal IP. The SPF record is missing which allows email spoofing."},
		{Type: "decision", Content: "Moving to phase 2 after finding DNS misconfiguration."},
		{Type: "message", Content: "The NS records show ns1.cloudflare.com and ns2.cloudflare.com."},
		{Type: "llm", Content: "Based on the dig output, example.com A 93.184.216.34 is the primary record."},
	}

	summary := collectReconReportSummary(events)

	// None of these agent prose events should produce DNS records
	if len(summary.DNSRecords) != 0 {
		t.Errorf("agent prose produced %d DNS records (should be 0): %v", len(summary.DNSRecords), summary.DNSRecords)
	}

	// Technologies should also not be detected from agent prose
	if len(summary.Technologies) != 0 {
		t.Errorf("agent prose detected %d technologies (should be 0): %v", len(summary.Technologies), summary.Technologies)
	}
}

func TestCollectReconReportSummary_Deduplication(t *testing.T) {
	events := []WSEvent{
		{Type: "tool_result", Output: "example.com.\t300\tIN\tA\t93.184.216.34"},
		{Type: "tool_result", Output: "example.com.\t300\tIN\tA\t93.184.216.34"}, // duplicate
		{Type: "tool_result", Output: "93.184.216.34 is alive"},
	}

	summary := collectReconReportSummary(events)

	if len(summary.DNSRecords) != 1 {
		t.Errorf("expected 1 DNS record after dedup, got %d: %v", len(summary.DNSRecords), summary.DNSRecords)
	}
	if len(summary.IPAddresses) != 1 {
		t.Errorf("expected 1 IP after dedup, got %d: %v", len(summary.IPAddresses), summary.IPAddresses)
	}
}

func TestCollectReconReportSummary_EmptyEvents(t *testing.T) {
	summary := collectReconReportSummary(nil)
	if summary.hasData() {
		t.Error("empty events should produce empty summary")
	}

	summary = collectReconReportSummary([]WSEvent{})
	if summary.hasData() {
		t.Error("nil events should produce empty summary")
	}
}
