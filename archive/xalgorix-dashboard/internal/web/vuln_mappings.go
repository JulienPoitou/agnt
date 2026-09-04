package web

import "strings"

// VulnMappings holds inferred security framework references for a vulnerability.
type VulnMappings struct {
	CWEID     string // e.g. "CWE-79"
	CWEName   string // e.g. "Cross-site Scripting"
	OWASP     string // e.g. "A03"
	OWASPName string // e.g. "Injection"
	PTES      string // e.g. "Exploitation"
}

// cweEntry maps a vulnerability type to its CWE identifier and short name.
type cweEntry struct {
	ID   string
	Name string
}

// vulnTypeToCWE maps extractVulnType() output → CWE.
var vulnTypeToCWE = map[string]cweEntry{
	"xss":                {"CWE-79", "Cross-site Scripting"},
	"sqli":               {"CWE-89", "SQL Injection"},
	"ssrf":               {"CWE-918", "Server-Side Request Forgery"},
	"idor":               {"CWE-639", "Authorization Bypass Through User-Controlled Key"},
	"lfi":                {"CWE-22", "Path Traversal"},
	"rfi":                {"CWE-98", "Remote File Inclusion"},
	"rce":                {"CWE-78", "OS Command Injection"},
	"csrf":               {"CWE-352", "Cross-Site Request Forgery"},
	"xxe":                {"CWE-611", "XML External Entity"},
	"open_redirect":      {"CWE-601", "URL Redirection to Untrusted Site"},
	"auth_bypass":        {"CWE-287", "Improper Authentication"},
	"info_disclosure":    {"CWE-200", "Exposure of Sensitive Information"},
	"subdomain_takeover": {"CWE-284", "Improper Access Control"},
	"clickjacking":       {"CWE-1021", "Improper Restriction of Rendered UI Layers"},
	"cors":               {"CWE-942", "Permissive Cross-domain Policy"},
	"crlf":               {"CWE-93", "CRLF Injection"},
	"ssti":               {"CWE-1336", "Server-Side Template Injection"},
	"deserialization":    {"CWE-502", "Deserialization of Untrusted Data"},
	"missing_header":     {"CWE-693", "Protection Mechanism Failure"},
	"version_disclosure": {"CWE-200", "Exposure of Sensitive Information"},
	"file_upload":        {"CWE-434", "Unrestricted Upload of File with Dangerous Type"},
}

// cweIDToName provides O(1) reverse lookup from CWE ID → name for
// agent-provided CWE values that may not exist in vulnTypeToCWE.
var cweIDToName map[string]string

func init() {
	cweIDToName = make(map[string]string, len(vulnTypeToCWE))
	for _, entry := range vulnTypeToCWE {
		cweIDToName[entry.ID] = entry.Name
	}
}

// owaspEntry holds an OWASP Top 10 (2021) category.
type owaspEntry struct {
	ID   string
	Name string
}

// cweToOWASP maps CWE IDs to OWASP Top 10 2021 categories.
var cweToOWASP = map[string]owaspEntry{
	// A01:2021 – Broken Access Control
	"CWE-639":  {"A01", "Broken Access Control"},
	"CWE-284":  {"A01", "Broken Access Control"},
	"CWE-942":  {"A01", "Broken Access Control"},
	"CWE-601":  {"A01", "Broken Access Control"},
	"CWE-22":   {"A01", "Broken Access Control"},
	"CWE-1021": {"A01", "Broken Access Control"},

	// A02:2021 – Cryptographic Failures
	// (no direct CWE mappings from our vuln types yet)

	// A03:2021 – Injection
	"CWE-79":   {"A03", "Injection"},
	"CWE-89":   {"A03", "Injection"},
	"CWE-78":   {"A03", "Injection"},
	"CWE-93":   {"A03", "Injection"},
	"CWE-611":  {"A03", "Injection"},
	"CWE-1336": {"A03", "Injection"},
	"CWE-98":   {"A03", "Injection"},

	// A04:2021 – Insecure Design
	"CWE-434": {"A04", "Insecure Design"},

	// A05:2021 – Security Misconfiguration
	"CWE-693": {"A05", "Security Misconfiguration"},
	"CWE-200": {"A05", "Security Misconfiguration"},

	// A07:2021 – Identification and Authentication Failures
	"CWE-287": {"A07", "Identification and Authentication Failures"},
	"CWE-352": {"A07", "Identification and Authentication Failures"},

	// A08:2021 – Software and Data Integrity Failures
	"CWE-502": {"A08", "Software and Data Integrity Failures"},

	// A10:2021 – Server-Side Request Forgery
	"CWE-918": {"A10", "Server-Side Request Forgery"},
}

// owaspIDToName provides direct OWASP ID → name lookup for agent-provided
// OWASP values where no CWE is available to cross-reference.
var owaspIDToName = map[string]string{
	"A01": "Broken Access Control",
	"A02": "Cryptographic Failures",
	"A03": "Injection",
	"A04": "Insecure Design",
	"A05": "Security Misconfiguration",
	"A06": "Vulnerable and Outdated Components",
	"A07": "Identification and Authentication Failures",
	"A08": "Software and Data Integrity Failures",
	"A09": "Security Logging and Monitoring Failures",
	"A10": "Server-Side Request Forgery",
}

// vulnTypeToPTES maps vulnerability type → PTES testing phase.
var vulnTypeToPTES = map[string]string{
	"xss":                "Vulnerability Analysis",
	"sqli":               "Exploitation",
	"ssrf":               "Exploitation",
	"idor":               "Exploitation",
	"lfi":                "Exploitation",
	"rfi":                "Exploitation",
	"rce":                "Exploitation",
	"csrf":               "Vulnerability Analysis",
	"xxe":                "Exploitation",
	"open_redirect":      "Vulnerability Analysis",
	"auth_bypass":        "Exploitation",
	"info_disclosure":    "Intelligence Gathering",
	"subdomain_takeover": "Intelligence Gathering",
	"clickjacking":       "Vulnerability Analysis",
	"cors":               "Vulnerability Analysis",
	"crlf":               "Vulnerability Analysis",
	"ssti":               "Exploitation",
	"deserialization":    "Exploitation",
	"missing_header":     "Vulnerability Analysis",
	"version_disclosure": "Intelligence Gathering",
	"file_upload":        "Exploitation",
}

// vulnTypeKeywords mirrors the reporting package's extractVulnType() logic
// so the web package can infer mappings without importing the reporting package.
var vulnTypeKeywords = []struct {
	typeName string
	keywords []string
}{
	{"rce", []string{"remote code execution", "rce", "command injection", "os command", "code execution"}},
	{"sqli", []string{"sql injection", "sqli", "sql inject", "blind sql", "union select", "error-based sql"}},
	{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "reflected xss", "stored xss", "dom xss", "script injection"}},
	{"ssrf", []string{"ssrf", "server-side request forgery", "server side request forgery"}},
	{"idor", []string{"idor", "insecure direct object", "broken access control", "unauthorized access"}},
	{"lfi", []string{"local file inclusion", "lfi", "file inclusion", "path traversal", "directory traversal"}},
	{"rfi", []string{"remote file inclusion", "rfi"}},
	{"file_upload", []string{"file upload", "unrestricted upload", "webshell upload", "malicious file upload", "arbitrary file upload"}},
	{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery"}},
	{"xxe", []string{"xxe", "xml external entity"}},
	{"open_redirect", []string{"open redirect", "url redirect", "unvalidated redirect"}},
	{"auth_bypass", []string{"authentication bypass", "auth bypass", "login bypass"}},
	{"ssti", []string{"ssti", "server-side template injection", "template injection"}},
	{"deserialization", []string{"deserialization", "insecure deserialization", "object injection"}},
	{"subdomain_takeover", []string{"subdomain takeover", "dangling dns", "unclaimed subdomain"}},
	{"clickjacking", []string{"clickjacking", "ui redressing"}},
	{"cors", []string{"cors", "cross-origin resource sharing"}},
	{"crlf", []string{"crlf injection", "http response splitting"}},
	{"info_disclosure", []string{"information disclosure", "info disclosure", "sensitive data exposure", "data leak", "credential leak", "password leak", "exposed secret", "token leak"}},
	{"missing_header", []string{"missing header", "security header", "x-frame-options", "content-security-policy", "hsts"}},
	{"version_disclosure", []string{"version disclosure", "server header", "x-powered-by", "technology disclosure"}},
}

// inferVulnType extracts a vulnerability class from title and description.
func inferVulnType(title, description string) string {
	lower := strings.ToLower(title + " " + description)
	for _, vt := range vulnTypeKeywords {
		for _, kw := range vt.keywords {
			if strings.Contains(lower, kw) {
				return vt.typeName
			}
		}
	}
	return ""
}

// InferVulnMappings derives CWE, OWASP, and PTES mappings for a vulnerability.
// If the VulnSummary already has CWE/OWASP populated (agent-provided), those
// values take priority. Otherwise, keyword-based inference is used.
func InferVulnMappings(v VulnSummary) VulnMappings {
	var m VulnMappings

	// If agent already provided CWE, use it with O(1) name lookup
	if v.CWE != "" {
		m.CWEID = v.CWE
		m.CWEName = cweIDToName[v.CWE] // empty string if unknown — fine
	}

	// If agent already provided OWASP, use it with direct name lookup
	if v.OWASP != "" {
		m.OWASP = v.OWASP
		m.OWASPName = owaspIDToName[v.OWASP]
	}

	// Infer from keywords if not already set
	vulnType := inferVulnType(v.Title, v.Description)
	if vulnType != "" {
		if m.CWEID == "" {
			if cwe, ok := vulnTypeToCWE[vulnType]; ok {
				m.CWEID = cwe.ID
				m.CWEName = cwe.Name
			}
		}
		if m.OWASP == "" && m.CWEID != "" {
			if owasp, ok := cweToOWASP[m.CWEID]; ok {
				m.OWASP = owasp.ID
				m.OWASPName = owasp.Name
			}
		}
		if ptes, ok := vulnTypeToPTES[vulnType]; ok {
			m.PTES = ptes
		}
	}

	// If we have a CWE but no OWASP yet, try CWE→OWASP cross-reference
	if m.OWASP == "" && m.CWEID != "" {
		if owasp, ok := cweToOWASP[m.CWEID]; ok {
			m.OWASP = owasp.ID
			m.OWASPName = owasp.Name
		}
	}

	return m
}
