package scanner

import "regexp"

// GetExtraRules returns additional vulnerability rules beyond OWASP Top 10
func GetExtraRules() []Rule {
	return []Rule{
		// ═══════════════════════════════════════════════════════════════
		// Type Juggling (PHP-specific)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "TYPE-001",
			Category:       "Type Juggling",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$_(GET|POST|REQUEST|COOKIE)\s*\[.*\]\s*==\s*['"]`),
			Description:    "Loose comparison (==) with user input in auth context",
			Recommendation: "Use strict comparison (===) for all security-sensitive checks",
			CWE:            "CWE-1025",
			Source:         "builtin",
		},
		{
			ID:             "TYPE-002",
			Category:       "Type Juggling",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)(password|token|secret|hash)\s*==\s*\$`),
			Description:    "Loose comparison of sensitive value (timing-unsafe)",
			Recommendation: "Use hash_equals() for comparing hashes/tokens; use === for strict comparison",
			CWE:            "CWE-1025",
			Source:         "builtin",
		},
		{
			ID:             "TYPE-003",
			Category:       "Type Juggling",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)strcmp\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "strcmp() with user input (returns 0 for array input, bypassing checks)",
			Recommendation: "Validate input type before strcmp(); use === for simple comparisons",
			CWE:            "CWE-1025",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Header Injection
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "HEADER-001",
			Category:       "Header Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)header\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "HTTP header injection via user input",
			Recommendation: "Strip \\r\\n from user input before passing to header(); validate against whitelist",
			CWE:            "CWE-113",
			Source:         "builtin",
		},
		{
			ID:             "HEADER-002",
			Category:       "Header Injection",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)setcookie\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "Cookie value from user input (header injection risk)",
			Recommendation: "Validate and sanitize cookie values; strip control characters",
			CWE:            "CWE-113",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Log Injection
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "LOG-001",
			Category:       "Log Injection",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)(error_log|syslog|trigger_error)\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "Log injection: user input written to logs without sanitization",
			Recommendation: "Strip newlines and control characters from user input before logging",
			CWE:            "CWE-117",
			Source:         "builtin",
		},
		{
			ID:             "LOG-002",
			Category:       "Log Injection",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)(fwrite|file_put_contents)\s*\(.*log.*\$_(GET|POST|REQUEST)`),
			Description:    "User input written to log file",
			Recommendation: "Sanitize user input before writing to logs; strip newlines and special characters",
			CWE:            "CWE-117",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// LDAP Injection
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "LDAP-001",
			Category:       "LDAP Injection",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)ldap_search\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "LDAP search with user input (LDAP injection)",
			Recommendation: "Use ldap_escape() to sanitize user input in LDAP queries",
			CWE:            "CWE-90",
			Source:         "builtin",
		},
		{
			ID:             "LDAP-002",
			Category:       "LDAP Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)ldap_(search|bind|compare|modify|add|delete)\s*\(.*\$`),
			Description:    "LDAP operation with variable input",
			Recommendation: "Validate and escape all input used in LDAP operations",
			CWE:            "CWE-90",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// XPath Injection
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "XPATH-001",
			Category:       "XPath Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)(xpath|query)\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "XPath query with user input",
			Recommendation: "Use parameterized XPath queries; validate and escape user input",
			CWE:            "CWE-643",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Race Conditions (TOCTOU)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "RACE-001",
			Category:       "Race Condition",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)file_exists\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)`),
			Description:    "TOCTOU: file_exists() check (verify no race with subsequent file operation)",
			Recommendation: "Use atomic file operations; handle errors from fopen() directly instead of checking first",
			CWE:            "CWE-367",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Insecure HTTP
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "HTTP-001",
			Category:       "Insecure Transport",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)(curl_setopt|file_get_contents|fopen)\s*\(.*['"]http://`),
			Description:    "Insecure HTTP connection (should use HTTPS)",
			Recommendation: "Use HTTPS for all external communications",
			CWE:            "CWE-319",
			Source:         "builtin",
		},
		{
			ID:             "HTTP-002",
			Category:       "Insecure Transport",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)`),
			Description:    "SSL certificate verification disabled",
			Recommendation: "Always enable SSL certificate verification; set CURLOPT_SSL_VERIFYPEER to true",
			CWE:            "CWE-295",
			Source:         "builtin",
		},
		{
			ID:             "HTTP-003",
			Category:       "Insecure Transport",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)CURLOPT_SSL_VERIFYHOST\s*,\s*(false|0)`),
			Description:    "SSL host verification disabled",
			Recommendation: "Always enable SSL host verification; set CURLOPT_SSL_VERIFYHOST to 2",
			CWE:            "CWE-295",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Regex DoS (ReDoS)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "REDOS-001",
			Category:       "Regex DoS",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)preg_(match|replace|split)\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "Regular expression with user-controlled input (ReDoS risk)",
			Recommendation: "Never use user input in regex patterns; validate input length and set timeouts",
			CWE:            "CWE-1333",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Email Injection
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "EMAIL-001",
			Category:       "Email Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\bmail\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "PHP mail() with user input (email header injection)",
			Recommendation: "Validate email addresses; strip newlines from headers; use a mail library",
			CWE:            "CWE-93",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Session Fixation
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "SESSION-001",
			Category:       "Session Fixation",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)session_id\s*\(.*\$_(GET|POST|REQUEST|COOKIE)`),
			Description:    "Session ID set from user input (session fixation)",
			Recommendation: "Never allow users to set session IDs; use session_regenerate_id() after login",
			CWE:            "CWE-384",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Unsafe Object Creation
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "OBJ-001",
			Category:       "Unsafe Object Creation",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)new\s+\$_(GET|POST|REQUEST)`),
			Description:    "Dynamic class instantiation from user input",
			Recommendation: "Validate class name against a whitelist before instantiation",
			CWE:            "CWE-470",
			Source:         "builtin",
		},
		{
			ID:             "OBJ-002",
			Category:       "Unsafe Object Creation",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)(call_user_func|call_user_func_array)\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "Dynamic function call with user input",
			Recommendation: "Validate function name against a whitelist; never pass user input to call_user_func()",
			CWE:            "CWE-470",
			Source:         "builtin",
		},
	}
}
