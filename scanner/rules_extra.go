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

		// ═══════════════════════════════════════════════════════════════
		// Plaintext Password Detection (Gap #1)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "PASSWD-001",
			Category:       "Plaintext Password",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)INSERT\s+INTO\s+.*(?:password|passwd|pwd|user_pass)['")\s,].*VALUES\s*\(`),
			Description:    "Password inserted into database — verify it is hashed with password_hash()",
			Recommendation: "Always use password_hash() before storing passwords; never store plaintext",
			CWE:            "CWE-256",
			Source:         "builtin",
		},
		{
			ID:             "PASSWD-002",
			Category:       "Plaintext Password",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)(WHERE|AND)\s+.*(?:password|passwd|pwd)\s*=\s*['"]\s*\$`),
			Description:    "Password compared in plaintext in SQL query (no hash verification)",
			Recommendation: "Use password_verify() to check passwords against stored hashes; never compare in SQL",
			CWE:            "CWE-256",
			Source:         "builtin",
		},
		{
			ID:             "PASSWD-003",
			Category:       "Plaintext Password",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)(WHERE|AND)\s+.*(?:password|passwd|pwd)\s*=\s*['"]?\s*\$_(POST|GET|REQUEST)`),
			Description:    "User password directly compared in SQL WHERE clause",
			Recommendation: "Retrieve hash from DB and use password_verify($input, $hash) instead",
			CWE:            "CWE-256",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// PCI-DSS / Sensitive Data Storage (Gap #2)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "PCI-001",
			Category:       "Sensitive Data Storage",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)INSERT\s+INTO\s+.*(?:cardnumber|card_number|cc_number|credit_card|card_num)['")\s,]`),
			Description:    "Credit card number being stored in database (PCI-DSS violation)",
			Recommendation: "Never store full card numbers; use a payment gateway (Stripe, PayPal); PCI-DSS requires tokenization",
			CWE:            "CWE-312",
			Source:         "builtin",
		},
		{
			ID:             "PCI-002",
			Category:       "Sensitive Data Storage",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)INSERT\s+INTO\s+.*(?:cvv|cvc|cvv2|cvc2|security_code|card_code)['")\s,]`),
			Description:    "CVV/CVC being stored in database (PCI-DSS explicitly prohibits this)",
			Recommendation: "NEVER store CVV/CVC data; process payments through a certified payment gateway",
			CWE:            "CWE-312",
			Source:         "builtin",
		},
		{
			ID:             "PCI-003",
			Category:       "Sensitive Data Storage",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$_(POST|GET|REQUEST)\s*\[\s*['"](?:cardnumber|card_number|cc_number|cvv|cvc|expdate|exp_date|card_exp)`),
			Description:    "Credit card data received from user input — ensure it is not stored",
			Recommendation: "Send card data directly to payment processor; never store on your server",
			CWE:            "CWE-312",
			Source:         "builtin",
		},
		{
			ID:             "PCI-004",
			Category:       "Sensitive Data Storage",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)INSERT\s+INTO\s+.*(?:ssn|social_security|national_id|tax_id)['")\s,]`),
			Description:    "Sensitive PII (SSN/national ID) being stored — ensure proper encryption",
			Recommendation: "Encrypt sensitive PII at rest; restrict access; comply with data protection laws",
			CWE:            "CWE-312",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Information Leakage — DB Errors (Gap #6)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "INFO-008",
			Category:       "Information Disclosure",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)(echo|print|die|exit)\s*\(?\s*(mysqli_error|mysql_error|pg_last_error|sqlsrv_errors)\s*\(`),
			Description:    "Database error message displayed to user (leaks DB structure)",
			Recommendation: "Log errors to file with error_log(); show generic error messages to users",
			CWE:            "CWE-209",
			Source:         "builtin",
		},
		{
			ID:             "INFO-009",
			Category:       "Information Disclosure",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)(echo|print|die|exit)\s*\(?\s*\$[a-zA-Z_]*err`),
			Description:    "Error variable echoed to user output",
			Recommendation: "Log errors internally; display user-friendly error messages",
			CWE:            "CWE-209",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Insecure Session Handling (Gap #8)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "SESSION-002",
			Category:       "Insecure Session",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)unset\s*\(\s*\$_SESSION\s*\[`),
			Description:    "Session variable unset individually (may leave session partially active)",
			Recommendation: "Use session_destroy() and session_unset() for complete logout; regenerate session ID",
			CWE:            "CWE-613",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Business Logic Flaws (Gap #9)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "LOGIC-001",
			Category:       "Business Logic",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$_(POST|GET|REQUEST)\s*\[\s*['"](?:total|price|amount|cost|subtotal|grand_total|total_price|total_amount|order_total|final_price)['"]`),
			Description:    "Price/total received from client input (attacker can modify)",
			Recommendation: "NEVER trust client-side prices; always recalculate totals server-side from DB prices",
			CWE:            "CWE-20",
			Source:         "builtin",
		},
		{
			ID:             "LOGIC-002",
			Category:       "Business Logic",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)SELECT\s+MAX\s*\(\s*\w*id\w*\s*\)\s*\+\s*1`),
			Description:    "Auto-increment ID generated via SELECT MAX()+1 (race condition vulnerability)",
			Recommendation: "Use database AUTO_INCREMENT or sequences; MAX()+1 causes duplicates under concurrency",
			CWE:            "CWE-362",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Missing Input Validation (Gap #10)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "VALID-001",
			Category:       "Input Validation",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)\$_(POST|GET|REQUEST)\s*\[\s*['"](email|e_mail|user_email)['"]\s*\]\s*;`),
			Description:    "Email from user input used without validation",
			Recommendation: "Use filter_var($email, FILTER_VALIDATE_EMAIL) to validate email format",
			CWE:            "CWE-20",
			Source:         "builtin",
		},
		{
			ID:             "VALID-002",
			Category:       "Input Validation",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)\$_(POST|GET|REQUEST)\s*\[\s*['"](url|website|link|redirect|callback|return_url)['"]\s*\]\s*;`),
			Description:    "URL from user input used without validation",
			Recommendation: "Use filter_var($url, FILTER_VALIDATE_URL) and whitelist allowed domains",
			CWE:            "CWE-20",
			Source:         "builtin",
		},

		// ═══════════════════════════════════════════════════════════════
		// Missing Security Headers (Gap #7)
		// ═══════════════════════════════════════════════════════════════
		{
			ID:             "COOKIE-001",
			Category:       "Insecure Cookie",
			Severity:       SeverityMedium,
			Pattern:        regexp.MustCompile(`(?i)setcookie\s*\([^)]*\)\s*;`),
			Description:    "Cookie set without Secure/HttpOnly/SameSite flags",
			Recommendation: "Use setcookie() with secure=true, httponly=true, samesite='Strict'",
			CWE:            "CWE-614",
			Source:         "builtin",
		},
	}
}
