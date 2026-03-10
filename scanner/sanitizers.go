package scanner

import (
	"regexp"
	"strings"
)

// SanitizerDef maps vulnerability categories to their sanitizer patterns
type SanitizerDef struct {
	Category string
	Pattern  *regexp.Regexp
	FuncName string // Human-readable function name
}

// GetSanitizers returns all known sanitizer definitions
func GetSanitizers() []SanitizerDef {
	return []SanitizerDef{
		// SQL Injection sanitizers
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bintval\s*\(`), FuncName: "intval()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bfloatval\s*\(`), FuncName: "floatval()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)->prepare\s*\(`), FuncName: "prepare()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bbind_param\s*\(`), FuncName: "bind_param()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bbindParam\s*\(`), FuncName: "bindParam()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bbindValue\s*\(`), FuncName: "bindValue()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)mysqli_real_escape_string\s*\(`), FuncName: "mysqli_real_escape_string()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\(int\)\s*\$`), FuncName: "(int) cast"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\(float\)\s*\$`), FuncName: "(float) cast"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bsettype\s*\(`), FuncName: "settype()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bctype_digit\s*\(`), FuncName: "ctype_digit()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\bis_numeric\s*\(`), FuncName: "is_numeric()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\babs\s*\(`), FuncName: "abs()"},
		{Category: "SQL Injection", Pattern: regexp.MustCompile(`(?i)\(bool\)\s*\$`), FuncName: "(bool) cast"},

		// XSS sanitizers
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bhtmlspecialchars\s*\(`), FuncName: "htmlspecialchars()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bhtmlentities\s*\(`), FuncName: "htmlentities()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bstrip_tags\s*\(`), FuncName: "strip_tags()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\burlencode\s*\(`), FuncName: "urlencode()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\brawurlencode\s*\(`), FuncName: "rawurlencode()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bjson_encode\s*\(`), FuncName: "json_encode()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)filter_var\s*\(.*FILTER_SANITIZE`), FuncName: "filter_var(FILTER_SANITIZE)"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)filter_input\s*\(`), FuncName: "filter_input()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\|\s*escape\b`), FuncName: "Twig |escape"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\|\s*e\b`), FuncName: "Twig |e"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`\{\{.*\}\}`), FuncName: "Blade {{ }}"},
		// WordPress escaping
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\besc_html\s*\(`), FuncName: "esc_html()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\besc_attr\s*\(`), FuncName: "esc_attr()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\besc_url\s*\(`), FuncName: "esc_url()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bwp_kses\s*\(`), FuncName: "wp_kses()"},
		{Category: "Cross-Site Scripting", Pattern: regexp.MustCompile(`(?i)\bwp_kses_post\s*\(`), FuncName: "wp_kses_post()"},

		// Command Injection sanitizers
		{Category: "Command Injection", Pattern: regexp.MustCompile(`(?i)\bescapeshellarg\s*\(`), FuncName: "escapeshellarg()"},
		{Category: "Command Injection", Pattern: regexp.MustCompile(`(?i)\bescapeshellcmd\s*\(`), FuncName: "escapeshellcmd()"},

		// Path Traversal sanitizers
		{Category: "Path Traversal", Pattern: regexp.MustCompile(`(?i)\bbasename\s*\(`), FuncName: "basename()"},
		{Category: "Path Traversal", Pattern: regexp.MustCompile(`(?i)\brealpath\s*\(`), FuncName: "realpath()"},
		{Category: "Path Traversal", Pattern: regexp.MustCompile(`(?i)\bpathinfo\s*\(`), FuncName: "pathinfo()"},
		{Category: "Path Traversal", Pattern: regexp.MustCompile(`(?i)\bin_array\s*\(`), FuncName: "in_array() whitelist"},

		// File Inclusion sanitizers
		{Category: "File Inclusion", Pattern: regexp.MustCompile(`(?i)\bbasename\s*\(`), FuncName: "basename()"},
		{Category: "File Inclusion", Pattern: regexp.MustCompile(`(?i)\bin_array\s*\(`), FuncName: "in_array() whitelist"},

		// SSRF sanitizers
		{Category: "SSRF", Pattern: regexp.MustCompile(`(?i)filter_var\s*\(.*FILTER_VALIDATE_URL`), FuncName: "filter_var(FILTER_VALIDATE_URL)"},
		{Category: "SSRF", Pattern: regexp.MustCompile(`(?i)\bparse_url\s*\(`), FuncName: "parse_url()"},
		{Category: "SSRF", Pattern: regexp.MustCompile(`(?i)\bin_array\s*\(`), FuncName: "in_array() whitelist"},

		// Open Redirect sanitizers
		{Category: "Open Redirect", Pattern: regexp.MustCompile(`(?i)filter_var\s*\(.*FILTER_VALIDATE_URL`), FuncName: "filter_var(FILTER_VALIDATE_URL)"},
		{Category: "Open Redirect", Pattern: regexp.MustCompile(`(?i)\bparse_url\s*\(`), FuncName: "parse_url()"},

		// Deserialization sanitizers
		{Category: "Insecure Deserialization", Pattern: regexp.MustCompile(`(?i)\bjson_decode\s*\(`), FuncName: "json_decode()"},
		{Category: "Insecure Deserialization", Pattern: regexp.MustCompile(`(?i)allowed_classes.*false`), FuncName: "allowed_classes:false"},
	}
}

// CheckSanitizer checks if a line contains a sanitizer for the given category
func CheckSanitizer(line string, category string) string {
	for _, s := range cachedSanitizers {
		if s.Category == category && s.Pattern.MatchString(line) {
			return s.FuncName
		}
	}
	return ""
}

// CheckSanitizerWraps checks if a sanitizer for the given category appears BEFORE
// the match position in the line (heuristic: sanitizer wraps the dangerous call)
func CheckSanitizerWraps(line string, category string, matchStart int) string {
	for _, s := range cachedSanitizers {
		if s.Category != category {
			continue
		}
		loc := s.Pattern.FindStringIndex(line)
		if loc == nil {
			continue
		}
		// Sanitizer must appear before or at the match to be wrapping it
		if loc[0] <= matchStart {
			return s.FuncName
		}
	}
	return ""
}

// CheckSanitizerInContext checks if a variable was sanitized within lookback lines before current
func CheckSanitizerInContext(allLines []string, currentLineIdx int, varName string, category string, lookback int) string {
	if varName == "" {
		return ""
	}
	start := currentLineIdx - lookback
	if start < 0 {
		start = 0
	}
	for i := start; i < currentLineIdx; i++ {
		line := allLines[i]
		// Check if this line assigns varName using a sanitizer
		if strings.Contains(line, varName) && strings.Contains(line, "=") {
			san := CheckSanitizer(line, category)
			if san != "" {
				return san + " (context)"
			}
		}
	}
	return ""
}

// CheckAnySanitizer checks if a line contains any known sanitizer
func CheckAnySanitizer(line string) string {
	for _, s := range cachedSanitizers {
		if s.Pattern.MatchString(line) {
			return s.FuncName
		}
	}
	return ""
}

// cachedSanitizers holds pre-loaded sanitizer definitions
var cachedSanitizers = GetSanitizers()
