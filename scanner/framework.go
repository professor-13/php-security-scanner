package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Framework represents a detected PHP framework
type Framework struct {
	Name    string
	Version string
}

// FrameworkRules returns additional rules based on detected framework
func GetFrameworkRules(framework Framework) []Rule {
	switch strings.ToLower(framework.Name) {
	case "laravel":
		return getLaravelRules()
	case "wordpress":
		return getWordPressRules()
	case "symfony":
		return getSymfonyRules()
	case "codeigniter":
		return getCodeIgniterRules()
	default:
		return nil
	}
}

// DetectFramework detects the PHP framework from composer.json or wp-config.php
func DetectFramework(projectRoot string) Framework {
	// Check for WordPress
	wpConfig := filepath.Join(projectRoot, "wp-config.php")
	if _, err := os.Stat(wpConfig); err == nil {
		return Framework{Name: "wordpress"}
	}
	wpContent := filepath.Join(projectRoot, "wp-content")
	if info, err := os.Stat(wpContent); err == nil && info.IsDir() {
		return Framework{Name: "wordpress"}
	}

	// Check composer.json
	composerPath := filepath.Join(projectRoot, "composer.json")
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return Framework{Name: "generic"}
	}

	var composer struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return Framework{Name: "generic"}
	}

	for pkg, ver := range composer.Require {
		switch {
		case strings.Contains(pkg, "laravel/framework"):
			return Framework{Name: "laravel", Version: ver}
		case strings.Contains(pkg, "symfony/framework-bundle"):
			return Framework{Name: "symfony", Version: ver}
		case strings.Contains(pkg, "codeigniter"):
			return Framework{Name: "codeigniter", Version: ver}
		case strings.Contains(pkg, "cakephp/cakephp"):
			return Framework{Name: "cakephp", Version: ver}
		case strings.Contains(pkg, "yiisoft/yii2"):
			return Framework{Name: "yii2", Version: ver}
		}
	}

	return Framework{Name: "generic"}
}

func getLaravelRules() []Rule {
	return []Rule{
		{
			ID:             "LARAVEL-001",
			Category:       "SQL Injection",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)DB::raw\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "Laravel DB::raw() with user input",
			Recommendation: "Use parameter binding: DB::raw('query WHERE id = ?', [$id])",
			CWE:            "CWE-89",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-002",
			Category:       "SQL Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)whereRaw\s*\(.*\$`),
			Description:    "Laravel whereRaw() with variable (potential SQL injection)",
			Recommendation: "Use parameter binding: whereRaw('column = ?', [$value])",
			CWE:            "CWE-89",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-003",
			Category:       "SQL Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)(selectRaw|havingRaw|orderByRaw|groupByRaw)\s*\(.*\$`),
			Description:    "Laravel raw query method with variable",
			Recommendation: "Use parameter binding with raw methods",
			CWE:            "CWE-89",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-004",
			Category:       "Cross-Site Scripting",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`\{!!\s*\$`),
			Description:    "Laravel Blade unescaped output {!! $var !!}",
			Recommendation: "Use {{ $var }} for auto-escaped output unless HTML is intentional",
			CWE:            "CWE-79",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-005",
			Category:       "Mass Assignment",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$request->all\s*\(\)`),
			Description:    "Mass assignment risk: $request->all() passes all input",
			Recommendation: "Use $request->only(['field1', 'field2']) or $request->validated()",
			CWE:            "CWE-915",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-006",
			Category:       "Insecure Configuration",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)APP_DEBUG\s*=\s*true`),
			Description:    "Laravel debug mode enabled in environment",
			Recommendation: "Set APP_DEBUG=false in production; debug mode exposes sensitive data",
			CWE:            "CWE-200",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
		{
			ID:             "LARAVEL-007",
			Category:       "Authentication & Credentials",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)APP_KEY\s*=\s*base64:[A-Za-z0-9+/=]+`),
			Description:    "Laravel APP_KEY exposed in source code",
			Recommendation: "Never commit .env files; use environment-specific configuration",
			CWE:            "CWE-798",
			Tags:           []string{"laravel"},
			Source:         "framework:laravel",
		},
	}
}

func getWordPressRules() []Rule {
	return []Rule{
		{
			ID:             "WP-001",
			Category:       "SQL Injection",
			Severity:       SeverityCritical,
			Pattern:        regexp.MustCompile(`(?i)\$wpdb->query\s*\(\s*["']\s*(SELECT|INSERT|UPDATE|DELETE).*\$`),
			Description:    "WordPress direct query without $wpdb->prepare()",
			Recommendation: "Use $wpdb->prepare() for all database queries with variables",
			CWE:            "CWE-89",
			Tags:           []string{"wordpress"},
			Source:         "framework:wordpress",
		},
		{
			ID:             "WP-002",
			Category:       "Cross-Site Scripting",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)echo\s+\$_(GET|POST|REQUEST)`),
			Description:    "WordPress: unescaped user input output",
			Recommendation: "Use esc_html(), esc_attr(), esc_url(), or wp_kses() for output",
			CWE:            "CWE-79",
			Tags:           []string{"wordpress"},
			Source:         "framework:wordpress",
		},
		{
			ID:             "WP-003",
			Category:       "CSRF",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$_POST\s*\[.*\](?!.*wp_verify_nonce|check_admin_referer)`),
			Description:    "WordPress: POST processing without nonce verification",
			Recommendation: "Use wp_verify_nonce() or check_admin_referer() before processing POST data",
			CWE:            "CWE-352",
			Tags:           []string{"wordpress"},
			Source:         "framework:wordpress",
		},
		{
			ID:             "WP-004",
			Category:       "Open Redirect",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)wp_redirect\s*\(.*\$_(GET|POST|REQUEST)`),
			Description:    "WordPress: open redirect via wp_redirect() with user input",
			Recommendation: "Use wp_safe_redirect() instead of wp_redirect() with user input",
			CWE:            "CWE-601",
			Tags:           []string{"wordpress"},
			Source:         "framework:wordpress",
		},
		{
			ID:             "WP-005",
			Category:       "Authentication & Credentials",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)update_option\s*\(\s*['"].*secret|password|key|token`),
			Description:    "WordPress: storing sensitive data in options table",
			Recommendation: "Use WordPress transients or dedicated secret storage for sensitive data",
			CWE:            "CWE-312",
			Tags:           []string{"wordpress"},
			Source:         "framework:wordpress",
		},
	}
}

func getSymfonyRules() []Rule {
	return []Rule{
		{
			ID:             "SYMFONY-001",
			Category:       "Cross-Site Scripting",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\|\s*raw\b`),
			Description:    "Symfony Twig: raw filter bypasses auto-escaping",
			Recommendation: "Remove |raw filter unless intentionally rendering trusted HTML",
			CWE:            "CWE-79",
			Tags:           []string{"symfony", "twig"},
			Source:         "framework:symfony",
		},
		{
			ID:             "SYMFONY-002",
			Category:       "Insecure Configuration",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)framework:\s*\n\s*profiler:\s*\n\s*enabled:\s*true`),
			Description:    "Symfony profiler enabled (should be disabled in production)",
			Recommendation: "Disable profiler in production environment configuration",
			CWE:            "CWE-200",
			Tags:           []string{"symfony"},
			Source:         "framework:symfony",
		},
	}
}

func getCodeIgniterRules() []Rule {
	return []Rule{
		{
			ID:             "CI-001",
			Category:       "SQL Injection",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$this->db->query\s*\(.*\$`),
			Description:    "CodeIgniter: direct query with variable (use query bindings)",
			Recommendation: "Use query bindings: $this->db->query('SELECT * WHERE id = ?', array($id))",
			CWE:            "CWE-89",
			Tags:           []string{"codeigniter"},
			Source:         "framework:codeigniter",
		},
		{
			ID:             "CI-002",
			Category:       "Cross-Site Scripting",
			Severity:       SeverityHigh,
			Pattern:        regexp.MustCompile(`(?i)\$this->input->(get|post)\s*\(`),
			Description:    "CodeIgniter: raw input without XSS filtering",
			Recommendation: "Use $this->input->get('key', TRUE) to enable XSS filtering",
			CWE:            "CWE-79",
			Tags:           []string{"codeigniter"},
			Source:         "framework:codeigniter",
		},
	}
}
