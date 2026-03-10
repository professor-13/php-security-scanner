package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// YAMLRuleFile represents a YAML/JSON rule file structure
// We use JSON parsing to avoid adding a YAML dependency,
// but support both .json and .yaml/.yml file formats
type YAMLRuleFile struct {
	Rules []YAMLRule `json:"rules"`
}

type YAMLRule struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	CWE            string   `json:"cwe"`
	Description    string   `json:"description"`
	Patterns       []string `json:"patterns"`
	Recommendation string   `json:"recommendation"`
	Tags           []string `json:"tags"`
}

// LoadRulesFromDir loads all rule files from a directory
// Supports .json files with the same schema
func LoadRulesFromDir(dir string) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("rules directory not found: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules path is not a directory: %s", dir)
	}

	var allRules []Rule

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" {
			return nil
		}

		rules, loadErr := LoadRulesFromFile(path)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load rules from %s: %v\n", path, loadErr)
			return nil
		}

		allRules = append(allRules, rules...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking rules directory: %w", err)
	}

	return allRules, nil
}

// LoadRulesFromFile loads rules from a single JSON file
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}

	var ruleFile YAMLRuleFile
	if err := json.Unmarshal(data, &ruleFile); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}

	sourceLabel := "yaml:" + filepath.Base(path)
	var rules []Rule

	for _, yr := range ruleFile.Rules {
		if yr.ID == "" || yr.Category == "" || len(yr.Patterns) == 0 {
			fmt.Fprintf(os.Stderr, "Warning: Skipping incomplete rule in %s (id=%s)\n", path, yr.ID)
			continue
		}

		for _, pattern := range yr.Patterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Invalid regex in rule %s: %v\n", yr.ID, err)
				continue
			}

			rules = append(rules, Rule{
				ID:             yr.ID,
				Category:       yr.Category,
				Severity:       ParseSeverity(yr.Severity),
				Pattern:        compiled,
				Description:    yr.Description,
				Recommendation: yr.Recommendation,
				CWE:            yr.CWE,
				Tags:           yr.Tags,
				Source:          sourceLabel,
			})
		}
	}

	return rules, nil
}

// GenerateExampleRuleFile creates an example rule file for users
func GenerateExampleRuleFile(outputPath string) error {
	example := YAMLRuleFile{
		Rules: []YAMLRule{
			{
				ID:             "CUSTOM-001",
				Category:       "Custom Rules",
				Severity:       "high",
				CWE:            "CWE-89",
				Description:    "Example: Raw DB query in custom framework",
				Patterns:       []string{"(?i)DB::raw\\(.*\\$_"},
				Recommendation: "Use parameterized queries instead of DB::raw()",
				Tags:           []string{"custom", "sql"},
			},
			{
				ID:             "LARAVEL-001",
				Category:       "SQL Injection",
				Severity:       "critical",
				CWE:            "CWE-89",
				Description:    "Laravel raw query with user input",
				Patterns:       []string{"(?i)DB::raw\\(.*\\$_(GET|POST|REQUEST)", "(?i)whereRaw\\(.*\\$_(GET|POST|REQUEST)"},
				Recommendation: "Use Laravel query builder with parameter binding: DB::table()->where()",
				Tags:           []string{"laravel", "framework"},
			},
			{
				ID:             "WP-001",
				Category:       "SQL Injection",
				Severity:       "critical",
				CWE:            "CWE-89",
				Description:    "WordPress direct query without prepare()",
				Patterns:       []string{"(?i)\\$wpdb->query\\((?!.*\\$wpdb->prepare)"},
				Recommendation: "Use $wpdb->prepare() for all database queries",
				Tags:           []string{"wordpress", "framework"},
			},
		},
	}

	data, err := json.MarshalIndent(example, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
