package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// SemgrepRule represents a parsed Semgrep rule
type SemgrepRule struct {
	ID       string
	Message  string
	Severity string
	Pattern  string
	Patterns []SemgrepPattern // AND patterns
	Languages []string
	Metadata SemgrepMetadata
}

// SemgrepPattern for compound rules
type SemgrepPattern struct {
	Pattern    string
	PatternNot string
}

// SemgrepMetadata from Semgrep rule metadata
type SemgrepMetadata struct {
	CWE        string
	Category   string
	Confidence string
	References []string
}

// ImportedRule is a converted rule ready for export
type ImportedRule struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Pattern        string `json:"pattern"`
	Description    string `json:"description"`
	Recommendation string `json:"recommendation"`
	CWE            string `json:"cwe"`
	Source         string `json:"source"`
}

// ImportSemgrepRules reads a Semgrep YAML file and converts rules to scanner rules
func ImportSemgrepRules(yamlPath string) ([]ImportedRule, error) {
	data, err := os.ReadFile(yamlPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read Semgrep file: %w", err)
	}

	semgrepRules := parseMinimalYAML(string(data))
	if len(semgrepRules) == 0 {
		return nil, fmt.Errorf("no valid rules found in %s", yamlPath)
	}

	var imported []ImportedRule
	for i, sr := range semgrepRules {
		// Only import PHP rules
		if !containsLang(sr.Languages, "php") {
			continue
		}

		// Convert Semgrep pattern to Go regex
		goPattern := semgrepPatternToRegex(sr.Pattern)
		if goPattern == "" {
			continue
		}

		// Validate the regex compiles
		if _, err := regexp.Compile(goPattern); err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: Skipping rule %s (pattern not convertible): %v\n", sr.ID, err)
			continue
		}

		ruleID := sr.ID
		if ruleID == "" {
			ruleID = fmt.Sprintf("SEMGREP-%03d", i+1)
		}

		severity := mapSemgrepSeverity(sr.Severity)
		category := sr.Metadata.Category
		if category == "" {
			category = "Semgrep Import"
		}

		cwe := sr.Metadata.CWE
		if cwe == "" {
			cwe = "CWE-Unknown"
		}

		rule := ImportedRule{
			ID:             ruleID,
			Category:       category,
			Severity:       severity,
			Pattern:        goPattern,
			Description:    sr.Message,
			Recommendation: "Review finding and apply recommended fix",
			CWE:            cwe,
			Source:          fmt.Sprintf("semgrep:%s", filepath.Base(yamlPath)),
		}

		imported = append(imported, rule)
	}

	return imported, nil
}

// SaveImportedRules writes converted rules to a JSON file for the scanner
func SaveImportedRules(rules []ImportedRule, outputPath string) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal rules: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("cannot write rules file: %w", err)
	}

	return nil
}

// ImportSemgrepDir processes all .yaml/.yml files in a directory
func ImportSemgrepDir(dirPath string) ([]ImportedRule, error) {
	var allRules []ImportedRule

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		fullPath := filepath.Join(dirPath, entry.Name())
		rules, err := ImportSemgrepRules(fullPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Warning: %s: %v\n", entry.Name(), err)
			continue
		}

		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal YAML parser (Semgrep rule subset only, no external deps)
// ──────────────────────────────────────────────────────────────────────────────

func parseMinimalYAML(content string) []SemgrepRule {
	var rules []SemgrepRule
	scanner := bufio.NewScanner(strings.NewReader(content))

	var currentRule *SemgrepRule
	var inRules bool
	var inMetadata bool
	var inLanguages bool
	var currentKey string

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := countIndent(line)

		// Top-level "rules:" key
		if trimmed == "rules:" {
			inRules = true
			continue
		}

		if !inRules {
			continue
		}

		// New rule entry (list item under rules:)
		if strings.HasPrefix(trimmed, "- id:") {
			if currentRule != nil {
				rules = append(rules, *currentRule)
			}
			currentRule = &SemgrepRule{
				ID: extractYAMLValue(trimmed[len("- id:"):]),
			}
			inMetadata = false
			inLanguages = false
			currentKey = ""
			continue
		}

		if currentRule == nil {
			continue
		}

		// Handle metadata block
		if trimmed == "metadata:" {
			inMetadata = true
			inLanguages = false
			currentKey = ""
			continue
		}

		// Handle languages block
		if trimmed == "languages:" {
			inLanguages = true
			inMetadata = false
			currentKey = ""
			continue
		}

		// Language list items
		if inLanguages && strings.HasPrefix(trimmed, "- ") {
			lang := strings.TrimSpace(trimmed[2:])
			currentRule.Languages = append(currentRule.Languages, lang)
			continue
		}

		// Exit languages on non-list
		if inLanguages && !strings.HasPrefix(trimmed, "- ") && indent <= 4 {
			inLanguages = false
		}

		// Metadata fields
		if inMetadata && indent >= 6 {
			if strings.HasPrefix(trimmed, "cwe:") {
				currentRule.Metadata.CWE = extractYAMLValue(trimmed[4:])
			} else if strings.HasPrefix(trimmed, "category:") {
				currentRule.Metadata.Category = extractYAMLValue(trimmed[9:])
			} else if strings.HasPrefix(trimmed, "confidence:") {
				currentRule.Metadata.Confidence = extractYAMLValue(trimmed[11:])
			}
			continue
		}

		// Exit metadata on dedent
		if inMetadata && indent < 6 {
			inMetadata = false
		}

		// Rule-level fields
		if indent >= 4 && !inMetadata && !inLanguages {
			if strings.HasPrefix(trimmed, "message:") {
				currentKey = "message"
				val := extractYAMLValue(trimmed[8:])
				if val != "" {
					currentRule.Message = val
				}
			} else if strings.HasPrefix(trimmed, "severity:") {
				currentKey = "severity"
				currentRule.Severity = extractYAMLValue(trimmed[9:])
			} else if strings.HasPrefix(trimmed, "pattern:") {
				currentKey = "pattern"
				val := extractYAMLValue(trimmed[8:])
				if val != "" {
					currentRule.Pattern = val
				}
			} else if strings.HasPrefix(trimmed, "- pattern:") {
				val := extractYAMLValue(trimmed[10:])
				currentRule.Patterns = append(currentRule.Patterns, SemgrepPattern{Pattern: val})
			} else if strings.HasPrefix(trimmed, "- pattern-not:") {
				val := extractYAMLValue(trimmed[14:])
				currentRule.Patterns = append(currentRule.Patterns, SemgrepPattern{PatternNot: val})
			} else if currentKey == "message" && (strings.HasPrefix(line, "      ") || strings.HasPrefix(line, "\t\t\t")) {
				// Multi-line message continuation
				currentRule.Message += " " + trimmed
			} else if currentKey == "pattern" && (strings.HasPrefix(line, "      ") || strings.HasPrefix(line, "\t\t\t")) {
				// Multi-line pattern continuation
				currentRule.Pattern += " " + trimmed
			} else {
				currentKey = ""
			}
		}
	}

	// Don't forget the last rule
	if currentRule != nil {
		rules = append(rules, *currentRule)
	}

	return rules
}

func countIndent(line string) int {
	count := 0
	for _, ch := range line {
		if ch == ' ' {
			count++
		} else if ch == '\t' {
			count += 4
		} else {
			break
		}
	}
	return count
}

func extractYAMLValue(s string) string {
	s = strings.TrimSpace(s)
	// Handle quoted values
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	// Handle block scalar indicators
	if s == "|" || s == ">" || s == "|-" || s == ">-" {
		return ""
	}
	return s
}

// ──────────────────────────────────────────────────────────────────────────────
// Semgrep pattern → Go regex converter
// ──────────────────────────────────────────────────────────────────────────────

func semgrepPatternToRegex(pattern string) string {
	if pattern == "" {
		return ""
	}

	p := strings.TrimSpace(pattern)

	// Skip patterns with complex Semgrep features we can't convert
	if strings.Contains(p, "...") && strings.Count(p, "...") > 2 {
		return "" // Too many ellipsis, too complex
	}

	// Start conversion
	result := p

	// Escape regex-special chars that are literal in Semgrep (keep $ for PHP vars)
	result = strings.ReplaceAll(result, "(", `\(`)
	result = strings.ReplaceAll(result, ")", `\)`)
	result = strings.ReplaceAll(result, "[", `\[`)
	result = strings.ReplaceAll(result, "]", `\]`)
	result = strings.ReplaceAll(result, "{", `\{`)
	result = strings.ReplaceAll(result, "}", `\}`)
	result = strings.ReplaceAll(result, "+", `\+`)
	result = strings.ReplaceAll(result, ".", `\.`)
	result = strings.ReplaceAll(result, "|", `\|`)
	result = strings.ReplaceAll(result, "^", `\^`)
	result = strings.ReplaceAll(result, "?", `\?`)
	result = strings.ReplaceAll(result, "*", `\*`)

	// Convert Semgrep metavariables ($VAR, $X, $FUNC, etc.) to regex capture groups
	metavarRe := regexp.MustCompile(`\$[A-Z][A-Z0-9_]*`)
	result = metavarRe.ReplaceAllString(result, `[^\s;]+`)

	// Convert Semgrep ellipsis (...) to regex wildcard
	result = strings.ReplaceAll(result, `\.\.\.`, `.*`)

	// Collapse excessive whitespace into \s+
	wsRe := regexp.MustCompile(`\s+`)
	result = wsRe.ReplaceAllString(result, `\s+`)

	// Make case-insensitive for PHP functions
	result = "(?i)" + result

	// Validate the result compiles
	if _, err := regexp.Compile(result); err != nil {
		return ""
	}

	return result
}

func containsLang(langs []string, target string) bool {
	for _, l := range langs {
		if strings.ToLower(l) == target {
			return true
		}
	}
	return false
}

func mapSemgrepSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return "critical"
	case "warning":
		return "high"
	case "info":
		return "medium"
	default:
		return "medium"
	}
}
