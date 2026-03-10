package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// ProjectConfig represents a .php-scanner.json configuration file
type ProjectConfig struct {
	// Scanner settings
	MinSeverity    string   `json:"min_severity,omitempty"`    // Minimum severity to report
	ExcludePatterns []string `json:"exclude_patterns,omitempty"` // Glob patterns to exclude
	DisabledRules  []string `json:"disabled_rules,omitempty"`  // Rule IDs to disable
	RulesDir       string   `json:"rules_dir,omitempty"`       // Directory with custom rule files

	// Output settings
	OutputDir      string `json:"output_dir,omitempty"`       // Output directory for reports
	NoHTML         bool   `json:"no_html,omitempty"`          // Skip HTML report
	JSONOutput     bool   `json:"json_output,omitempty"`      // Generate JSON report
	SARIFOutput    bool   `json:"sarif_output,omitempty"`     // Generate SARIF report

	// Analysis settings
	Concurrency    int  `json:"concurrency,omitempty"`       // Number of parallel workers (0 = auto)
	ContextLines   int  `json:"context_lines,omitempty"`     // Lines of context (default 3)
	ShowSuppressed bool `json:"show_suppressed,omitempty"`   // Include suppressed findings

	// Baseline
	BaselinePath   string `json:"baseline,omitempty"`         // Path to baseline file for diff
}

const configFileName = ".php-scanner.json"

// FindProjectConfig searches for a config file starting from the target path
// and walking up parent directories until found or root is reached
func FindProjectConfig(startPath string) (string, error) {
	info, err := os.Stat(startPath)
	if err != nil {
		return "", err
	}

	dir := startPath
	if !info.IsDir() {
		dir = filepath.Dir(startPath)
	}

	// Walk up directory tree
	for {
		configPath := filepath.Join(dir, configFileName)
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}

	return "", fmt.Errorf("no %s found", configFileName)
}

// LoadProjectConfig reads and parses a project config file
func LoadProjectConfig(path string) (*ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config file: %w", err)
	}

	var config ProjectConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}

	return &config, nil
}

// MergeWithScanConfig applies project config values to a ScanConfig,
// only overriding fields that are not already set by CLI flags
func (pc *ProjectConfig) MergeWithScanConfig(sc *ScanConfig, cliFlags map[string]bool) {
	// Only apply config values when the CLI flag was NOT explicitly set
	if !cliFlags["severity"] && pc.MinSeverity != "" {
		sc.MinSeverity = ParseSeverity(pc.MinSeverity)
	}
	if !cliFlags["exclude"] && len(pc.ExcludePatterns) > 0 {
		sc.ExcludePatterns = append(sc.ExcludePatterns, pc.ExcludePatterns...)
	}
	if !cliFlags["disable-rule"] && len(pc.DisabledRules) > 0 {
		sc.DisabledRules = append(sc.DisabledRules, pc.DisabledRules...)
	}
	if !cliFlags["rules-dir"] && pc.RulesDir != "" {
		sc.RulesDir = pc.RulesDir
	}
	if !cliFlags["output"] && pc.OutputDir != "" {
		sc.OutputDir = pc.OutputDir
	}
	if !cliFlags["no-html"] && pc.NoHTML {
		sc.NoHTML = true
	}
	if !cliFlags["json"] && pc.JSONOutput {
		sc.JSONOutput = true
	}
	if !cliFlags["sarif"] && pc.SARIFOutput {
		sc.SARIFOutput = true
	}
	if !cliFlags["concurrency"] && pc.Concurrency > 0 {
		sc.Concurrency = pc.Concurrency
	}
	if !cliFlags["context-lines"] && pc.ContextLines > 0 {
		sc.ContextLines = pc.ContextLines
	}
	if !cliFlags["show-suppressed"] && pc.ShowSuppressed {
		sc.ShowSuppressed = true
	}
	if !cliFlags["baseline"] && pc.BaselinePath != "" {
		// Resolve relative paths against config file directory
		sc.BaselinePath = pc.BaselinePath
	}
}

// GenerateDefaultConfig creates a default config file at the given path
func GenerateDefaultConfig(outputPath string) error {
	config := ProjectConfig{
		MinSeverity:     "low",
		ExcludePatterns: []string{"vendor/*", "node_modules/*", "test/*", "tests/*"},
		DisabledRules:   []string{},
		OutputDir:       "./report",
		ContextLines:    3,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0644)
}
