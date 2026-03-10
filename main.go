package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"php-security-scanner/reporter"
	"php-security-scanner/scanner"
)

const version = "2.0.0"

const banner = `
╔══════════════════════════════════════════════════╗
║   PHP Security Scanner v%s                    ║
║   OWASP Top 10 + Taint Analysis SAST Tool       ║
║   105+ Detection Rules | 25+ Categories         ║
╚══════════════════════════════════════════════════╝
`

func main() {
	// ─── Handle subcommands before flag.Parse ───────────────────────
	if len(os.Args) >= 2 && os.Args[1] == "import-semgrep" {
		handleImportSemgrep(os.Args[2:])
		return
	}

	// ─── Define CLI Flags ───────────────────────────────────────────
	// Output
	outputDir := flag.String("o", "./report", "Output directory for reports")
	noHTML := flag.Bool("no-html", false, "Skip HTML report generation")
	jsonOutput := flag.Bool("json", false, "Also output JSON report")
	sarifOutput := flag.Bool("sarif", false, "Also output SARIF report (for CI/CD)")

	// Analysis
	severity := flag.String("s", "low", "Minimum severity: critical, high, medium, low, info")
	exclude := flag.String("e", "", "Comma-separated glob patterns to exclude")
	rulesDir := flag.String("rules-dir", "", "Directory with custom JSON rule files")
	disableRule := flag.String("disable-rule", "", "Comma-separated rule IDs to disable")
	contextLines := flag.Int("context-lines", 3, "Number of context lines before/after findings")
	concurrency := flag.Int("concurrency", 0, "Number of parallel scan workers (0 = auto)")
	showSuppressed := flag.Bool("show-suppressed", false, "Include suppressed findings in output")

	// Baseline
	baseline := flag.String("baseline", "", "Path to baseline file for diff comparison")
	saveBaseline := flag.String("save-baseline", "", "Save current scan as baseline to this path")

	// Utility
	showVersion := flag.Bool("version", false, "Show version and exit")
	initConfig := flag.Bool("init-config", false, "Create a default .php-scanner.json config file")
	initRules := flag.Bool("init-rules", false, "Create an example custom-rules.json file")

	// Long flag aliases
	flag.StringVar(outputDir, "output", "./report", "Output directory for reports")
	flag.StringVar(severity, "severity", "low", "Minimum severity to report")
	flag.StringVar(exclude, "exclude", "", "Comma-separated glob patterns to exclude")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, banner, version)
		fmt.Fprintf(os.Stderr, "\nUsage: php-security-scanner [flags] <path>\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  <path>    Path to PHP file or directory to scan\n\n")
		fmt.Fprintf(os.Stderr, "Output Flags:\n")
		fmt.Fprintf(os.Stderr, "  -o, --output string        Output directory for reports (default \"./report\")\n")
		fmt.Fprintf(os.Stderr, "      --no-html              Skip HTML report generation\n")
		fmt.Fprintf(os.Stderr, "      --json                 Also output JSON report\n")
		fmt.Fprintf(os.Stderr, "      --sarif                Also output SARIF report (GitHub/CI/CD integration)\n")
		fmt.Fprintf(os.Stderr, "\nAnalysis Flags:\n")
		fmt.Fprintf(os.Stderr, "  -s, --severity string      Minimum severity: critical, high, medium, low, info (default \"low\")\n")
		fmt.Fprintf(os.Stderr, "  -e, --exclude string       Comma-separated glob patterns to exclude (e.g., vendor/*,test/*)\n")
		fmt.Fprintf(os.Stderr, "      --rules-dir string     Directory containing custom JSON rule files\n")
		fmt.Fprintf(os.Stderr, "      --disable-rule string  Comma-separated rule IDs to disable (e.g., AUTH-001,INFO-003)\n")
		fmt.Fprintf(os.Stderr, "      --context-lines int    Lines of context before/after findings (default 3)\n")
		fmt.Fprintf(os.Stderr, "      --concurrency int      Number of parallel workers, 0=auto (default 0)\n")
		fmt.Fprintf(os.Stderr, "      --show-suppressed      Include // nosec suppressed findings in output\n")
		fmt.Fprintf(os.Stderr, "\nBaseline Flags:\n")
		fmt.Fprintf(os.Stderr, "      --baseline string      Compare against baseline file (show only new findings)\n")
		fmt.Fprintf(os.Stderr, "      --save-baseline string Save current scan as baseline to this path\n")
		fmt.Fprintf(os.Stderr, "\nUtility Flags:\n")
		fmt.Fprintf(os.Stderr, "      --init-config          Create a default .php-scanner.json config in current directory\n")
		fmt.Fprintf(os.Stderr, "      --init-rules           Create an example custom-rules.json file\n")
		fmt.Fprintf(os.Stderr, "      --version              Show version and exit\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner ./src\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner -s critical -o ./results ./project\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner -e \"vendor/*,test/*\" --json --sarif ./app\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner --rules-dir ./rules --disable-rule AUTH-001 ./src\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner --save-baseline baseline.json ./src\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner --baseline baseline.json ./src   # show only new findings\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner --no-html -s high ./single-file.php\n")
		fmt.Fprintf(os.Stderr, "\nConfig File:\n")
		fmt.Fprintf(os.Stderr, "  Place a .php-scanner.json in your project root. CLI flags override config values.\n")
		fmt.Fprintf(os.Stderr, "  Run --init-config to generate a starter config.\n")
		fmt.Fprintf(os.Stderr, "\nExit Codes:\n")
		fmt.Fprintf(os.Stderr, "  0  No critical or high severity findings\n")
		fmt.Fprintf(os.Stderr, "  1  Critical or high severity findings detected\n")
		fmt.Fprintf(os.Stderr, "  2  Scanner error\n")
	}

	flag.Parse()

	// ─── Handle utility commands first ──────────────────────────────
	if *showVersion {
		fmt.Printf("PHP Security Scanner v%s\n", version)
		os.Exit(0)
	}

	if *initConfig {
		configPath := filepath.Join(".", ".php-scanner.json")
		if err := scanner.GenerateDefaultConfig(configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating config: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Created default config: %s\n", configPath)
		os.Exit(0)
	}

	if *initRules {
		rulesPath := filepath.Join(".", "custom-rules.json")
		if err := scanner.GenerateExampleRuleFile(rulesPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating rules file: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Created example rules file: %s\n", rulesPath)
		os.Exit(0)
	}

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	targetPath := flag.Arg(0)

	// Validate target path exists
	if _, err := os.Stat(targetPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot access path '%s': %v\n", targetPath, err)
		os.Exit(2)
	}

	// ─── Track which flags were explicitly set ──────────────────────
	// Map short flag names to their canonical names for config merge
	shortToCanonical := map[string]string{
		"s": "severity",
		"o": "output",
		"e": "exclude",
	}
	cliFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		cliFlags[f.Name] = true
		// Also mark the canonical name if this is a short alias
		if canonical, ok := shortToCanonical[f.Name]; ok {
			cliFlags[canonical] = true
		}
	})

	// ─── Parse CLI values ───────────────────────────────────────────
	// Parse exclude patterns
	var excludePatterns []string
	if *exclude != "" {
		for _, p := range strings.Split(*exclude, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				excludePatterns = append(excludePatterns, p)
			}
		}
	}

	// Parse disabled rules
	var disabledRules []string
	if *disableRule != "" {
		for _, id := range strings.Split(*disableRule, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				disabledRules = append(disabledRules, id)
			}
		}
	}

	// Parse severity
	minSeverity := scanner.ParseSeverity(*severity)

	// ─── Build ScanConfig from CLI flags ────────────────────────────
	config := scanner.ScanConfig{
		TargetPath:      targetPath,
		OutputDir:       *outputDir,
		MinSeverity:     minSeverity,
		ExcludePatterns: excludePatterns,
		NoHTML:          *noHTML,
		JSONOutput:      *jsonOutput,
		SARIFOutput:     *sarifOutput,
		RulesDir:        *rulesDir,
		DisabledRules:   disabledRules,
		ShowSuppressed:  *showSuppressed,
		Concurrency:     *concurrency,
		ContextLines:    *contextLines,
		BaselinePath:    *baseline,
		SaveBaseline:    *saveBaseline,
	}

	// ─── Load project config file (.php-scanner.json) ───────────────
	configPath, configErr := scanner.FindProjectConfig(targetPath)
	if configErr == nil {
		projConfig, loadErr := scanner.LoadProjectConfig(configPath)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not parse config %s: %v\n", configPath, loadErr)
		} else {
			projConfig.MergeWithScanConfig(&config, cliFlags)
			fmt.Fprintf(os.Stderr, "  Config: %s\n", configPath)
		}
	}

	// ─── Print banner ───────────────────────────────────────────────
	fmt.Printf(banner, version)
	fmt.Printf("  Scanning: %s\n", targetPath)
	fmt.Printf("  Min Severity: %s\n", config.MinSeverity)
	if len(config.ExcludePatterns) > 0 {
		fmt.Printf("  Excluding: %s\n", strings.Join(config.ExcludePatterns, ", "))
	}
	if config.RulesDir != "" {
		fmt.Printf("  Custom Rules: %s\n", config.RulesDir)
	}
	if len(config.DisabledRules) > 0 {
		fmt.Printf("  Disabled: %s\n", strings.Join(config.DisabledRules, ", "))
	}
	if config.BaselinePath != "" {
		fmt.Printf("  Baseline: %s\n", config.BaselinePath)
	}
	fmt.Println()

	// ─── Run scan ───────────────────────────────────────────────────
	result, err := scanner.Scan(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	// ─── Baseline comparison ────────────────────────────────────────
	var newFindings []scanner.Finding
	var fixedCount int
	hasBaseline := false

	if config.BaselinePath != "" {
		bl, blErr := scanner.LoadBaseline(config.BaselinePath)
		if blErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load baseline: %v\n", blErr)
		} else {
			hasBaseline = true
			newFindings, fixedCount = scanner.DiffFindings(result, bl)

			fmt.Printf("  Baseline comparison:\n")
			fmt.Printf("    New findings:   %d\n", len(newFindings))
			fmt.Printf("    Fixed findings: %d\n", fixedCount)
			fmt.Println()

			// Replace result findings with only new findings for reporting
			result.Findings = newFindings
		}
	}

	// ─── Print terminal report ──────────────────────────────────────
	reporter.PrintResults(result)

	// ─── Generate reports ───────────────────────────────────────────
	fmt.Println()

	if !config.NoHTML {
		htmlPath, err := reporter.GenerateHTML(result, config.OutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not generate HTML report: %v\n", err)
		} else {
			fmt.Printf("  HTML Report:  %s\n", htmlPath)
		}
	}

	if config.JSONOutput {
		jsonPath, err := reporter.GenerateJSON(result, config.OutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not generate JSON report: %v\n", err)
		} else {
			fmt.Printf("  JSON Report:  %s\n", jsonPath)
		}
	}

	if config.SARIFOutput {
		sarifPath, err := reporter.GenerateSARIF(result, config.OutputDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not generate SARIF report: %v\n", err)
		} else {
			fmt.Printf("  SARIF Report: %s\n", sarifPath)
		}
	}

	// ─── Save baseline ──────────────────────────────────────────────
	if config.SaveBaseline != "" {
		if err := scanner.SaveBaseline(result, config.SaveBaseline); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not save baseline: %v\n", err)
		} else {
			fmt.Printf("  Baseline saved: %s\n", config.SaveBaseline)
		}
	}

	fmt.Println()

	// ─── Summary line ───────────────────────────────────────────────
	if hasBaseline && len(newFindings) == 0 {
		fmt.Println("  No new findings since baseline. ✓")
		fmt.Println()
	}

	// Exit with non-zero code if critical/high findings exist
	counts := result.CountBySeverity()
	if counts[scanner.SeverityCritical] > 0 || counts[scanner.SeverityHigh] > 0 {
		os.Exit(1)
	}
}

// handleImportSemgrep processes the import-semgrep subcommand
func handleImportSemgrep(args []string) {
	fs := flag.NewFlagSet("import-semgrep", flag.ExitOnError)
	outputFile := fs.String("o", "semgrep-rules.json", "Output JSON file for imported rules")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: php-security-scanner import-semgrep [flags] <path>\n\n")
		fmt.Fprintf(os.Stderr, "Import Semgrep YAML rules and convert to scanner JSON format.\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  <path>    Path to Semgrep YAML file or directory of YAML files\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner import-semgrep ./semgrep-rules/php/\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner import-semgrep -o my-rules.json rule.yaml\n")
		fmt.Fprintf(os.Stderr, "\nAfter import, use the rules with:\n")
		fmt.Fprintf(os.Stderr, "  php-security-scanner --rules-dir . ./src\n")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	if fs.NArg() == 0 {
		fs.Usage()
		os.Exit(2)
	}

	inputPath := fs.Arg(0)
	info, err := os.Stat(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Cannot access '%s': %v\n", inputPath, err)
		os.Exit(2)
	}

	var rules []scanner.ImportedRule

	if info.IsDir() {
		fmt.Printf("Importing Semgrep rules from directory: %s\n", inputPath)
		rules, err = scanner.ImportSemgrepDir(inputPath)
	} else {
		fmt.Printf("Importing Semgrep rules from: %s\n", inputPath)
		rules, err = scanner.ImportSemgrepRules(inputPath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	if len(rules) == 0 {
		fmt.Println("No PHP rules found to import.")
		os.Exit(0)
	}

	if err := scanner.SaveImportedRules(rules, *outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving rules: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Successfully imported %d PHP rules → %s\n", len(rules), *outputFile)
	fmt.Printf("Use with: php-security-scanner --rules-dir %s ./src\n", filepath.Dir(*outputFile))
}
