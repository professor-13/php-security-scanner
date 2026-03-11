package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// PHP file extensions to scan
var phpExtensions = map[string]bool{
	".php":     true,
	".phtml":   true,
	".php3":    true,
	".php4":    true,
	".php5":    true,
	".php7":    true,
	".inc":     true,
	".phps":    true,
	".module":  true,
	".install": true,
	".theme":   true,
}

const (
	maxLineLength = 4096
	maxBufferSize = 1024 * 1024 // 1MB
	largeFileSize = 10 * 1024 * 1024 // 10MB
)

// fileResult holds scan results for a single file
type fileResult struct {
	findings []Finding
	lines    int
	err      error
}

// Scan performs a security scan on the target path
func Scan(config ScanConfig) (*ScanResult, error) {
	startTime := time.Now()

	// Validate target path
	info, err := os.Stat(config.TargetPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access target path: %w", err)
	}

	// Set default context lines
	if config.ContextLines == 0 {
		config.ContextLines = 3
	}

	// Build rule set: builtin + YAML + framework
	allRules := GetAllRules()
	for i := range allRules {
		allRules[i].Source = "builtin"
	}

	// Load YAML rules
	var yamlCount int
	if config.RulesDir != "" {
		yamlRules, err := LoadRulesFromDir(config.RulesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not load YAML rules: %v\n", err)
		} else {
			allRules = append(allRules, yamlRules...)
			yamlCount = len(yamlRules)
		}
	}

	// Detect framework and add framework-specific rules
	var framework Framework
	if info.IsDir() {
		framework = DetectFramework(config.TargetPath)
		if framework.Name != "generic" {
			fwRules := GetFrameworkRules(framework)
			allRules = append(allRules, fwRules...)
			fmt.Fprintf(os.Stderr, "  Framework: %s detected (%d framework rules loaded)\n", framework.Name, len(fwRules))
		}
	}

	// Filter by severity and disabled rules
	disabledSet := make(map[string]bool)
	for _, id := range config.DisabledRules {
		disabledSet[strings.ToUpper(strings.TrimSpace(id))] = true
	}

	var rules []Rule
	for _, r := range allRules {
		if r.Severity >= config.MinSeverity && !disabledSet[strings.ToUpper(r.ID)] {
			rules = append(rules, r)
		}
	}

	result := &ScanResult{
		TargetPath:     config.TargetPath,
		ScanTimestamp:  startTime,
		RulesLoaded:    len(rules),
		YAMLRulesCount: yamlCount,
	}

	// Collect PHP files
	var phpFiles []string
	if info.IsDir() {
		err = filepath.Walk(config.TargetPath, func(path string, fInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fInfo.IsDir() {
				base := filepath.Base(path)
				if base == ".git" || base == ".svn" || base == "node_modules" || base == ".idea" || base == ".vscode" {
					return filepath.SkipDir
				}
				return nil
			}
			if !isPHPFile(path) {
				return nil
			}
			if shouldExclude(path, config.ExcludePatterns) {
				return nil
			}
			if fInfo.Size() > largeFileSize {
				fmt.Fprintf(os.Stderr, "Warning: Large file (%d MB): %s\n", fInfo.Size()/(1024*1024), path)
			}
			phpFiles = append(phpFiles, path)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("error walking directory: %w", err)
		}
	} else {
		if !isPHPFile(config.TargetPath) {
			return nil, fmt.Errorf("not a PHP file: %s", config.TargetPath)
		}
		phpFiles = append(phpFiles, config.TargetPath)
	}

	if len(phpFiles) == 0 {
		result.ScanDuration = time.Since(startTime)
		return result, nil
	}

	// Determine concurrency
	numWorkers := config.Concurrency
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	if numWorkers > len(phpFiles) {
		numWorkers = len(phpFiles)
	}

	// Concurrent scanning with worker pool
	jobs := make(chan string, len(phpFiles))
	results := make(chan fileResult, len(phpFiles))

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				findings, lineCount, scanErr := scanFileAdvanced(path, rules, config)
				results <- fileResult{
					findings: findings,
					lines:    lineCount,
					err:      scanErr,
				}
			}
		}()
	}

	// Send jobs
	for _, f := range phpFiles {
		jobs <- f
	}
	close(jobs)

	// Close results channel when all workers done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for r := range results {
		if r.err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Scan error: %v\n", r.err)
			continue
		}
		result.Findings = append(result.Findings, r.findings...)
		result.FilesScanned++
		result.TotalLines += r.lines
	}

	// Deduplicate findings (regex + taint on same line/category)
	result.Findings = deduplicateFindings(result.Findings)

	// Count suppressed
	for _, f := range result.Findings {
		if f.Suppressed {
			result.Suppressed++
		}
	}

	// Filter out suppressed unless ShowSuppressed
	if !config.ShowSuppressed {
		var active []Finding
		for _, f := range result.Findings {
			if !f.Suppressed {
				active = append(active, f)
			}
		}
		result.Findings = active
	}

	// Sort findings
	sort.Slice(result.Findings, func(i, j int) bool {
		fi, fj := result.Findings[i], result.Findings[j]
		if fi.Rule.Severity != fj.Rule.Severity {
			return fi.Rule.Severity > fj.Rule.Severity
		}
		if fi.Confidence != fj.Confidence {
			return fi.Confidence > fj.Confidence
		}
		if fi.FilePath != fj.FilePath {
			return fi.FilePath < fj.FilePath
		}
		return fi.LineNumber < fj.LineNumber
	})

	result.ScanDuration = time.Since(startTime)
	return result, nil
}

// scanFileAdvanced reads a PHP file with all analysis passes
// Returns all findings (regex + taint converted) and line count
func scanFileAdvanced(filePath string, rules []Rule, config ScanConfig) ([]Finding, int, error) {
	// Read all lines first (needed for context lines and taint analysis)
	allLines, err := readFileLines(filePath)
	if err != nil {
		return nil, 0, err
	}

	lineCount := len(allLines)
	slashPath := filepath.ToSlash(filePath)
	var findings []Finding
	inMultiLineComment := false

	// Pass 1: Regex-based scanning with sanitizer and suppression checks
	for lineIdx, line := range allLines {
		lineNumber := lineIdx + 1

		if len(line) > maxLineLength {
			line = line[:maxLineLength]
		}

		trimmedLine := strings.TrimSpace(line)

		// Track multi-line comment state
		if inMultiLineComment {
			if idx := strings.Index(trimmedLine, "*/"); idx != -1 {
				inMultiLineComment = false
				trimmedLine = trimmedLine[idx+2:]
				if len(strings.TrimSpace(trimmedLine)) == 0 {
					continue
				}
			} else {
				continue
			}
		}

		if idx := strings.Index(trimmedLine, "/*"); idx != -1 {
			if !strings.Contains(trimmedLine[idx:], "*/") {
				inMultiLineComment = true
				trimmedLine = trimmedLine[:idx]
				if len(strings.TrimSpace(trimmedLine)) == 0 {
					continue
				}
			}
		}

		if strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// Check for inline suppression
		suppressed, suppressComment := checkSuppression(line)

		for i := range rules {
			match := rules[i].Pattern.FindString(line)
			if match == "" {
				continue
			}

			// Post-match accuracy filter: skip if line has ->prepare( for SQL rules
			if rules[i].Category == "SQL Injection" && strings.Contains(line, "->prepare(") {
				continue
			}

			// Post-match: skip XSS-004 if echo line uses htmlspecialchars/htmlentities wrapping
			if rules[i].ID == "XSS-004" {
				lowerCheck := strings.ToLower(line)
				if strings.Contains(lowerCheck, "htmlspecialchars(") ||
					strings.Contains(lowerCheck, "htmlentities(") ||
					strings.Contains(lowerCheck, "strip_tags(") ||
					strings.Contains(lowerCheck, "esc_html(") ||
					strings.Contains(lowerCheck, "esc_attr(") ||
					strings.Contains(lowerCheck, "urlencode(") ||
					strings.Contains(lowerCheck, "json_encode(") {
					continue
				}
			}

			// Post-match: skip AUTH rules if variable name has safe suffix
			if strings.HasPrefix(rules[i].ID, "AUTH-001") || strings.HasPrefix(rules[i].ID, "AUTH-002") {
				varName := extractVariable(match)
				if isCredentialFalsePositiveVar(varName) {
					continue
				}
			}

			// Post-match: skip generic variable rules if variable name is clearly safe
			if isGenericVariableRule(rules[i].ID) {
				varName := extractVariable(match)
				if isLikelySafeVariable(varName) {
					continue
				}
			}

			displayLine := trimmedLine
			if len(displayLine) > 200 {
				displayLine = displayLine[:200] + "..."
			}
			matchDisplay := match
			if len(matchDisplay) > 100 {
				matchDisplay = matchDisplay[:100] + "..."
			}

			// Check sanitizer with wrapping awareness
			matchLoc := rules[i].Pattern.FindStringIndex(line)
			matchStart := 0
			if matchLoc != nil {
				matchStart = matchLoc[0]
			}
			sanitizerFunc := CheckSanitizerWraps(line, rules[i].Category, matchStart)
			// Also check context (prior lines) for sanitizer
			if sanitizerFunc == "" {
				varName := extractVariable(match)
				if varName != "" {
					sanitizerFunc = CheckSanitizerInContext(allLines, lineIdx, varName, rules[i].Category, 5)
				}
			}
			isSanitized := sanitizerFunc != ""

			// Determine confidence
			confidence := determineConfidence(line, &rules[i], isSanitized)

			// Build context lines
			contextBefore := getContextLines(allLines, lineIdx, config.ContextLines, true)
			contextAfter := getContextLines(allLines, lineIdx, config.ContextLines, false)

			// Check rule-specific suppression
			ruleSuppressed := suppressed
			if suppressed && suppressComment != "" {
				// Check if suppression is for specific rule
				if !strings.Contains(strings.ToLower(suppressComment), strings.ToLower(rules[i].ID)) &&
					strings.Contains(suppressComment, "-") {
					ruleSuppressed = false // Specific rule suppression doesn't match
				}
			}

			// Skip sanitized findings for high-FP rules
			if isSanitized && (rules[i].ID == "XSS-004" || rules[i].ID == "CMD-008" || rules[i].ID == "SQL-005") {
				continue
			}

			// For remaining findings: if sanitized anywhere in file, demote confidence
			if !isSanitized {
				varName := extractVariable(match)
				if varName != "" {
					fileSan := CheckSanitizerAnywhere(allLines, lineIdx, varName, rules[i].Category)
					if fileSan != "" {
						isSanitized = true
						sanitizerFunc = fileSan
					}
				}
			}

			findings = append(findings, Finding{
				Rule:          &rules[i],
				FilePath:      slashPath,
				LineNumber:    lineNumber,
				LineText:      displayLine,
				MatchText:     matchDisplay,
				Confidence:    confidence,
				Suppressed:    ruleSuppressed,
				SuppressedBy:  suppressComment,
				Sanitized:     isSanitized,
				SanitizerFunc: sanitizerFunc,
				ContextBefore: contextBefore,
				ContextAfter:  contextAfter,
			})
		}
	}

	// Pass 2: Taint analysis
	tracker := NewTaintTracker(slashPath, allLines)
	flows := tracker.Analyze()

	// Convert taint flows to findings (with flow path preserved)
	for _, flow := range flows {
		finding := taintFlowToFinding(flow, allLines, config.ContextLines)
		findings = append(findings, finding)
	}

	// Pass 3: Multi-line TOCTOU check
	toctouFindings := checkTOCTOU(allLines, slashPath, config)
	findings = append(findings, toctouFindings...)

	// Pass 4: Smart CSRF form check (multi-line)
	csrfFindings := checkCSRFForm(allLines, slashPath, config)
	findings = append(findings, csrfFindings...)

	// Pass 5: Insecure logout check (unset without session_destroy)
	logoutFindings := checkInsecureLogout(allLines, slashPath, config)
	findings = append(findings, logoutFindings...)

	// Pass 6: Missing security headers check (file-level)
	headerFindings := checkMissingSecurityHeaders(allLines, slashPath, config)
	findings = append(findings, headerFindings...)

	// Post-pass: Filter out CSRF-001 regex findings (replaced by smart check)
	var filtered []Finding
	for _, f := range findings {
		if f.Rule.ID == "CSRF-001" && !f.IsTaintFlow {
			continue // Skip regex CSRF-001, we use the smart multi-line check instead
		}
		filtered = append(filtered, f)
	}

	return filtered, lineCount, nil
}

// readFileLines reads all lines from a file
func readFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, maxBufferSize), maxBufferSize)

	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return lines, fmt.Errorf("error reading file: %w", err)
	}

	return lines, nil
}

// checkSuppression checks if a line has a nosec comment
func checkSuppression(line string) (bool, string) {
	lowerLine := strings.ToLower(line)

	// Check for // nosec or # nosec
	for _, prefix := range []string{"// nosec", "# nosec", "/* nosec", "//nosec", "#nosec"} {
		idx := strings.Index(lowerLine, prefix)
		if idx != -1 {
			comment := strings.TrimSpace(line[idx:])
			return true, comment
		}
	}

	// Check for @phpcs:ignore or @SuppressWarnings
	if strings.Contains(lowerLine, "@suppress") || strings.Contains(lowerLine, "phpcs:ignore") {
		return true, "phpcs:ignore"
	}

	return false, ""
}

// determineConfidence calculates finding confidence level
func determineConfidence(line string, rule *Rule, sanitized bool) Confidence {
	if sanitized {
		return ConfidenceLow
	}

	lowerLine := strings.ToLower(line)

	// High confidence: direct superglobal usage in dangerous function
	hasSuperglobal := strings.Contains(lowerLine, "$_get") ||
		strings.Contains(lowerLine, "$_post") ||
		strings.Contains(lowerLine, "$_request") ||
		strings.Contains(lowerLine, "$_cookie")

	if hasSuperglobal {
		return ConfidenceHigh
	}

	// Generic variable rules without superglobal → low confidence
	if isGenericVariableRule(rule.ID) {
		return ConfidenceLow
	}

	// Medium confidence: variable in dangerous function
	if rule.Severity >= SeverityHigh {
		return ConfidenceMedium
	}

	return ConfidenceLow
}

// isGenericVariableRule returns true for rules that match any variable (not just superglobals)
func isGenericVariableRule(ruleID string) bool {
	generic := map[string]bool{
		"XSS-004": true, "CMD-008": true, "SQL-005": true,
		"FI-002": true, "DESER-002": true, "DESER-003": true,
		"SSRF-004": true, "REDIR-002": true,
	}
	return generic[ruleID]
}

// getContextLines returns surrounding code lines
func getContextLines(allLines []string, currentIdx int, count int, before bool) []ContextLine {
	var contextLines []ContextLine

	if before {
		start := currentIdx - count
		if start < 0 {
			start = 0
		}
		for i := start; i < currentIdx; i++ {
			line := allLines[i]
			if len(line) > 200 {
				line = line[:200] + "..."
			}
			contextLines = append(contextLines, ContextLine{
				Number: i + 1,
				Text:   line,
			})
		}
	} else {
		end := currentIdx + count + 1
		if end > len(allLines) {
			end = len(allLines)
		}
		for i := currentIdx + 1; i < end; i++ {
			line := allLines[i]
			if len(line) > 200 {
				line = line[:200] + "..."
			}
			contextLines = append(contextLines, ContextLine{
				Number: i + 1,
				Text:   line,
			})
		}
	}

	return contextLines
}

// taintFlowToFinding converts a taint flow into a Finding with flow path preserved
func taintFlowToFinding(flow TaintFlow, allLines []string, contextLines int) Finding {
	lastStep := flow.Path[len(flow.Path)-1]

	// Convert TaintStep slice to FlowStep slice
	var flowSteps []FlowStep
	for _, step := range flow.Path {
		code := step.Code
		if len(code) > 120 {
			code = code[:120] + "..."
		}
		flowSteps = append(flowSteps, FlowStep{
			File:      step.File,
			Line:      step.Line,
			Code:      code,
			Operation: step.Operation,
			Variable:  step.Variable,
		})
	}

	// Build description with flow info
	desc := fmt.Sprintf("Taint flow: %s flows from %s (line %d) to %s() (line %d)",
		flow.Source.Variable,
		flow.Source.Key,
		flow.Source.Line,
		flow.Sink.Function,
		lastStep.Line,
	)

	rule := &Rule{
		ID:             "TAINT-" + strings.ReplaceAll(flow.Sink.Category, " ", ""),
		Category:       flow.Sink.Category,
		Severity:       flow.Sink.Severity,
		Description:    desc,
		Recommendation: fmt.Sprintf("Sanitize %s before passing to %s()", flow.Source.Variable, flow.Sink.Function),
		CWE:            flow.Sink.CWE,
		Source:         "taint-analysis",
	}

	// Build context around the sink line
	var contextBefore, contextAfter []ContextLine
	if lastStep.Line > 0 && lastStep.Line <= len(allLines) {
		lineIdx := lastStep.Line - 1
		contextBefore = getContextLines(allLines, lineIdx, contextLines, true)
		contextAfter = getContextLines(allLines, lineIdx, contextLines, false)
	}

	return Finding{
		Rule:          rule,
		FilePath:      lastStep.File,
		LineNumber:    lastStep.Line,
		LineText:      lastStep.Code,
		MatchText:     flow.Source.Variable + " -> " + flow.Sink.Function + "()",
		Confidence:    ConfidenceHigh,
		FlowSteps:     flowSteps,
		IsTaintFlow:   true,
		ContextBefore: contextBefore,
		ContextAfter:  contextAfter,
	}
}

// deduplicateFindings consolidates findings on the same file+line+category.
// Keeps the one with highest confidence, prefers taint over regex, then higher severity.
func deduplicateFindings(findings []Finding) []Finding {
	type dedupKey struct {
		file     string
		line     int
		category string
	}

	best := make(map[dedupKey]int) // key -> index in findings

	for i, f := range findings {
		key := dedupKey{
			file:     f.FilePath,
			line:     f.LineNumber,
			category: f.Rule.Category,
		}

		existingIdx, exists := best[key]
		if !exists {
			best[key] = i
			continue
		}

		existing := findings[existingIdx]

		// Prefer higher confidence
		if f.Confidence > existing.Confidence {
			// Propagate suppression from loser
			if existing.Suppressed {
				findings[i].Suppressed = true
				findings[i].SuppressedBy = existing.SuppressedBy
			}
			best[key] = i
			continue
		}
		if f.Confidence < existing.Confidence {
			if f.Suppressed {
				findings[existingIdx].Suppressed = true
				findings[existingIdx].SuppressedBy = f.SuppressedBy
			}
			continue
		}

		// Tied confidence: prefer taint findings (more precise)
		if f.IsTaintFlow && !existing.IsTaintFlow {
			if existing.Suppressed {
				findings[i].Suppressed = true
				findings[i].SuppressedBy = existing.SuppressedBy
			}
			best[key] = i
			continue
		}
		if !f.IsTaintFlow && existing.IsTaintFlow {
			if f.Suppressed {
				findings[existingIdx].Suppressed = true
				findings[existingIdx].SuppressedBy = f.SuppressedBy
			}
			continue
		}

		// Tied: prefer higher severity
		if f.Rule.Severity > existing.Rule.Severity {
			if existing.Suppressed {
				findings[i].Suppressed = true
				findings[i].SuppressedBy = existing.SuppressedBy
			}
			best[key] = i
			continue
		}

		// Propagate suppression from loser to winner
		if f.Suppressed {
			findings[existingIdx].Suppressed = true
			findings[existingIdx].SuppressedBy = f.SuppressedBy
		}
	}

	// Collect winners preserving order
	kept := make(map[int]bool, len(best))
	for _, idx := range best {
		kept[idx] = true
	}

	var result []Finding
	for i, f := range findings {
		if kept[i] {
			result = append(result, f)
		}
	}

	return result
}

// extractVariable pulls the first $variable_name from a string
var varExtractRe = regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*`)

func extractVariable(s string) string {
	return varExtractRe.FindString(s)
}

// isLikelySafeVariable returns true if the variable name suggests non-user-input
func isLikelySafeVariable(varName string) bool {
	if varName == "" {
		return false
	}
	lower := strings.ToLower(varName)
	safeParts := []string{
		"count", "total", "length", "size", "offset", "limit",
		"page", "config", "setting", "path", "dir", "directory",
		"version", "status", "type", "mode", "level", "flag",
		"index", "position", "width", "height", "color", "class",
		"title", "label", "prefix", "suffix",
	}
	for _, part := range safeParts {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}

// isCredentialFalsePositiveVar checks if a variable name is a false positive for credential rules
func isCredentialFalsePositiveVar(varName string) bool {
	if varName == "" {
		return false
	}
	lower := strings.ToLower(varName)
	falseSuffixes := []string{
		"_pattern", "_regex", "_field", "_column", "_hash",
		"_label", "_validator", "_placeholder", "_name",
		"_length", "_min", "_max", "_rules", "_format",
		"_policy", "_strength", "_error", "_message",
		"_confirm", "_old", "_new", "_reset", "_form",
	}
	for _, suffix := range falseSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// checkTOCTOU detects TOCTOU race conditions by looking for file_exists()
// followed by a file operation using the same variable within 3 lines
var fileExistsRe = regexp.MustCompile(`(?i)\bfile_exists\s*\(\s*(\$[a-zA-Z_][a-zA-Z0-9_]*)`)
var fileOpRe = regexp.MustCompile(`(?i)\b(fopen|file_get_contents|file_put_contents|unlink|readfile|copy|rename|mkdir|rmdir)\s*\(`)

func checkTOCTOU(allLines []string, filePath string, config ScanConfig) []Finding {
	var findings []Finding

	for lineIdx, line := range allLines {
		matches := fileExistsRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}
		checkedVar := matches[1]
		lineNumber := lineIdx + 1

		// Look ahead 3 lines for a file operation using the same variable
		lookAhead := 3
		endIdx := lineIdx + lookAhead + 1
		if endIdx > len(allLines) {
			endIdx = len(allLines)
		}

		for j := lineIdx + 1; j < endIdx; j++ {
			if fileOpRe.MatchString(allLines[j]) && strings.Contains(allLines[j], checkedVar) {
				rule := &Rule{
					ID:             "RACE-001",
					Category:       "Race Condition",
					Severity:       SeverityMedium,
					Description:    fmt.Sprintf("TOCTOU: file_exists() on line %d followed by file operation on line %d using %s", lineNumber, j+1, checkedVar),
					Recommendation: "Use atomic file operations or file locking to prevent TOCTOU race conditions",
					CWE:            "CWE-367",
					Source:         "builtin",
				}

				contextBefore := getContextLines(allLines, lineIdx, config.ContextLines, true)
				contextAfter := getContextLines(allLines, lineIdx, config.ContextLines, false)

				findings = append(findings, Finding{
					Rule:          rule,
					FilePath:      filePath,
					LineNumber:    lineNumber,
					LineText:      strings.TrimSpace(line),
					MatchText:     fmt.Sprintf("file_exists(%s) -> file op line %d", checkedVar, j+1),
					Confidence:    ConfidenceMedium,
					ContextBefore: contextBefore,
					ContextAfter:  contextAfter,
				})
				break
			}
		}
	}

	return findings
}

// checkCSRFForm detects POST forms that lack CSRF token fields.
// Scans for <form method="post"> and checks the next 30 lines for a CSRF token input.
var formPostRe = regexp.MustCompile(`(?i)<form[^>]*method\s*=\s*['"]post['"]`)
var csrfTokenRe = regexp.MustCompile(`(?i)(csrf|_token|nonce|xsrf|authenticity_token|anti.?forgery|__RequestVerificationToken|csrfmiddlewaretoken)`)
var formEndRe = regexp.MustCompile(`(?i)</form>`)
var dbWriteRe = regexp.MustCompile(`(?i)(INSERT|UPDATE|DELETE|mysqli_query|->query|->exec|->execute|->save|->update|->delete|->create|->destroy|->store)`)

func checkCSRFForm(allLines []string, filePath string, config ScanConfig) []Finding {
	var findings []Finding

	for lineIdx, line := range allLines {
		if !formPostRe.MatchString(line) {
			continue
		}
		lineNumber := lineIdx + 1

		// Look ahead up to 30 lines for CSRF token or form close
		lookAhead := 30
		endIdx := lineIdx + lookAhead + 1
		if endIdx > len(allLines) {
			endIdx = len(allLines)
		}

		hasCSRFToken := false
		hasDBWrite := false
		for j := lineIdx + 1; j < endIdx; j++ {
			if csrfTokenRe.MatchString(allLines[j]) {
				hasCSRFToken = true
				break
			}
			if dbWriteRe.MatchString(allLines[j]) {
				hasDBWrite = true
			}
			if formEndRe.MatchString(allLines[j]) {
				break
			}
		}

		// Only report if: no CSRF token found AND there's a DB write in the form handler
		if !hasCSRFToken && hasDBWrite {
			rule := &Rule{
				ID:             "CSRF-002",
				Category:       "CSRF",
				Severity:       SeverityHigh,
				Description:    "POST form without CSRF token submits to state-changing operation",
				Recommendation: "Add a CSRF token hidden field and validate it server-side before DB operations",
				CWE:            "CWE-352",
				Source:         "builtin",
			}
			contextBefore := getContextLines(allLines, lineIdx, config.ContextLines, true)
			contextAfter := getContextLines(allLines, lineIdx, config.ContextLines, false)

			findings = append(findings, Finding{
				Rule:          rule,
				FilePath:      filePath,
				LineNumber:    lineNumber,
				LineText:      strings.TrimSpace(line),
				MatchText:     "POST form -> no csrf_token -> DB write",
				Confidence:    ConfidenceHigh,
				ContextBefore: contextBefore,
				ContextAfter:  contextAfter,
			})
		} else if !hasCSRFToken {
			// No DB write but still no token — low severity informational
			rule := &Rule{
				ID:             "CSRF-003",
				Category:       "CSRF",
				Severity:       SeverityLow,
				Description:    "POST form without visible CSRF token (review if state-changing)",
				Recommendation: "Consider adding CSRF token if this form performs state-changing operations",
				CWE:            "CWE-352",
				Source:         "builtin",
			}
			contextBefore := getContextLines(allLines, lineIdx, config.ContextLines, true)
			contextAfter := getContextLines(allLines, lineIdx, config.ContextLines, false)

			findings = append(findings, Finding{
				Rule:          rule,
				FilePath:      filePath,
				LineNumber:    lineNumber,
				LineText:      strings.TrimSpace(line),
				MatchText:     "POST form without CSRF token",
				Confidence:    ConfidenceLow,
				ContextBefore: contextBefore,
				ContextAfter:  contextAfter,
			})
		}
		// If hasCSRFToken, no finding — form is properly protected
	}

	return findings
}

// checkInsecureLogout detects files where $_SESSION variables are individually unset
// without a call to session_destroy() — leaving the session partially active.
var sessionUnsetRe = regexp.MustCompile(`(?i)unset\s*\(\s*\$_SESSION\s*\[`)
var sessionDestroyRe = regexp.MustCompile(`(?i)session_destroy\s*\(`)

func checkInsecureLogout(allLines []string, filePath string, config ScanConfig) []Finding {
	var findings []Finding

	// First pass: check if file has session unset AND lacks session_destroy
	hasSessionUnset := false
	hasSessionDestroy := false
	var unsetLines []int

	for lineIdx, line := range allLines {
		if sessionUnsetRe.MatchString(line) {
			hasSessionUnset = true
			unsetLines = append(unsetLines, lineIdx)
		}
		if sessionDestroyRe.MatchString(line) {
			hasSessionDestroy = true
		}
	}

	// Only report if there are session unsets but no session_destroy anywhere in file
	if hasSessionUnset && !hasSessionDestroy {
		// Report on the first unset line
		if len(unsetLines) > 0 {
			lineIdx := unsetLines[0]
			lineNumber := lineIdx + 1

			rule := &Rule{
				ID:             "SESSION-003",
				Category:       "Insecure Session",
				Severity:       SeverityHigh,
				Description:    fmt.Sprintf("Logout uses unset($_SESSION[...]) without session_destroy() — session remains active (%d unset calls found)", len(unsetLines)),
				Recommendation: "Use session_unset() + session_destroy() + session_regenerate_id(true) for complete logout",
				CWE:            "CWE-613",
				Source:         "builtin",
			}

			contextBefore := getContextLines(allLines, lineIdx, config.ContextLines, true)
			contextAfter := getContextLines(allLines, lineIdx, config.ContextLines, false)

			findings = append(findings, Finding{
				Rule:          rule,
				FilePath:      filePath,
				LineNumber:    lineNumber,
				LineText:      strings.TrimSpace(allLines[lineIdx]),
				MatchText:     "unset($_SESSION[...]) without session_destroy()",
				Confidence:    ConfidenceMedium,
				ContextBefore: contextBefore,
				ContextAfter:  contextAfter,
			})
		}
	}

	return findings
}

// checkMissingSecurityHeaders detects PHP files that produce output (echo/print/HTML)
// but lack important security response headers.
var securityHeaderCSPRe = regexp.MustCompile(`(?i)header\s*\(\s*['"]Content-Security-Policy`)
var securityHeaderXFrameRe = regexp.MustCompile(`(?i)header\s*\(\s*['"]X-Frame-Options`)
var securityHeaderXContentTypeRe = regexp.MustCompile(`(?i)header\s*\(\s*['"]X-Content-Type-Options`)
var securityHeaderHSTSRe = regexp.MustCompile(`(?i)header\s*\(\s*['"]Strict-Transport-Security`)
var htmlOutputRe = regexp.MustCompile(`(?i)(echo\s|print\s|<html|<head|<body|<\!DOCTYPE|\?>.*<)`)

func checkMissingSecurityHeaders(allLines []string, filePath string, config ScanConfig) []Finding {
	var findings []Finding

	// Only check files that produce output (have echo/print/HTML content)
	hasOutput := false
	hasCSP := false
	hasXFrame := false
	hasXContentType := false
	hasHSTS := false

	for _, line := range allLines {
		if htmlOutputRe.MatchString(line) {
			hasOutput = true
		}
		if securityHeaderCSPRe.MatchString(line) {
			hasCSP = true
		}
		if securityHeaderXFrameRe.MatchString(line) {
			hasXFrame = true
		}
		if securityHeaderXContentTypeRe.MatchString(line) {
			hasXContentType = true
		}
		if securityHeaderHSTSRe.MatchString(line) {
			hasHSTS = true
		}
	}

	// Only report for files that produce output
	if !hasOutput {
		return findings
	}

	// Report missing headers — each gets a unique category to avoid dedup collapsing them
	if !hasXFrame {
		rule := &Rule{
			ID:             "HEADER-003",
			Category:       "Missing Header: X-Frame-Options",
			Severity:       SeverityMedium,
			Description:    "No X-Frame-Options header set (clickjacking risk)",
			Recommendation: "Add header('X-Frame-Options: DENY') or 'SAMEORIGIN' to prevent clickjacking",
			CWE:            "CWE-1021",
			Source:         "builtin",
		}
		findings = append(findings, Finding{
			Rule:       rule,
			FilePath:   filePath,
			LineNumber: 1,
			LineText:   "(file-level check)",
			MatchText:  "Missing X-Frame-Options header",
			Confidence: ConfidenceLow,
		})
	}

	if !hasXContentType {
		rule := &Rule{
			ID:             "HEADER-004",
			Category:       "Missing Header: X-Content-Type-Options",
			Severity:       SeverityMedium,
			Description:    "No X-Content-Type-Options header set (MIME sniffing risk)",
			Recommendation: "Add header('X-Content-Type-Options: nosniff') to prevent MIME-type sniffing",
			CWE:            "CWE-16",
			Source:         "builtin",
		}
		findings = append(findings, Finding{
			Rule:       rule,
			FilePath:   filePath,
			LineNumber: 1,
			LineText:   "(file-level check)",
			MatchText:  "Missing X-Content-Type-Options header",
			Confidence: ConfidenceLow,
		})
	}

	if !hasCSP {
		rule := &Rule{
			ID:             "HEADER-005",
			Category:       "Missing Header: Content-Security-Policy",
			Severity:       SeverityLow,
			Description:    "No Content-Security-Policy header set",
			Recommendation: "Add Content-Security-Policy header to mitigate XSS and data injection attacks",
			CWE:            "CWE-16",
			Source:         "builtin",
		}
		findings = append(findings, Finding{
			Rule:       rule,
			FilePath:   filePath,
			LineNumber: 1,
			LineText:   "(file-level check)",
			MatchText:  "Missing Content-Security-Policy header",
			Confidence: ConfidenceLow,
		})
	}

	if !hasHSTS {
		rule := &Rule{
			ID:             "HEADER-006",
			Category:       "Missing Header: Strict-Transport-Security",
			Severity:       SeverityLow,
			Description:    "No Strict-Transport-Security header set",
			Recommendation: "Add header('Strict-Transport-Security: max-age=31536000; includeSubDomains') for HTTPS enforcement",
			CWE:            "CWE-319",
			Source:         "builtin",
		}
		findings = append(findings, Finding{
			Rule:       rule,
			FilePath:   filePath,
			LineNumber: 1,
			LineText:   "(file-level check)",
			MatchText:  "Missing Strict-Transport-Security header",
			Confidence: ConfidenceLow,
		})
	}

	return findings
}

// isPHPFile checks if a file has a PHP extension
func isPHPFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return phpExtensions[ext]
}

// shouldExclude checks if a file path matches any exclude pattern
func shouldExclude(filePath string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(filePath)); matched {
			return true
		}
		if strings.Contains(filePath, strings.TrimPrefix(strings.TrimSuffix(pattern, "*"), "*")) {
			return true
		}
	}
	return false
}
