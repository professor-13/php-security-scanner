package scanner

import (
	"regexp"
	"strings"
)

// TaintSource defines where untrusted data enters
type TaintSource struct {
	Variable string
	Key      string
	File     string
	Line     int
	Code     string
}

// TaintSink defines a dangerous function call
type TaintSink struct {
	Function string
	Category string
	Severity Severity
	CWE      string
}

// TaintFlow represents a complete source-to-sink path
type TaintFlow struct {
	Source TaintSource
	Sink   TaintSink
	Path   []TaintStep
}

// TaintStep is one hop in the data flow
type TaintStep struct {
	File      string
	Line      int
	Code      string
	Operation string // "source", "assignment", "concatenation", "function_arg", "sink"
	Variable  string
}

// TaintInfo tracks the taint status of a variable
type TaintInfo struct {
	IsTainted  bool
	Source     TaintSource
	Sanitized  bool
	Sanitizer  string
	PropPath   []TaintStep
}

// TaintTracker performs intraprocedural taint analysis within a single file
type TaintTracker struct {
	taintedVars map[string]*TaintInfo
	flows       []TaintFlow
	filePath    string
	lines       []string
}

// Source patterns: superglobals that carry user input
var sourcePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[`),
	regexp.MustCompile(`\$_FILES\s*\[`),
	regexp.MustCompile(`\bfile_get_contents\s*\(\s*['"]php://input['"]\s*\)`),
	regexp.MustCompile(`\bphp://input\b`),
}

// Assignment pattern: $var = expr
var assignmentPattern = regexp.MustCompile(`(\$[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)`)

// Variable reference pattern
var variablePattern = regexp.MustCompile(`\$[a-zA-Z_][a-zA-Z0-9_]*`)

// Sink definitions: dangerous functions and which argument is dangerous
var sinkDefs = []TaintSink{
	// SQL Injection sinks
	{Function: "mysql_query", Category: "SQL Injection", Severity: SeverityCritical, CWE: "CWE-89"},
	{Function: "mysqli_query", Category: "SQL Injection", Severity: SeverityCritical, CWE: "CWE-89"},
	{Function: "->query", Category: "SQL Injection", Severity: SeverityHigh, CWE: "CWE-89"},
	{Function: "pg_query", Category: "SQL Injection", Severity: SeverityCritical, CWE: "CWE-89"},

	// Command Injection sinks
	{Function: "exec", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "system", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "passthru", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "shell_exec", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "popen", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "proc_open", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-78"},
	{Function: "eval", Category: "Command Injection", Severity: SeverityCritical, CWE: "CWE-94"},

	// XSS sinks
	{Function: "echo", Category: "Cross-Site Scripting", Severity: SeverityHigh, CWE: "CWE-79"},
	{Function: "print", Category: "Cross-Site Scripting", Severity: SeverityHigh, CWE: "CWE-79"},

	// File Inclusion sinks
	{Function: "include", Category: "File Inclusion", Severity: SeverityCritical, CWE: "CWE-98"},
	{Function: "include_once", Category: "File Inclusion", Severity: SeverityCritical, CWE: "CWE-98"},
	{Function: "require", Category: "File Inclusion", Severity: SeverityCritical, CWE: "CWE-98"},
	{Function: "require_once", Category: "File Inclusion", Severity: SeverityCritical, CWE: "CWE-98"},

	// Path Traversal sinks
	{Function: "file_get_contents", Category: "Path Traversal", Severity: SeverityHigh, CWE: "CWE-22"},
	{Function: "file_put_contents", Category: "Path Traversal", Severity: SeverityHigh, CWE: "CWE-22"},
	{Function: "fopen", Category: "Path Traversal", Severity: SeverityHigh, CWE: "CWE-22"},
	{Function: "readfile", Category: "Path Traversal", Severity: SeverityHigh, CWE: "CWE-22"},
	{Function: "unlink", Category: "Path Traversal", Severity: SeverityHigh, CWE: "CWE-22"},

	// Deserialization sinks
	{Function: "unserialize", Category: "Insecure Deserialization", Severity: SeverityCritical, CWE: "CWE-502"},

	// SSRF sinks
	{Function: "curl_init", Category: "SSRF", Severity: SeverityHigh, CWE: "CWE-918"},
	{Function: "curl_setopt", Category: "SSRF", Severity: SeverityHigh, CWE: "CWE-918"},

	// Open Redirect sinks
	{Function: "header", Category: "Open Redirect", Severity: SeverityHigh, CWE: "CWE-601"},
}

// Sanitizer functions that neutralize taint
var taintSanitizers = map[string][]string{
	"SQL Injection":          {"intval", "floatval", "prepare", "bind_param", "bindParam", "bindValue", "mysqli_real_escape_string"},
	"Cross-Site Scripting":   {"htmlspecialchars", "htmlentities", "strip_tags", "urlencode", "filter_var", "filter_input"},
	"Command Injection":      {"escapeshellarg", "escapeshellcmd"},
	"Path Traversal":         {"basename", "realpath"},
	"File Inclusion":         {"basename", "in_array"},
	"Open Redirect":          {"filter_var", "parse_url"},
	"Insecure Deserialization": {"json_decode"},
	"SSRF":                   {"filter_var", "parse_url"},
}

// NewTaintTracker creates a new taint tracker for a file
func NewTaintTracker(filePath string, lines []string) *TaintTracker {
	return &TaintTracker{
		taintedVars: make(map[string]*TaintInfo),
		filePath:    filePath,
		lines:       lines,
	}
}

// Analyze performs intraprocedural taint analysis on all lines
func (t *TaintTracker) Analyze() []TaintFlow {
	for lineNum, line := range t.lines {
		lineNo := lineNum + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "/*") {
			continue
		}

		// Step 1: Check for new taint sources (direct assignment from superglobal)
		t.checkSourceAssignment(line, lineNo)

		// Step 2: Check for taint propagation (assignment from tainted var)
		t.checkPropagation(line, lineNo)

		// Step 3: Check for sanitization
		t.checkSanitization(line, lineNo)

		// Step 4: Check for sinks with tainted arguments
		t.checkSinks(line, lineNo)
	}

	return t.flows
}

// checkSourceAssignment checks if a line assigns a superglobal to a variable
func (t *TaintTracker) checkSourceAssignment(line string, lineNo int) {
	matches := assignmentPattern.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	varName := matches[1]
	expr := matches[2]

	for _, sp := range sourcePatterns {
		if sp.MatchString(expr) {
			srcMatch := sp.FindString(expr)
			source := TaintSource{
				Variable: varName,
				Key:      srcMatch,
				File:     t.filePath,
				Line:     lineNo,
				Code:     strings.TrimSpace(line),
			}
			t.taintedVars[varName] = &TaintInfo{
				IsTainted: true,
				Source:    source,
				PropPath: []TaintStep{
					{
						File:      t.filePath,
						Line:      lineNo,
						Code:      strings.TrimSpace(line),
						Operation: "source",
						Variable:  varName,
					},
				},
			}
			return
		}
	}
}

// checkPropagation checks if a tainted variable flows into another variable
func (t *TaintTracker) checkPropagation(line string, lineNo int) {
	matches := assignmentPattern.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	targetVar := matches[1]
	expr := matches[2]

	// Check if we already set this as a direct source
	if info, exists := t.taintedVars[targetVar]; exists && info.Source.Line == lineNo {
		return
	}

	// Check if expression references any tainted variable
	referencedVars := variablePattern.FindAllString(expr, -1)
	for _, ref := range referencedVars {
		if info, exists := t.taintedVars[ref]; exists && info.IsTainted && !info.Sanitized {
			// Propagate taint
			newPath := make([]TaintStep, len(info.PropPath))
			copy(newPath, info.PropPath)
			newPath = append(newPath, TaintStep{
				File:      t.filePath,
				Line:      lineNo,
				Code:      strings.TrimSpace(line),
				Operation: "assignment",
				Variable:  targetVar,
			})

			t.taintedVars[targetVar] = &TaintInfo{
				IsTainted: true,
				Source:    info.Source,
				PropPath:  newPath,
			}
			return
		}
	}
}

// checkSanitization checks if a line sanitizes a tainted variable
func (t *TaintTracker) checkSanitization(line string, lineNo int) {
	matches := assignmentPattern.FindStringSubmatch(line)
	if matches == nil {
		return
	}

	targetVar := matches[1]
	expr := matches[2]

	// Check if expression applies a sanitizer to a tainted variable
	for category, sanitizers := range taintSanitizers {
		_ = category
		for _, san := range sanitizers {
			if strings.Contains(strings.ToLower(expr), strings.ToLower(san)) {
				// Check if any tainted var is in the expression
				referencedVars := variablePattern.FindAllString(expr, -1)
				for _, ref := range referencedVars {
					if info, exists := t.taintedVars[ref]; exists && info.IsTainted {
						// Mark target as sanitized
						t.taintedVars[targetVar] = &TaintInfo{
							IsTainted: true,
							Source:    info.Source,
							Sanitized: true,
							Sanitizer: san,
							PropPath:  info.PropPath,
						}
						return
					}
				}
			}
		}
	}
}

// checkSinks checks if a line passes tainted data to a dangerous function
func (t *TaintTracker) checkSinks(line string, lineNo int) {
	lowerLine := strings.ToLower(line)

	for _, sink := range sinkDefs {
		sinkFunc := strings.ToLower(sink.Function)
		if !strings.Contains(lowerLine, sinkFunc) {
			continue
		}

		// Check if any tainted variable appears in this function call
		referencedVars := variablePattern.FindAllString(line, -1)
		for _, ref := range referencedVars {
			info, exists := t.taintedVars[ref]
			if !exists || !info.IsTainted || info.Sanitized {
				continue
			}

			// Check if there's a relevant sanitizer on this line
			sanitized := false
			if sans, ok := taintSanitizers[sink.Category]; ok {
				for _, san := range sans {
					if strings.Contains(lowerLine, strings.ToLower(san)) {
						sanitized = true
						break
					}
				}
			}
			if sanitized {
				continue
			}

			// Build complete flow
			path := make([]TaintStep, len(info.PropPath))
			copy(path, info.PropPath)
			path = append(path, TaintStep{
				File:      t.filePath,
				Line:      lineNo,
				Code:      strings.TrimSpace(line),
				Operation: "sink",
				Variable:  ref,
			})

			flow := TaintFlow{
				Source: info.Source,
				Sink:   sink,
				Path:   path,
			}
			t.flows = append(t.flows, flow)
		}
	}
}
