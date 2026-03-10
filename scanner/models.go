package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Severity represents the severity level of a finding
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// Color returns ANSI color code for terminal output
func (s Severity) Color() string {
	switch s {
	case SeverityCritical:
		return "\033[1;31m" // Bold Red
	case SeverityHigh:
		return "\033[31m" // Red
	case SeverityMedium:
		return "\033[33m" // Yellow
	case SeverityLow:
		return "\033[32m" // Green
	case SeverityInfo:
		return "\033[36m" // Cyan
	default:
		return "\033[0m"
	}
}

// HTMLColor returns CSS color for HTML report
func (s Severity) HTMLColor() string {
	switch s {
	case SeverityCritical:
		return "#ff1744"
	case SeverityHigh:
		return "#ff5252"
	case SeverityMedium:
		return "#ffc107"
	case SeverityLow:
		return "#4caf50"
	case SeverityInfo:
		return "#29b6f6"
	default:
		return "#9e9e9e"
	}
}

// HTMLBgColor returns CSS background color for HTML report badges
func (s Severity) HTMLBgColor() string {
	switch s {
	case SeverityCritical:
		return "#4a0000"
	case SeverityHigh:
		return "#3d0000"
	case SeverityMedium:
		return "#3d3000"
	case SeverityLow:
		return "#003d00"
	case SeverityInfo:
		return "#003050"
	default:
		return "#333333"
	}
}

// ParseSeverity converts a string to Severity
func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info":
		return SeverityInfo
	default:
		return SeverityLow
	}
}

// Confidence represents how certain a finding is
type Confidence int

const (
	ConfidenceLow    Confidence = iota // Heuristic match only
	ConfidenceMedium                   // Pattern + context match
	ConfidenceHigh                     // Source with user input confirmed
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "HIGH"
	case ConfidenceMedium:
		return "MEDIUM"
	case ConfidenceLow:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func (c Confidence) HTMLColor() string {
	switch c {
	case ConfidenceHigh:
		return "#4caf50"
	case ConfidenceMedium:
		return "#ffc107"
	case ConfidenceLow:
		return "#ff9800"
	default:
		return "#9e9e9e"
	}
}

// Rule defines a single security detection rule
type Rule struct {
	ID             string
	Category       string
	Severity       Severity
	Pattern        *regexp.Regexp
	Description    string
	Recommendation string
	CWE            string
	Tags           []string // For filtering (e.g., "laravel", "wordpress")
	Source         string   // "builtin" or "yaml:<filename>"
}

// ContextLine represents a single line of surrounding code context
type ContextLine struct {
	Number int
	Text   string
}

// FlowStep represents one step in a taint flow path (for reporters)
type FlowStep struct {
	File      string
	Line      int
	Code      string
	Operation string // "source", "assignment", "concatenation", "sink"
	Variable  string
}

// Finding represents a single security issue found in code
type Finding struct {
	Rule          *Rule
	FilePath      string
	LineNumber    int
	LineText      string
	MatchText     string
	Confidence    Confidence
	Suppressed    bool        // True if suppressed via // nosec
	SuppressedBy  string      // The suppression comment text
	Sanitized     bool        // True if sanitizer detected on same line
	SanitizerFunc string      // Name of sanitizer function detected
	ContextBefore []ContextLine // Lines before the finding
	ContextAfter  []ContextLine // Lines after the finding
	FlowSteps     []FlowStep  // Taint flow path steps (empty for regex-only findings)
	IsTaintFlow   bool        // True if originated from taint analysis
}

// ScanResult holds all results from a scan
type ScanResult struct {
	Findings       []Finding
	Suppressed     int // Count of suppressed findings
	FilesScanned   int
	TotalLines     int
	ScanDuration   time.Duration
	TargetPath     string
	ScanTimestamp  time.Time
	RulesLoaded    int // Total rules loaded (builtin + YAML)
	YAMLRulesCount int // Rules loaded from YAML files
}

// ScanConfig holds scanner configuration
type ScanConfig struct {
	TargetPath      string
	OutputDir       string
	MinSeverity     Severity
	ExcludePatterns []string
	NoHTML          bool
	JSONOutput      bool
	SARIFOutput     bool
	RulesDir        string   // Directory with YAML rule files
	DisabledRules   []string // Rule IDs to disable
	ShowSuppressed  bool     // Include suppressed findings in output
	Concurrency     int      // Number of parallel workers (0 = auto)
	ContextLines    int      // Number of context lines before/after (default 3)
	BaselinePath    string   // Path to baseline file for diff comparison
	SaveBaseline    string   // Path to save current scan as baseline
}

// CountBySeverity returns finding counts grouped by severity
func (r *ScanResult) CountBySeverity() map[Severity]int {
	counts := make(map[Severity]int)
	for _, f := range r.Findings {
		if !f.Suppressed {
			counts[f.Rule.Severity]++
		}
	}
	return counts
}

// CountByCategory returns finding counts grouped by category
func (r *ScanResult) CountByCategory() map[string]int {
	counts := make(map[string]int)
	for _, f := range r.Findings {
		if !f.Suppressed {
			counts[f.Rule.Category]++
		}
	}
	return counts
}

// CountByConfidence returns finding counts grouped by confidence
func (r *ScanResult) CountByConfidence() map[Confidence]int {
	counts := make(map[Confidence]int)
	for _, f := range r.Findings {
		if !f.Suppressed {
			counts[f.Confidence]++
		}
	}
	return counts
}

// ActiveFindings returns only non-suppressed findings
func (r *ScanResult) ActiveFindings() []Finding {
	var active []Finding
	for _, f := range r.Findings {
		if !f.Suppressed {
			active = append(active, f)
		}
	}
	return active
}

// Summary returns a formatted summary string
func (r *ScanResult) Summary() string {
	counts := r.CountBySeverity()
	total := 0
	for _, c := range counts {
		total += c
	}
	return fmt.Sprintf("%d total (%d Critical, %d High, %d Medium, %d Low, %d Info)",
		total,
		counts[SeverityCritical],
		counts[SeverityHigh],
		counts[SeverityMedium],
		counts[SeverityLow],
		counts[SeverityInfo],
	)
}
