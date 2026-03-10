package reporter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"php-security-scanner/scanner"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorBoldRed = "\033[1;31m"
	colorBold    = "\033[1m"
	colorGray    = "\033[90m"
	colorWhite   = "\033[97m"
	colorDim     = "\033[2m"
)

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return true
}

func colorize(color, text string) string {
	if !useColor() {
		return text
	}
	return color + text + colorReset
}

// PrintResults outputs scan results to the terminal with colors
func PrintResults(result *scanner.ScanResult) {
	separator := strings.Repeat("─", 70)

	fmt.Println()
	fmt.Println(colorize(colorBold, "═══════════════════════════════════════════════════════════════════════"))
	fmt.Println(colorize(colorBold, "  PHP SECURITY SCANNER v2.0 - SCAN RESULTS"))
	fmt.Println(colorize(colorBold, "═══════════════════════════════════════════════════════════════════════"))
	fmt.Println()

	fmt.Printf("  %s %s\n", colorize(colorBold, "Target:"), result.TargetPath)
	fmt.Printf("  %s %d files (%s lines) in %s\n",
		colorize(colorBold, "Scanned:"),
		result.FilesScanned,
		formatNumber(result.TotalLines),
		result.ScanDuration.Round(1000000).String(),
	)
	fmt.Printf("  %s %d total (%d builtin + %d YAML/framework)\n",
		colorize(colorBold, "Rules:"),
		result.RulesLoaded,
		result.RulesLoaded-result.YAMLRulesCount,
		result.YAMLRulesCount,
	)

	counts := result.CountBySeverity()
	activeCount := 0
	for _, c := range counts {
		activeCount += c
	}
	fmt.Printf("  %s %s\n",
		colorize(colorBold, "Findings:"),
		formatFindings(counts, activeCount),
	)

	if result.Suppressed > 0 {
		fmt.Printf("  %s %d findings suppressed via // nosec\n",
			colorize(colorBold, "Suppressed:"),
			result.Suppressed,
		)
	}

	// Confidence breakdown
	confCounts := result.CountByConfidence()
	if activeCount > 0 {
		fmt.Printf("  %s High: %d | Medium: %d | Low: %d\n",
			colorize(colorBold, "Confidence:"),
			confCounts[scanner.ConfidenceHigh],
			confCounts[scanner.ConfidenceMedium],
			confCounts[scanner.ConfidenceLow],
		)
	}

	fmt.Println()

	if activeCount == 0 {
		fmt.Println(colorize(colorGreen, "  ✓ No security issues found!"))
		fmt.Println()
		return
	}

	// Print each finding
	for _, f := range result.Findings {
		if f.Suppressed {
			continue
		}

		fmt.Println(colorize(colorGray, separator))
		sevColor := getSeverityColor(f.Rule.Severity)

		// Severity + Confidence
		confLabel := ""
		switch f.Confidence {
		case scanner.ConfidenceHigh:
			confLabel = colorize(colorGreen, " [✓ High Confidence]")
		case scanner.ConfidenceMedium:
			confLabel = colorize(colorYellow, " [~ Medium Confidence]")
		case scanner.ConfidenceLow:
			confLabel = colorize(colorDim, " [? Low Confidence]")
		}

		fmt.Printf("  %s %s: %s%s\n",
			colorize(sevColor, fmt.Sprintf("[%s]", f.Rule.Severity)),
			colorize(colorBold, f.Rule.ID),
			f.Rule.Description,
			confLabel,
		)
		fmt.Printf("  %s %s:%d\n",
			colorize(colorBold, "File:"),
			colorize(colorBlue, f.FilePath),
			f.LineNumber,
		)

		// Context before
		for _, cl := range f.ContextBefore {
			fmt.Printf("  %s %s\n",
				colorize(colorDim, fmt.Sprintf("  %4d │", cl.Number)),
				colorize(colorDim, cl.Text),
			)
		}
		// Highlighted line
		fmt.Printf("  %s %s\n",
			colorize(sevColor, fmt.Sprintf("► %4d │", f.LineNumber)),
			colorize(colorWhite, f.LineText),
		)
		// Context after
		for _, cl := range f.ContextAfter {
			fmt.Printf("  %s %s\n",
				colorize(colorDim, fmt.Sprintf("  %4d │", cl.Number)),
				colorize(colorDim, cl.Text),
			)
		}

		// Flow trace for taint findings
		if len(f.FlowSteps) > 0 {
			fmt.Printf("  %s\n", colorize(colorBold, "  Flow Trace:"))
			for i, step := range f.FlowSteps {
				arrow := "  "
				if i > 0 {
					arrow = colorize(colorDim, "  -> ")
				}
				opLabel := ""
				switch step.Operation {
				case "source":
					opLabel = colorize(colorRed, "[SOURCE]")
				case "assignment":
					opLabel = colorize(colorYellow, "[ASSIGN]")
				case "concatenation":
					opLabel = colorize(colorYellow, "[CONCAT]")
				case "sink":
					opLabel = colorize(colorBoldRed, "[ SINK ]")
				default:
					opLabel = colorize(colorDim, "["+step.Operation+"]")
				}
				code := step.Code
				if len(code) > 80 {
					code = code[:80] + "..."
				}
				fmt.Printf("  %s%s L%-4d %s  %s\n",
					arrow, opLabel, step.Line,
					colorize(colorWhite, code),
					colorize(colorCyan, "("+step.Variable+")"),
				)
			}
		}

		fmt.Printf("  %s %s", colorize(colorBold, "CWE: "), f.Rule.CWE)
		if f.Sanitized {
			fmt.Printf("  %s", colorize(colorMagenta, fmt.Sprintf("(sanitizer detected: %s)", f.SanitizerFunc)))
		}
		fmt.Println()

		if f.Rule.Source != "" && f.Rule.Source != "builtin" {
			fmt.Printf("  %s %s\n", colorize(colorBold, "Source:"), colorize(colorDim, f.Rule.Source))
		}

		fmt.Printf("  %s %s\n",
			colorize(colorBold, "Fix: "),
			colorize(colorGreen, f.Rule.Recommendation),
		)
	}
	fmt.Println(colorize(colorGray, separator))

	// Category breakdown
	fmt.Println()
	fmt.Println(colorize(colorBold, "  ═══ CATEGORY BREAKDOWN ═══"))
	fmt.Println()

	catCounts := result.CountByCategory()
	categories := make([]string, 0, len(catCounts))
	for cat := range catCounts {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	for _, cat := range categories {
		count := catCounts[cat]
		bar := strings.Repeat("█", min(count, 40))
		fmt.Printf("  %-30s %3d  %s\n", cat, count, colorize(colorYellow, bar))
	}

	fmt.Println()

	if counts[scanner.SeverityCritical] > 0 {
		fmt.Println(colorize(colorBoldRed, fmt.Sprintf("  ⚠ %d CRITICAL issues require immediate attention!", counts[scanner.SeverityCritical])))
	}
	if counts[scanner.SeverityHigh] > 0 {
		fmt.Println(colorize(colorRed, fmt.Sprintf("  ⚠ %d HIGH severity issues found.", counts[scanner.SeverityHigh])))
	}
	fmt.Println()
}

func getSeverityColor(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return colorBoldRed
	case scanner.SeverityHigh:
		return colorRed
	case scanner.SeverityMedium:
		return colorYellow
	case scanner.SeverityLow:
		return colorGreen
	case scanner.SeverityInfo:
		return colorCyan
	default:
		return colorWhite
	}
}

func formatFindings(counts map[scanner.Severity]int, total int) string {
	parts := []string{fmt.Sprintf("%d total", total)}
	if c := counts[scanner.SeverityCritical]; c > 0 {
		parts = append(parts, colorize(colorBoldRed, fmt.Sprintf("%d Critical", c)))
	}
	if c := counts[scanner.SeverityHigh]; c > 0 {
		parts = append(parts, colorize(colorRed, fmt.Sprintf("%d High", c)))
	}
	if c := counts[scanner.SeverityMedium]; c > 0 {
		parts = append(parts, colorize(colorYellow, fmt.Sprintf("%d Medium", c)))
	}
	if c := counts[scanner.SeverityLow]; c > 0 {
		parts = append(parts, colorize(colorGreen, fmt.Sprintf("%d Low", c)))
	}
	if c := counts[scanner.SeverityInfo]; c > 0 {
		parts = append(parts, colorize(colorCyan, fmt.Sprintf("%d Info", c)))
	}
	return strings.Join(parts, " | ")
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%d,%03d", n/1000, n%1000)
	}
	return fmt.Sprintf("%d,%03d,%03d", n/1000000, (n/1000)%1000, n%1000)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
