package reporter

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"php-security-scanner/scanner"
)

type HTMLReportData struct {
	TargetPath      string
	ScanDate        string
	ScanDuration    string
	FilesScanned    int
	TotalLines      int
	TotalFindings   int
	SuppressedCount int
	RulesLoaded     int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	InfoCount       int
	HighConfidence  int
	MedConfidence   int
	LowConfidence   int
	Categories      []CategoryCount
	Findings        []HTMLFinding
}

type CategoryCount struct {
	Name  string
	Count int
}

type HTMLFlowStep struct {
	Line      int
	Code      string
	Operation string
	Variable  string
}

type HTMLFinding struct {
	Severity       string
	SeverityColor  string
	SeverityBg     string
	RuleID         string
	Category       string
	FilePath       string
	LineNumber     int
	LineText       string
	Description    string
	Recommendation string
	CWE            string
	Confidence     string
	ConfidenceColor string
	Sanitized      bool
	SanitizerFunc  string
	Source         string
	ContextBefore  []HTMLContextLine
	ContextAfter   []HTMLContextLine
	FlowSteps      []HTMLFlowStep
	IsTaintFlow    bool
}

type HTMLContextLine struct {
	Number int
	Text   string
}

func GenerateHTML(result *scanner.ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create output directory: %w", err)
	}

	outputPath := filepath.Join(outputDir, "php-security-report.html")

	counts := result.CountBySeverity()
	catCounts := result.CountByCategory()
	confCounts := result.CountByConfidence()

	categories := make([]CategoryCount, 0, len(catCounts))
	for name, count := range catCounts {
		categories = append(categories, CategoryCount{Name: name, Count: count})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Count > categories[j].Count
	})

	findings := make([]HTMLFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.Suppressed {
			continue
		}

		var ctxBefore []HTMLContextLine
		for _, cl := range f.ContextBefore {
			ctxBefore = append(ctxBefore, HTMLContextLine{Number: cl.Number, Text: cl.Text})
		}
		var ctxAfter []HTMLContextLine
		for _, cl := range f.ContextAfter {
			ctxAfter = append(ctxAfter, HTMLContextLine{Number: cl.Number, Text: cl.Text})
		}

		source := f.Rule.Source
		if source == "builtin" {
			source = ""
		}

		var htmlFlowSteps []HTMLFlowStep
		if f.IsTaintFlow {
			for _, step := range f.FlowSteps {
				htmlFlowSteps = append(htmlFlowSteps, HTMLFlowStep{
					Line:      step.Line,
					Code:      step.Code,
					Operation: step.Operation,
					Variable:  step.Variable,
				})
			}
		}

		findings = append(findings, HTMLFinding{
			Severity:        f.Rule.Severity.String(),
			SeverityColor:   f.Rule.Severity.HTMLColor(),
			SeverityBg:      f.Rule.Severity.HTMLBgColor(),
			RuleID:          f.Rule.ID,
			Category:        f.Rule.Category,
			FilePath:        f.FilePath,
			LineNumber:      f.LineNumber,
			LineText:        f.LineText,
			Description:     f.Rule.Description,
			Recommendation:  f.Rule.Recommendation,
			CWE:             f.Rule.CWE,
			Confidence:      f.Confidence.String(),
			ConfidenceColor: f.Confidence.HTMLColor(),
			Sanitized:       f.Sanitized,
			SanitizerFunc:   f.SanitizerFunc,
			Source:          source,
			ContextBefore:   ctxBefore,
			ContextAfter:    ctxAfter,
			FlowSteps:       htmlFlowSteps,
			IsTaintFlow:     f.IsTaintFlow,
		})
	}

	activeCount := 0
	for _, c := range counts {
		activeCount += c
	}

	data := HTMLReportData{
		TargetPath:      result.TargetPath,
		ScanDate:        result.ScanTimestamp.Format(time.RFC1123),
		ScanDuration:    result.ScanDuration.Round(time.Millisecond).String(),
		FilesScanned:    result.FilesScanned,
		TotalLines:      result.TotalLines,
		TotalFindings:   activeCount,
		SuppressedCount: result.Suppressed,
		RulesLoaded:     result.RulesLoaded,
		CriticalCount:   counts[scanner.SeverityCritical],
		HighCount:       counts[scanner.SeverityHigh],
		MediumCount:     counts[scanner.SeverityMedium],
		LowCount:        counts[scanner.SeverityLow],
		InfoCount:       counts[scanner.SeverityInfo],
		HighConfidence:  confCounts[scanner.ConfidenceHigh],
		MedConfidence:   confCounts[scanner.ConfidenceMedium],
		LowConfidence:   confCounts[scanner.ConfidenceLow],
		Categories:      categories,
		Findings:        findings,
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("cannot create report file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return "", fmt.Errorf("template execute error: %w", err)
	}

	return outputPath, nil
}

// JSON report types
type JSONReport struct {
	Scanner    string        `json:"scanner"`
	Version    string        `json:"version"`
	ScanDate   string        `json:"scan_date"`
	Target     string        `json:"target"`
	Duration   string        `json:"duration"`
	Summary    JSONSummary   `json:"summary"`
	Findings   []JSONFinding `json:"findings"`
}

type JSONSummary struct {
	FilesScanned  int            `json:"files_scanned"`
	TotalLines    int            `json:"total_lines"`
	TotalFindings int            `json:"total_findings"`
	Suppressed    int            `json:"suppressed"`
	RulesLoaded   int            `json:"rules_loaded"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	ByConfidence  map[string]int `json:"by_confidence"`
}

type JSONFlowStep struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	Code      string `json:"code"`
	Operation string `json:"operation"`
	Variable  string `json:"variable"`
}

type JSONFinding struct {
	RuleID         string         `json:"rule_id"`
	Category       string         `json:"category"`
	Severity       string         `json:"severity"`
	Confidence     string         `json:"confidence"`
	File           string         `json:"file"`
	Line           int            `json:"line"`
	Code           string         `json:"code"`
	Match          string         `json:"match"`
	Description    string         `json:"description"`
	Recommendation string         `json:"recommendation"`
	CWE            string         `json:"cwe"`
	Sanitized      bool           `json:"sanitized,omitempty"`
	SanitizerFunc  string         `json:"sanitizer_func,omitempty"`
	Source         string         `json:"source,omitempty"`
	FlowSteps      []JSONFlowStep `json:"flow_steps,omitempty"`
	IsTaintFlow    bool           `json:"is_taint_flow,omitempty"`
}

func GenerateJSON(result *scanner.ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create output directory: %w", err)
	}

	outputPath := filepath.Join(outputDir, "php-security-report.json")
	counts := result.CountBySeverity()
	confCounts := result.CountByConfidence()

	sevMap := map[string]int{
		"critical": counts[scanner.SeverityCritical],
		"high":     counts[scanner.SeverityHigh],
		"medium":   counts[scanner.SeverityMedium],
		"low":      counts[scanner.SeverityLow],
		"info":     counts[scanner.SeverityInfo],
	}
	confMap := map[string]int{
		"high":   confCounts[scanner.ConfidenceHigh],
		"medium": confCounts[scanner.ConfidenceMedium],
		"low":    confCounts[scanner.ConfidenceLow],
	}

	findings := make([]JSONFinding, 0, len(result.Findings))
	for _, f := range result.Findings {
		if f.Suppressed {
			continue
		}
		var jsonFlowSteps []JSONFlowStep
		if f.IsTaintFlow {
			for _, step := range f.FlowSteps {
				jsonFlowSteps = append(jsonFlowSteps, JSONFlowStep{
					File:      step.File,
					Line:      step.Line,
					Code:      step.Code,
					Operation: step.Operation,
					Variable:  step.Variable,
				})
			}
		}
		findings = append(findings, JSONFinding{
			RuleID:         f.Rule.ID,
			Category:       f.Rule.Category,
			Severity:       f.Rule.Severity.String(),
			Confidence:     f.Confidence.String(),
			File:           f.FilePath,
			Line:           f.LineNumber,
			Code:           f.LineText,
			Match:          f.MatchText,
			Description:    f.Rule.Description,
			Recommendation: f.Rule.Recommendation,
			CWE:            f.Rule.CWE,
			Sanitized:      f.Sanitized,
			SanitizerFunc:  f.SanitizerFunc,
			Source:         f.Rule.Source,
			FlowSteps:      jsonFlowSteps,
			IsTaintFlow:    f.IsTaintFlow,
		})
	}

	activeCount := 0
	for _, c := range counts {
		activeCount += c
	}

	report := JSONReport{
		Scanner:  "PHP Security Scanner",
		Version:  "2.0.0",
		ScanDate: result.ScanTimestamp.Format(time.RFC3339),
		Target:   result.TargetPath,
		Duration: result.ScanDuration.Round(time.Millisecond).String(),
		Summary: JSONSummary{
			FilesScanned:  result.FilesScanned,
			TotalLines:    result.TotalLines,
			TotalFindings: activeCount,
			Suppressed:    result.Suppressed,
			RulesLoaded:   result.RulesLoaded,
			BySeverity:    sevMap,
			ByCategory:    result.CountByCategory(),
			ByConfidence:  confMap,
		},
		Findings: findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON marshal error: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return "", fmt.Errorf("cannot write JSON report: %w", err)
	}

	return outputPath, nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PHP Security Scan Report</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0a0a1a;color:#e0e0e0;line-height:1.6}
.container{max-width:1400px;margin:0 auto;padding:20px}
header{background:linear-gradient(135deg,#1a1a3e,#0f3460);padding:30px 40px;border-radius:12px;margin-bottom:24px;border:1px solid #1e3a5f}
header h1{font-size:28px;color:#fff;margin-bottom:4px}
header .subtitle{color:#8892b0;font-size:14px}
.meta{display:flex;gap:20px;margin-top:16px;flex-wrap:wrap}
.meta-item{font-size:13px;color:#a0aec0}
.meta-item strong{color:#e2e8f0}
.dashboard{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;margin-bottom:24px}
.card{background:#12122a;border-radius:10px;padding:20px;text-align:center;border:1px solid #1e2d4a;transition:transform .2s}
.card:hover{transform:translateY(-2px)}
.card .count{font-size:36px;font-weight:700;line-height:1.2}
.card .label{font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-top:4px;color:#8892b0}
.stats-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.stat-box{background:#12122a;border-radius:10px;padding:20px;border:1px solid #1e2d4a}
.stat-box h3{font-size:15px;margin-bottom:12px;color:#e2e8f0}
.stat-item{display:flex;justify-content:space-between;padding:4px 0;font-size:13px}
.categories{background:#12122a;border-radius:10px;padding:24px;margin-bottom:24px;border:1px solid #1e2d4a}
.categories h2{font-size:18px;margin-bottom:16px;color:#e2e8f0}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.cat-item{display:flex;justify-content:space-between;align-items:center;background:#0a0a1a;padding:10px 16px;border-radius:6px;border:1px solid #1e2d4a}
.cat-item .name{font-size:14px}
.cat-item .badge{background:#1e3a5f;color:#64b5f6;padding:2px 10px;border-radius:12px;font-size:13px;font-weight:600}
.filters{background:#12122a;border-radius:10px;padding:20px;margin-bottom:24px;border:1px solid #1e2d4a;display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.filters label{font-size:13px;color:#8892b0;cursor:pointer;display:flex;align-items:center;gap:4px}
.filters input[type="checkbox"]{accent-color:#4fc3f7}
.filters input[type="text"]{background:#0a0a1a;border:1px solid #1e2d4a;color:#e0e0e0;padding:8px 14px;border-radius:6px;font-size:13px;width:250px}
.filters select{background:#0a0a1a;border:1px solid #1e2d4a;color:#e0e0e0;padding:8px 14px;border-radius:6px;font-size:13px}
.findings{width:100%}
.finding{background:#12122a;border-radius:10px;padding:20px;margin-bottom:12px;border-left:4px solid;border-right:1px solid #1e2d4a;border-top:1px solid #1e2d4a;border-bottom:1px solid #1e2d4a;transition:background .2s}
.finding:hover{background:#181838}
.finding-header{display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap}
.sev-badge{padding:3px 12px;border-radius:4px;font-size:12px;font-weight:700;letter-spacing:.5px}
.conf-badge{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;border:1px solid}
.rule-id{font-weight:600;color:#4fc3f7;font-size:14px}
.category-tag{font-size:12px;color:#8892b0;background:#1a1a3e;padding:2px 8px;border-radius:4px}
.sanitizer-tag{font-size:11px;color:#ce93d8;background:#2a0a2a;padding:2px 8px;border-radius:4px;border:1px solid #4a1a4a}
.source-tag{font-size:11px;color:#90a4ae;background:#1a1a2a;padding:2px 6px;border-radius:4px}
.finding-desc{font-size:15px;color:#e2e8f0;margin-bottom:8px}
.finding-meta{font-size:13px;color:#8892b0;margin-bottom:8px}
.code-block{background:#0a0a1a;border-radius:6px;font-family:'Cascadia Code','Fira Code',monospace;font-size:13px;overflow-x:auto;margin-bottom:8px;border:1px solid #1e2d4a}
.code-line{display:flex;padding:1px 0}
.code-line.highlight{background:#1a1a3e}
.line-num{color:#4a5568;min-width:50px;text-align:right;padding:2px 12px 2px 8px;border-right:1px solid #1e2d4a;user-select:none}
.line-code{padding:2px 12px;color:#a0aec0;white-space:pre-wrap;word-break:break-all}
.code-line.highlight .line-code{color:#e2e8f0}
.finding-fix{font-size:13px;color:#81c784;background:#0a200a;padding:10px 14px;border-radius:6px;border:1px solid #1a3a1a}
.finding-fix strong{color:#a5d6a7}
.no-results{text-align:center;padding:60px;color:#8892b0;font-size:18px}
footer{text-align:center;padding:24px;color:#4a5568;font-size:12px;margin-top:20px}
@media(max-width:768px){.dashboard{grid-template-columns:repeat(2,1fr)}.stats-row{grid-template-columns:1fr}.filters{flex-direction:column;align-items:stretch}.filters input[type="text"]{width:100%}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>&#128737; PHP Security Scanner Report v2.0</h1>
<p class="subtitle">Static Analysis Security Testing (SAST) with Taint Tracking</p>
<div class="meta">
<div class="meta-item"><strong>Target:</strong> {{.TargetPath}}</div>
<div class="meta-item"><strong>Date:</strong> {{.ScanDate}}</div>
<div class="meta-item"><strong>Duration:</strong> {{.ScanDuration}}</div>
<div class="meta-item"><strong>Files:</strong> {{.FilesScanned}}</div>
<div class="meta-item"><strong>Lines:</strong> {{.TotalLines}}</div>
<div class="meta-item"><strong>Rules:</strong> {{.RulesLoaded}}</div>
{{if .SuppressedCount}}<div class="meta-item"><strong>Suppressed:</strong> {{.SuppressedCount}}</div>{{end}}
</div>
</header>

<div class="dashboard">
<div class="card" style="border-color:#ff1744"><div class="count" style="color:#ff1744">{{.CriticalCount}}</div><div class="label">Critical</div></div>
<div class="card" style="border-color:#ff5252"><div class="count" style="color:#ff5252">{{.HighCount}}</div><div class="label">High</div></div>
<div class="card" style="border-color:#ffc107"><div class="count" style="color:#ffc107">{{.MediumCount}}</div><div class="label">Medium</div></div>
<div class="card" style="border-color:#4caf50"><div class="count" style="color:#4caf50">{{.LowCount}}</div><div class="label">Low</div></div>
<div class="card" style="border-color:#29b6f6"><div class="count" style="color:#29b6f6">{{.InfoCount}}</div><div class="label">Info</div></div>
</div>

<div class="stats-row">
<div class="stat-box">
<h3>Confidence Distribution</h3>
<div class="stat-item"><span style="color:#4caf50">&#9679; High Confidence</span><span>{{.HighConfidence}}</span></div>
<div class="stat-item"><span style="color:#ffc107">&#9679; Medium Confidence</span><span>{{.MedConfidence}}</span></div>
<div class="stat-item"><span style="color:#ff9800">&#9679; Low Confidence</span><span>{{.LowConfidence}}</span></div>
</div>
<div class="stat-box">
<h3>Scan Summary</h3>
<div class="stat-item"><span>Total Findings</span><span>{{.TotalFindings}}</span></div>
<div class="stat-item"><span>Suppressed (nosec)</span><span>{{.SuppressedCount}}</span></div>
<div class="stat-item"><span>Rules Loaded</span><span>{{.RulesLoaded}}</span></div>
</div>
</div>

{{if .Categories}}
<div class="categories">
<h2>Category Breakdown</h2>
<div class="cat-grid">
{{range .Categories}}<div class="cat-item"><span class="name">{{.Name}}</span><span class="badge">{{.Count}}</span></div>{{end}}
</div>
</div>
{{end}}

<div class="filters">
<strong style="color:#e2e8f0;font-size:14px">Filter:</strong>
<label><input type="checkbox" class="sev-filter" value="CRITICAL" checked> Critical</label>
<label><input type="checkbox" class="sev-filter" value="HIGH" checked> High</label>
<label><input type="checkbox" class="sev-filter" value="MEDIUM" checked> Medium</label>
<label><input type="checkbox" class="sev-filter" value="LOW" checked> Low</label>
<label><input type="checkbox" class="sev-filter" value="INFO" checked> Info</label>
<select id="catFilter"><option value="">All Categories</option>{{range .Categories}}<option value="{{.Name}}">{{.Name}}</option>{{end}}</select>
<select id="confFilter"><option value="">All Confidence</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option></select>
<input type="text" id="searchBox" placeholder="Search file, rule ID, or CWE...">
</div>

<div class="findings" id="findingsList">
{{if eq .TotalFindings 0}}
<div class="no-results">&#10003; No security issues found. Your code looks clean!</div>
{{else}}
{{range .Findings}}
<div class="finding" data-severity="{{.Severity}}" data-category="{{.Category}}" data-confidence="{{.Confidence}}" style="border-left-color:{{.SeverityColor}}">
<div class="finding-header">
<span class="sev-badge" style="background:{{.SeverityBg}};color:{{.SeverityColor}}">{{.Severity}}</span>
<span class="conf-badge" style="color:{{.ConfidenceColor}};border-color:{{.ConfidenceColor}}">{{.Confidence}}</span>
<span class="rule-id">{{.RuleID}}</span>
<span class="category-tag">{{.Category}}</span>
{{if .Sanitized}}<span class="sanitizer-tag">Sanitizer: {{.SanitizerFunc}}</span>{{end}}
{{if .Source}}<span class="source-tag">{{.Source}}</span>{{end}}
</div>
<div class="finding-desc">{{.Description}}</div>
<div class="finding-meta">&#128196; <strong>{{.FilePath}}</strong>:{{.LineNumber}} &nbsp; | &nbsp; {{.CWE}}</div>
<div class="code-block">
{{range .ContextBefore}}<div class="code-line"><span class="line-num">{{.Number}}</span><span class="line-code">{{.Text}}</span></div>{{end}}
<div class="code-line highlight"><span class="line-num">{{.LineNumber}}</span><span class="line-code">{{.LineText}}</span></div>
{{range .ContextAfter}}<div class="code-line"><span class="line-num">{{.Number}}</span><span class="line-code">{{.Text}}</span></div>{{end}}
</div>
{{if .IsTaintFlow}}
<details style="margin:8px 0">
<summary style="cursor:pointer;color:#4fc3f7;font-size:13px;font-weight:600">&#9654; Taint Flow ({{len .FlowSteps}} steps)</summary>
<div style="background:#0a0a1a;border-radius:6px;padding:12px;margin-top:8px;border:1px solid #1e2d4a">
{{range $i, $step := .FlowSteps}}
<div style="display:flex;align-items:center;gap:8px;padding:4px 0;font-size:13px;font-family:'Cascadia Code','Fira Code',monospace">
<span style="color:#4a5568;min-width:20px">{{if gt $i 0}}&#8594;{{else}}&nbsp;{{end}}</span>
{{if eq .Operation "source"}}<span style="color:#ff5252;font-weight:600;min-width:70px">[SOURCE]</span>{{else if eq .Operation "sink"}}<span style="color:#ff1744;font-weight:700;min-width:70px">[ SINK ]</span>{{else}}<span style="color:#ffc107;min-width:70px">[ASSIGN]</span>{{end}}
<span style="color:#8892b0;min-width:40px">L{{.Line}}</span>
<span style="color:#e2e8f0">{{.Code}}</span>
<span style="color:#4fc3f7">({{.Variable}})</span>
</div>
{{end}}
</div>
</details>
{{end}}
<div class="finding-fix"><strong>Fix:</strong> {{.Recommendation}}</div>
</div>
{{end}}
{{end}}
</div>

<footer>Generated by PHP Security Scanner v2.0.0 | OWASP Top 10 + Taint Analysis + Framework Detection</footer>
</div>

<script>
(function(){
var checks=document.querySelectorAll('.sev-filter');
var catSel=document.getElementById('catFilter');
var confSel=document.getElementById('confFilter');
var search=document.getElementById('searchBox');
function af(){
var sevs={};
checks.forEach(function(c){sevs[c.value]=c.checked});
var cat=catSel.value;
var conf=confSel.value;
var q=search.value.toLowerCase();
var items=document.querySelectorAll('.finding');
var shown=0;
items.forEach(function(el){
var s=el.getAttribute('data-severity');
var c=el.getAttribute('data-category');
var cf=el.getAttribute('data-confidence');
var text=el.textContent.toLowerCase();
var show=sevs[s]&&(!cat||c===cat)&&(!conf||cf===conf)&&(!q||text.indexOf(q)!==-1);
el.style.display=show?'':'none';
if(show)shown++;
});
var dnr=document.querySelector('.dynamic-nr');
if(dnr)dnr.remove();
if(shown===0&&!document.querySelector('.no-results')){
var d=document.createElement('div');
d.className='no-results dynamic-nr';
d.textContent='No findings match the current filters.';
document.getElementById('findingsList').appendChild(d);
}
}
checks.forEach(function(c){c.addEventListener('change',af)});
catSel.addEventListener('change',af);
confSel.addEventListener('change',af);
search.addEventListener('input',af);
})();
</script>
</body>
</html>`
