package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"php-security-scanner/scanner"
)

// SARIF format structures (v2.1.0)
type SARIFReport struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool       SARIFTool       `json:"tool"`
	Results    []SARIFResult   `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	ShortDescription SARIFMessage       `json:"shortDescription"`
	FullDescription  SARIFMessage       `json:"fullDescription,omitempty"`
	Help             SARIFMessage       `json:"help,omitempty"`
	DefaultConfig    SARIFRuleConfig    `json:"defaultConfiguration"`
	Properties       SARIFRuleProperties `json:"properties,omitempty"`
}

type SARIFRuleConfig struct {
	Level string `json:"level"`
}

type SARIFRuleProperties struct {
	Tags []string `json:"tags,omitempty"`
}

type SARIFResult struct {
	RuleID    string            `json:"ruleId"`
	Level     string            `json:"level"`
	Message   SARIFMessage      `json:"message"`
	Locations []SARIFLocation   `json:"locations"`
	CodeFlows []SARIFCodeFlow   `json:"codeFlows,omitempty"`
	Properties SARIFResultProps  `json:"properties,omitempty"`
}

type SARIFResultProps struct {
	Confidence string `json:"confidence,omitempty"`
	CWE        string `json:"cwe,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
	ContextRegion    *SARIFRegion          `json:"contextRegion,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int           `json:"startLine"`
	EndLine     int           `json:"endLine,omitempty"`
	Snippet     *SARIFSnippet `json:"snippet,omitempty"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location SARIFLocation `json:"location"`
	Message  *SARIFMessage `json:"message,omitempty"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

// severityToSARIFLevel converts scanner severity to SARIF level
func severityToSARIFLevel(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical, scanner.SeverityHigh:
		return "error"
	case scanner.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// GenerateSARIF creates a SARIF v2.1.0 report file
func GenerateSARIF(result *scanner.ScanResult, outputDir string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("cannot create output directory: %w", err)
	}

	outputPath := filepath.Join(outputDir, "php-security-report.sarif")

	// Build unique rule definitions
	ruleMap := make(map[string]*SARIFRule)
	var ruleOrder []string

	for _, f := range result.Findings {
		if _, exists := ruleMap[f.Rule.ID]; !exists {
			rule := &SARIFRule{
				ID:   f.Rule.ID,
				Name: f.Rule.ID,
				ShortDescription: SARIFMessage{
					Text: f.Rule.Description,
				},
				FullDescription: SARIFMessage{
					Text: f.Rule.Recommendation,
				},
				Help: SARIFMessage{
					Text: fmt.Sprintf("%s\n\nCWE: %s\nRecommendation: %s",
						f.Rule.Description, f.Rule.CWE, f.Rule.Recommendation),
				},
				DefaultConfig: SARIFRuleConfig{
					Level: severityToSARIFLevel(f.Rule.Severity),
				},
				Properties: SARIFRuleProperties{
					Tags: []string{
						f.Rule.Category,
						f.Rule.CWE,
						"security",
						"php",
					},
				},
			}
			ruleMap[f.Rule.ID] = rule
			ruleOrder = append(ruleOrder, f.Rule.ID)
		}
	}

	rules := make([]SARIFRule, 0, len(ruleMap))
	for _, id := range ruleOrder {
		rules = append(rules, *ruleMap[id])
	}

	// Build results
	sarifResults := make([]SARIFResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		// Build context snippet
		var snippetLines []string
		for _, cl := range f.ContextBefore {
			snippetLines = append(snippetLines, cl.Text)
		}
		snippetLines = append(snippetLines, f.LineText)
		for _, cl := range f.ContextAfter {
			snippetLines = append(snippetLines, cl.Text)
		}
		snippetText := strings.Join(snippetLines, "\n")

		location := SARIFLocation{
			PhysicalLocation: SARIFPhysicalLocation{
				ArtifactLocation: SARIFArtifactLocation{
					URI: f.FilePath,
				},
				Region: SARIFRegion{
					StartLine: f.LineNumber,
					Snippet: &SARIFSnippet{
						Text: f.LineText,
					},
				},
			},
		}

		if len(snippetLines) > 1 {
			contextStart := f.LineNumber - len(f.ContextBefore)
			if contextStart < 1 {
				contextStart = 1
			}
			location.PhysicalLocation.ContextRegion = &SARIFRegion{
				StartLine: contextStart,
				EndLine:   f.LineNumber + len(f.ContextAfter),
				Snippet: &SARIFSnippet{
					Text: snippetText,
				},
			}
		}

		sarifResult := SARIFResult{
			RuleID: f.Rule.ID,
			Level:  severityToSARIFLevel(f.Rule.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s [%s] %s", f.Rule.Description, f.Rule.CWE, f.Rule.Recommendation),
			},
			Locations: []SARIFLocation{location},
			Properties: SARIFResultProps{
				Confidence: f.Confidence.String(),
				CWE:        f.Rule.CWE,
			},
		}

		// Populate CodeFlows from FlowSteps for taint findings
		if f.IsTaintFlow && len(f.FlowSteps) > 0 {
			var threadFlowLocs []SARIFThreadFlowLocation
			for _, step := range f.FlowSteps {
				tfl := SARIFThreadFlowLocation{
					Location: SARIFLocation{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: step.File,
							},
							Region: SARIFRegion{
								StartLine: step.Line,
								Snippet: &SARIFSnippet{
									Text: step.Code,
								},
							},
						},
					},
					Message: &SARIFMessage{
						Text: fmt.Sprintf("[%s] %s", strings.ToUpper(step.Operation), step.Variable),
					},
				}
				threadFlowLocs = append(threadFlowLocs, tfl)
			}
			sarifResult.CodeFlows = []SARIFCodeFlow{
				{
					ThreadFlows: []SARIFThreadFlow{
						{Locations: threadFlowLocs},
					},
				},
			}
		}

		sarifResults = append(sarifResults, sarifResult)
	}

	report := SARIFReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "PHP Security Scanner",
						Version:        "2.0.0",
						InformationURI: "https://github.com/php-security-scanner",
						Rules:          rules,
					},
				},
				Results: sarifResults,
				Invocations: []SARIFInvocation{
					{ExecutionSuccessful: true},
				},
			},
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("SARIF marshal error: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return "", fmt.Errorf("cannot write SARIF report: %w", err)
	}

	return outputPath, nil
}
