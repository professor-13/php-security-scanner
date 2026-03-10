package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// ScanCache stores file hashes and findings for incremental scanning
type ScanCache struct {
	Version    string                    `json:"version"`
	RulesHash  string                    `json:"rules_hash"`
	Timestamp  time.Time                 `json:"timestamp"`
	FileHashes map[string]string         `json:"file_hashes"`
	Findings   map[string][]CachedFinding `json:"findings"`
}

// CachedFinding is a serializable version of Finding
type CachedFinding struct {
	RuleID     string `json:"rule_id"`
	LineNumber int    `json:"line_number"`
	LineText   string `json:"line_text"`
	MatchText  string `json:"match_text"`
}

const cacheFileName = ".php-scanner-cache.json"

// NewScanCache creates a new empty cache
func NewScanCache() *ScanCache {
	return &ScanCache{
		Version:    "1.0.0",
		Timestamp:  time.Now(),
		FileHashes: make(map[string]string),
		Findings:   make(map[string][]CachedFinding),
	}
}

// LoadCache loads the scan cache from disk
func LoadCache(projectRoot string) (*ScanCache, error) {
	cachePath := filepath.Join(projectRoot, cacheFileName)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, err
	}

	var cache ScanCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

// Save writes the cache to disk
func (c *ScanCache) Save(projectRoot string) error {
	cachePath := filepath.Join(projectRoot, cacheFileName)
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cachePath, data, 0644)
}

// NeedsRescan checks if a file needs to be re-scanned
func (c *ScanCache) NeedsRescan(filePath string) bool {
	hash, err := HashFile(filePath)
	if err != nil {
		return true // rescan on error
	}
	cached, exists := c.FileHashes[filePath]
	return !exists || cached != hash
}

// UpdateFile updates the cache entry for a file
func (c *ScanCache) UpdateFile(filePath string, hash string, findings []CachedFinding) {
	c.FileHashes[filePath] = hash
	c.Findings[filePath] = findings
}

// RemoveFile removes a file's cache entry
func (c *ScanCache) RemoveFile(filePath string) {
	delete(c.FileHashes, filePath)
	delete(c.Findings, filePath)
}

// GetCachedFindings returns cached findings for a file
func (c *ScanCache) GetCachedFindings(filePath string) ([]CachedFinding, bool) {
	findings, exists := c.Findings[filePath]
	return findings, exists
}

// HashFile computes SHA-256 hash of a file
func HashFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashRules computes a hash of all rule IDs and patterns (for cache invalidation)
func HashRules(rules []Rule) string {
	h := sha256.New()
	for _, r := range rules {
		fmt.Fprintf(h, "%s:%s:%s\n", r.ID, r.Pattern.String(), r.Severity.String())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Baseline represents a previous scan result for diff comparison
type Baseline struct {
	ScanDate  time.Time         `json:"scan_date"`
	Findings  map[string][]string `json:"findings"` // file -> list of finding fingerprints
}

// LoadBaseline loads a baseline file for comparison
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}
	return &baseline, nil
}

// SaveBaseline saves current findings as a baseline
func SaveBaseline(result *ScanResult, outputPath string) error {
	baseline := Baseline{
		ScanDate: result.ScanTimestamp,
		Findings: make(map[string][]string),
	}

	for _, f := range result.Findings {
		fp := FingerprintFinding(f)
		baseline.Findings[f.FilePath] = append(baseline.Findings[f.FilePath], fp)
	}

	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// FingerprintFinding creates a unique fingerprint for a finding
func FingerprintFinding(f Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s:%s:%d:%s", f.Rule.ID, f.FilePath, f.LineNumber, f.MatchText)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// DiffFindings compares current findings against a baseline
// Returns new findings (not in baseline) and fixed findings (in baseline but not current)
func DiffFindings(current *ScanResult, baseline *Baseline) (newFindings []Finding, fixedCount int) {
	baseFingerprints := make(map[string]bool)
	for _, fps := range baseline.Findings {
		for _, fp := range fps {
			baseFingerprints[fp] = true
		}
	}

	for _, f := range current.Findings {
		fp := FingerprintFinding(f)
		if !baseFingerprints[fp] {
			newFindings = append(newFindings, f)
		}
		delete(baseFingerprints, fp)
	}

	fixedCount = len(baseFingerprints)
	return
}
