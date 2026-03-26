package src

import (
	"log"
	// TODO: add imports you need
)

// LoadConfig reads configPath, process the JSON into a RuleConfig,
// compiles every rule's Pattern into a Regex, and validates the result.
// Return an error if the file is missing, the JSON is invalid, there are
// zero rules, or any pattern is not a valid regular expression.
func LoadConfig(configPath string) (RuleConfig, error) {
	// TODO
	return RuleConfig{}, nil
}

// ScanSingleFile reads the file at task.AbsolutePath, applies every rule,
// and returns a ScanResult. If the file cannot be read, return a ScanResult
// with Status "error" — do not crash.
// Score = sum of (occurrences × rule.Weight) across all matching rules.
func ScanSingleFile(task ScanTask, rules []ThreatRule, logger *log.Logger) ScanResult {
	// TODO
	return ScanResult{}
}
