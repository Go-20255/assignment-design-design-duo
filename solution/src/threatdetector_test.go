package src

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestLoadConfig_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	// write a valid config
	configJSON := `{
		"rules": [
			{
				"name": "TestRule",
				"pattern": "bad",
				"severity": "medium",
				"weight": 5,
				"description": "Detects bad words"
			}
		]
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}

	if len(config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(config.Rules))
	}

	rule := config.Rules[0]
	if rule.Regex == nil {
		t.Errorf("expected compiled regex, got nil")
	}
	if rule.Weight != 5 {
		t.Errorf("expected weight 5, got %d", rule.Weight)
	}
	if rule.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", rule.Severity)
	}
}

func TestLoadConfig_InvalidRegex(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "bad.json")

	configJSON := `{
		"rules": [
			{
				"name": "BadRegex",
				"pattern": "[unclosed",
				"severity": "low",
				"weight": 1,
				"description": "invalid regex"
			}
		]
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	_, err := LoadConfig(configPath)
	if err == nil {
		t.Fatal("expected error for invalid regex, got nil")
	}
}

func TestScanSingleFile_NoThreats(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "clean.log")
	if err := os.WriteFile(filePath, []byte("all good content"), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	task := ScanTask{
		AbsolutePath: filePath,
		RelativePath: "clean.log",
	}

	// no rules
	result := ScanSingleFile(task, []ThreatRule{}, log.Default())
	if result.Report.Status != "clean" {
		t.Errorf("expected status 'clean', got %q", result.Report.Status)
	}
	if result.Report.ThreatCount != 0 {
		t.Errorf("expected 0 threats, got %d", result.Report.ThreatCount)
	}
}

func TestScanSingleFile_WithThreats(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "evil.log")
	content := "this is bad content"
	if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	task := ScanTask{
		AbsolutePath: filePath,
		RelativePath: "evil.log",
	}

	rules := []ThreatRule{
		{
			Name:        "BadWord",
			Pattern:     "bad",
			Severity:    "high",
			Weight:      3,
			Description: "detects bad",
			Regex:       regexp.MustCompile("bad"),
		},
	}

	result := ScanSingleFile(task, rules, log.Default())
	if result.Report.Status != "flagged" {
		t.Errorf("expected status 'flagged', got %q", result.Report.Status)
	}
	if result.Report.ThreatCount != 1 {
		t.Errorf("expected 1 threat, got %d", result.Report.ThreatCount)
	}
	if len(result.Report.Threats) != 1 {
		t.Errorf("expected 1 threat entry, got %d", len(result.Report.Threats))
	}
	if result.Report.Threats[0].MatchedText != "bad" {
		t.Errorf("expected matched text 'bad', got %q", result.Report.Threats[0].MatchedText)
	}
}
