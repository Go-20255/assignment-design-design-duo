package src

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildReport_Basic(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.json")
	workerCount := 2

	// dummy scan results
	results := []ScanResult{
		{
			Report: FileReport{
				Path:        "file1.log",
				Status:      "flagged",
				ThreatScore: 5,
				RiskLevel:   "medium",
				ThreatCount: 1,
				Threats: []ThreatMatch{
					{
						RuleName:    "TestRule",
						Severity:    "medium",
						Weight:      5,
						Description: "test threat",
						MatchedText: "bad stuff",
						Occurrences: 1,
					},
				},
			},
			Logs: []LogEntry{
				{Time: time.Now().Format(time.RFC3339), Level: "INFO", Message: "scanned file1.log"},
			},
		},
		{
			Report: FileReport{
				Path:   "file2.log",
				Status: "clean",
			},
			Logs: []LogEntry{
				{Time: time.Now().Format(time.RFC3339), Level: "INFO", Message: "scanned file2.log"},
			},
		},
	}

	walkLogs := []LogEntry{
		{Time: time.Now().Format(time.RFC3339), Level: "INFO", Message: "started scan"},
	}

	report := BuildReport(inputDir, outputDir, configPath, workerCount, walkLogs, results)

	// sanity checks
	if report.InputDirectory != inputDir {
		t.Errorf("InputDirectory mismatch: got %q, want %q", report.InputDirectory, inputDir)
	}
	if report.OutputDirectory != outputDir {
		t.Errorf("OutputDirectory mismatch: got %q, want %q", report.OutputDirectory, outputDir)
	}
	if report.ConfigPath != configPath {
		t.Errorf("ConfigPath mismatch: got %q, want %q", report.ConfigPath, configPath)
	}
	if report.WorkerCount != workerCount {
		t.Errorf("WorkerCount mismatch: got %d, want %d", report.WorkerCount, workerCount)
	}

	if len(report.Files) != 2 {
		t.Errorf("expected 2 files in report, got %d", len(report.Files))
	}
	if report.Summary.FilesFlagged != 1 {
		t.Errorf("expected 1 flagged file, got %d", report.Summary.FilesFlagged)
	}
	if report.Summary.TotalThreatScore != 5 {
		t.Errorf("expected total threat score 5, got %d", report.Summary.TotalThreatScore)
	}

	// verify logs include walkLogs and result logs
	if len(report.Logs) != 3 {
		t.Errorf("expected 3 log entries, got %d", len(report.Logs))
	}
}

func TestWriteReport_Success(t *testing.T) {
	outputDir := t.TempDir()

	// build minimal report
	report := Report{
		InputDirectory:  "/input",
		OutputDirectory: outputDir,
		ConfigPath:      "/config.json",
		WorkerCount:     1,
		Summary: Summary{
			FilesDiscovered: 1,
			FilesScanned:    1,
			FilesFlagged:    0,
		},
		Files: []FileReport{
			{
				Path:   "test.log",
				Status: "clean",
			},
		},
	}

	reportPath, err := WriteReport(outputDir, report)
	if err != nil {
		t.Fatalf("WriteReport returned error: %v", err)
	}

	// file should exist
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatalf("report file not created: %v", err)
	}

	// file should contain valid JSON
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("failed to read report file: %v", err)
	}

	var loaded Report
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("report JSON is invalid: %v", err)
	}

	// verify a field
	if loaded.InputDirectory != report.InputDirectory {
		t.Errorf("loaded report InputDirectory mismatch: got %q, want %q", loaded.InputDirectory, report.InputDirectory)
	}
	if len(loaded.Files) != 1 || loaded.Files[0].Path != "test.log" {
		t.Errorf("loaded report Files mismatch")
	}
}
