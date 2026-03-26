package src

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type ThreatRule struct {
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	Severity    string  `json:"severity"`
	Weight      int     `json:"weight"`
	Description string  `json:"description"`
	Regex       *RegExp `json:"-"`
}

type RuleConfig struct {
	Rules []ThreatRule `json:"rules"`
}

type ThreatMatch struct {
	RuleName    string `json:"rule_name"`
	Severity    string `json:"severity"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
	MatchedText string `json:"matched_text"`
	Occurrences int    `json:"occurrences"`
}

type FileReport struct {
	Path        string        `json:"path"`
	Status      string        `json:"status"`
	ThreatScore int           `json:"threat_score"`
	RiskLevel   string        `json:"risk_level"`
	ThreatCount int           `json:"threat_count"`
	Threats     []ThreatMatch `json:"threats"`
	Error       string        `json:"error,omitempty"`
}

type LogEntry struct {
	Time    string `json:"time"`           //timestamp
	Level   string `json:"level"`          // "INFO" or "ERROR"
	Message string `json:"message"`        // human-readable description
	Path    string `json:"path,omitempty"` // file path if relevant
}

type Summary struct {
	ScannedAt              string         `json:"scanned_at"`
	FilesDiscovered        int            `json:"files_discovered"`
	FilesScanned           int            `json:"files_scanned"`
	FilesFlagged           int            `json:"files_flagged"`
	InaccessibleFiles      int            `json:"inaccessible_files"`
	TotalThreatMatches     int            `json:"total_threat_matches"`
	TotalThreatScore       int            `json:"total_threat_score"`
	AverageThreatScore     float64        `json:"average_threat_score"`
	HighestThreatScore     int            `json:"highest_threat_score"`
	HighestThreatScoreFile string         `json:"highest_threat_score_file,omitempty"`
	SeverityCounts         map[string]int `json:"severity_counts"`
	RuleMatchCounts        map[string]int `json:"rule_match_counts"`
}

type Report struct {
	InputDirectory  string       `json:"input_directory"`
	OutputDirectory string       `json:"output_directory"`
	ConfigPath      string       `json:"config_path"`
	WorkerCount     int          `json:"worker_count"`
	Summary         Summary      `json:"summary"`
	Files           []FileReport `json:"files"`
	Logs            []LogEntry   `json:"logs"`
}

type ScanTask struct {
	AbsolutePath string
	RelativePath string
}

type ScanResult struct {
	Report FileReport
	Logs   []LogEntry
}

func BuildReport(inputDir, outputDir, configPath string, workerCount int, walkLogs []LogEntry, results []ScanResult) Report {
	files := make([]FileReport, 0, len(results))
	logs := append([]LogEntry{}, walkLogs...)

	summary := Summary{
		ScannedAt:       time.Now().Format(time.RFC3339),
		FilesDiscovered: len(results),
		SeverityCounts:  make(map[string]int),
		RuleMatchCounts: make(map[string]int),
	}

	for _, result := range results {
		report := result.Report
		files = append(files, report)
		logs = append(logs, result.Logs...)

		if report.Status != "error" {
			summary.FilesScanned++
		} else {
			summary.InaccessibleFiles++
		}

		if report.ThreatScore > summary.HighestThreatScore {
			summary.HighestThreatScore = report.ThreatScore
			summary.HighestThreatScoreFile = report.Path
		}

		if report.Status == "flagged" {
			summary.FilesFlagged++
			summary.TotalThreatMatches += report.ThreatCount
			summary.TotalThreatScore += report.ThreatScore
		}

		for _, threat := range report.Threats {
			summary.SeverityCounts[threat.Severity] += threat.Occurrences
			summary.RuleMatchCounts[threat.RuleName] += threat.Occurrences
		}
	}

	if summary.FilesScanned > 0 {
		summary.AverageThreatScore = float64(summary.TotalThreatScore) / float64(summary.FilesScanned)
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	sort.Slice(logs, func(i, j int) bool {
		if logs[i].Time == logs[j].Time {
			return logs[i].Path < logs[j].Path
		}
		return logs[i].Time < logs[j].Time
	})

	return Report{
		InputDirectory:  inputDir,
		OutputDirectory: outputDir,
		ConfigPath:      configPath,
		WorkerCount:     workerCount,
		Summary:         summary,
		Files:           files,
		Logs:            logs,
	}
}

func WriteReport(outputDir string, report Report) (string, error) {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Format("2006-01-02-15-04-05")
	filename := fmt.Sprintf("report-%s.json", timestamp)
	reportPath := filepath.Join(outputDir, filename)

	return reportPath, os.WriteFile(reportPath, data, 0o644)
}
