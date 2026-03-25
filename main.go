package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type ThreatRule struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
	regex       *regexp.Regexp
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
	Time    string `json:"time"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Path    string `json:"path,omitempty"`
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

type scanTask struct {
	absolutePath string
	relativePath string
}

type scanResult struct {
	report FileReport
	logs   []LogEntry
}

func main() {
	inputDir := flag.String("input", "./input", "input directory containing files to scan")
	outputDir := flag.String("output", "./output", "output directory for reports and logs")
	configPath := flag.String("config", "./config/threats.json", "path to threat detection config JSON")
	workerCount := flag.Int("workers", runtime.NumCPU(), "number of concurrent workers")
	flag.Parse()

	if *workerCount < 1 {
		fmt.Fprintln(os.Stderr, "workers must be at least 1")
		os.Exit(1)
	}

	logger, logFile, err := buildLogger(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logging: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	config, err := loadConfig(*configPath)
	if err != nil {
		logger.Printf("failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	tasks, walkLogs := discoverFiles(*inputDir, logger)
	results := scanFiles(tasks, config.Rules, *workerCount, logger)
	report := buildReport(*inputDir, *outputDir, *configPath, *workerCount, walkLogs, results)

	if err := writeReport(*outputDir, report); err != nil {
		logger.Printf("failed to write report: %v", err)
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scan complete. Report written to %s\n", filepath.Join(*outputDir, "report.json"))
}

func buildLogger(outputDir string) (*log.Logger, *os.File, error) {
	logDir := filepath.Join(outputDir, "logs")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, nil, err
	}

	logPath := filepath.Join(logDir, "scan.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		return nil, nil, err
	}

	logger := log.New(io.MultiWriter(os.Stdout, logFile), "scanner ", log.LstdFlags)
	return logger, logFile, nil
}

func loadConfig(configPath string) (RuleConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return RuleConfig{}, err
	}

	var config RuleConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return RuleConfig{}, err
	}

	if len(config.Rules) == 0 {
		return RuleConfig{}, errors.New("config does not contain any threat rules")
	}

	for i := range config.Rules {
		rule := &config.Rules[i]
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return RuleConfig{}, fmt.Errorf("invalid regex for rule %q: %w", rule.Name, err)
		}
		rule.regex = compiled
		rule.Severity = normalizeSeverity(rule.Severity)
		if rule.Weight < 1 {
			rule.Weight = 1
		}
	}

	return config, nil
}

func discoverFiles(inputDir string, logger *log.Logger) ([]scanTask, []LogEntry) {
	tasks := make([]scanTask, 0)
	logs := make([]LogEntry, 0)

	walkErr := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Printf("unable to access path %s: %v", path, err)
			logs = append(logs, newLogEntry("ERROR", fmt.Sprintf("Unable to access path: %v", err), path))
			return nil
		}

		if d.IsDir() {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil {
			logger.Printf("unable to inspect file %s: %v", path, statErr)
			logs = append(logs, newLogEntry("ERROR", fmt.Sprintf("Unable to inspect file: %v", statErr), path))
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		relativePath, relErr := filepath.Rel(inputDir, path)
		if relErr != nil {
			relativePath = path
		}

		tasks = append(tasks, scanTask{
			absolutePath: path,
			relativePath: relativePath,
		})
		return nil
	})

	if walkErr != nil {
		logger.Printf("directory traversal stopped early: %v", walkErr)
		logs = append(logs, newLogEntry("ERROR", fmt.Sprintf("Directory traversal stopped early: %v", walkErr), inputDir))
	}

	return tasks, logs
}

func scanFiles(tasks []scanTask, rules []ThreatRule, workerCount int, logger *log.Logger) []scanResult {
	taskCh := make(chan scanTask)
	resultCh := make(chan scanResult)

	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range taskCh {
				resultCh <- scanSingleFile(task, rules, logger)
			}
		}()
	}

	go func() {
		for _, task := range tasks {
			taskCh <- task
		}
		close(taskCh)
		workers.Wait()
		close(resultCh)
	}()

	results := make([]scanResult, 0, len(tasks))
	for result := range resultCh {
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].report.Path < results[j].report.Path
	})

	return results
}

func scanSingleFile(task scanTask, rules []ThreatRule, logger *log.Logger) scanResult {
	data, err := os.ReadFile(task.absolutePath)
	if err != nil {
		logger.Printf("unable to read file %s: %v", task.absolutePath, err)
		logEntry := newLogEntry("ERROR", fmt.Sprintf("Unable to read file: %v", err), task.relativePath)
		return scanResult{
			report: FileReport{
				Path:   task.relativePath,
				Status: "error",
				Error:  err.Error(),
			},
			logs: []LogEntry{logEntry},
		}
	}

	content := string(data)
	threats := make([]ThreatMatch, 0)
	score := 0
	totalMatches := 0

	for _, rule := range rules {
		matches := rule.regex.FindAllString(content, -1)
		if len(matches) == 0 {
			continue
		}

		score += len(matches) * rule.Weight
		totalMatches += len(matches)
		threats = append(threats, ThreatMatch{
			RuleName:    rule.Name,
			Severity:    rule.Severity,
			Weight:      rule.Weight,
			Description: rule.Description,
			MatchedText: truncatePreview(matches[0]),
			Occurrences: len(matches),
		})
	}

	status := "clean"
	if totalMatches > 0 {
		status = "flagged"
	}

	return scanResult{
		report: FileReport{
			Path:        task.relativePath,
			Status:      status,
			ThreatScore: score,
			RiskLevel:   riskLevel(score),
			ThreatCount: totalMatches,
			Threats:     threats,
		},
	}
}

func buildReport(inputDir, outputDir, configPath string, workerCount int, walkLogs []LogEntry, results []scanResult) Report {
	files := make([]FileReport, 0, len(results))
	logs := append([]LogEntry{}, walkLogs...)

	summary := Summary{
		ScannedAt:       time.Now().Format(time.RFC3339),
		FilesDiscovered: len(results),
		SeverityCounts:  make(map[string]int),
		RuleMatchCounts: make(map[string]int),
	}

	for _, result := range results {
		report := result.report
		files = append(files, report)
		logs = append(logs, result.logs...)

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

func writeReport(outputDir string, report Report) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	reportPath := filepath.Join(outputDir, "report.json")
	return os.WriteFile(reportPath, data, 0o644)
}

func newLogEntry(level, message, path string) LogEntry {
	return LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   level,
		Message: message,
		Path:    path,
	}
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

func riskLevel(score int) string {
	switch {
	case score >= 15:
		return "high"
	case score >= 7:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

func truncatePreview(text string) string {
	const limit = 60
	cleaned := strings.ReplaceAll(text, "\n", " ")
	if len(cleaned) <= limit {
		return cleaned
	}
	return cleaned[:limit] + "..."
}
