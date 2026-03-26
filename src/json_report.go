package src

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

// BuildReport assembles a Report from walk logs and scan results.
// It must compute all Summary fields and sort Files and Logs.
func BuildReport(inputDir, outputDir, configPath string, workerCount int, walkLogs []LogEntry, results []ScanResult) Report {
	//TODO
	return Report{}
}

// WriteReport creates outputDir if needed and writes report to
// outputDir/report.json as indented JSON.
func WriteReport(outputDir string, report Report) error {
	//TODO
	return nil
}
