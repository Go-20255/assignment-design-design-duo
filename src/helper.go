package src

import (
	"strings"
	"time"
)

// NewLogEntry builds a LogEntry with the current timestamp.
// level   - "INFO" or "ERROR"
// message - human-readable description of the event
// path    - file path related to the event (can be empty string)
func NewLogEntry(level, message, path string) LogEntry {
	return LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Level:   level,
		Message: message,
		Path:    path,
	}
}

// NormalizeSeverity maps any casing of "high"/"medium" to a canonical
// lowercase string. Anything else (including empty) becomes "low".
func NormalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	default:
		return "low"
	}
}

// RiskLevel converts a numeric threat score into a human-readable label
func RiskLevel(score int) string {
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

// TruncatePreview shortens a matched string to 60 characters for display.
func TruncatePreview(text string) string {
	const limit = 60
	cleaned := strings.ReplaceAll(text, "\n", " ")
	if len(cleaned) <= limit {
		return cleaned
	}
	return cleaned[:limit] + "..."
}
