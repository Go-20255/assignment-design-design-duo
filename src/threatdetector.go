package src

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
)

func LoadConfig(configPath string) (RuleConfig, error) {

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
		rule.Regex = compiled

		rule.Severity = NormalizeSeverity(rule.Severity)

		if rule.Weight < 1 {
			rule.Weight = 1
		}
	}

	return config, nil
}

func ScanSingleFile(task ScanTask, rules []ThreatRule, logger *log.Logger) ScanResult {
	data, err := os.ReadFile(task.AbsolutePath)
	if err != nil {
		logger.Printf("unable to read file %s: %v", task.AbsolutePath, err)
		return ScanResult{
			Report: FileReport{
				Path:   task.RelativePath,
				Status: "error",
				Error:  err.Error(),
			},
			Logs: []LogEntry{
				NewLogEntry("ERROR",
					fmt.Sprintf("Unable to read file: %v", err),
					task.RelativePath),
			},
		}
	}

	content := string(data)
	threats := make([]ThreatMatch, 0)
	score := 0
	totalMatches := 0

	for _, rule := range rules {

		matches := rule.Regex.FindAllString(content, -1)
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
			MatchedText: TruncatePreview(matches[0]), // show first match as preview
			Occurrences: len(matches),
		})
	}

	status := "clean"
	if totalMatches > 0 {
		status = "flagged"
	}

	return ScanResult{
		Report: FileReport{
			Path:        task.RelativePath,
			Status:      status,
			ThreatScore: score,
			RiskLevel:   RiskLevel(score),
			ThreatCount: totalMatches,
			Threats:     threats,
		},
	}
}
