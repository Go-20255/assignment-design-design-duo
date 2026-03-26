package src

import (
	"io"
	"log"
	"os"
	"path/filepath"
)

func BuildLogger(outputDir string) (*log.Logger, *os.File, error) {
	// Create the logs directory (and any missing parents).
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
