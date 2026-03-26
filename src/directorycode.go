package src

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
)

func DiscoverFiles(inputDir string, logger *log.Logger) ([]ScanTask, []LogEntry) {
	tasks := make([]ScanTask, 0)
	logs := make([]LogEntry, 0)

	walkErr := filepath.WalkDir(inputDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logger.Printf("unable to access path %s: %v", path, err)
			logs = append(logs, NewLogEntry("ERROR",
				fmt.Sprintf("Unable to access path: %v", err), path))
			return nil
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil {
			logger.Printf("unable to inspect file %s: %v", path, statErr)
			logs = append(logs, NewLogEntry("ERROR",
				fmt.Sprintf("Unable to inspect file: %v", statErr), path))
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		relativePath, relErr := filepath.Rel(inputDir, path)
		if relErr != nil {
			relativePath = path
		}

		tasks = append(tasks, ScanTask{
			AbsolutePath: path,
			RelativePath: relativePath,
		})
		return nil
	})

	if walkErr != nil {
		logger.Printf("directory traversal stopped early: %v", walkErr)
		logs = append(logs, NewLogEntry("ERROR",
			fmt.Sprintf("Directory traversal stopped early: %v", walkErr), inputDir))
	}

	return tasks, logs
}
