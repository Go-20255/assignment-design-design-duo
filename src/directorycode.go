package src

import (
	"log"
	// TODO: add imports you need
)

// DiscoverFiles walks inputDir recursively and returns one ScanTask per
// regular file found, plus a LogEntry for every path that could not be accessed.
func DiscoverFiles(inputDir string, logger *log.Logger) ([]ScanTask, []LogEntry) {
	// TODO: use filepath.WalkDir to walk the directory
	// - skip directories
	// - skip non-regular files (symlinks, pipes, etc.)
	// - for any access error: log a warning and continue (don't crash)
	// - build RelativePath using filepath.Rel(inputDir, path)
	return nil, nil
}
