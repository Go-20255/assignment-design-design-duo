package src

import (
	"log"
	// TODO: add imports you need
)

// ScanFiles distributes tasks across workerCount goroutines using channels
// and a sync.WaitGroup, collects all results, and returns them sorted by
// file path.
//
// Requirements:
//   - Exactly workerCount goroutines must run concurrently
//   - Use a channel to feed tasks to workers
//   - Use a channel to collect ScanResults from workers
//   - Use sync.WaitGroup to know when all workers are done
//   - Sort results by Report.Path before returning
func ScanFiles(tasks []ScanTask, rules []ThreatRule, workerCount int, logger *log.Logger) []ScanResult {
	// TODO
	return nil
}
