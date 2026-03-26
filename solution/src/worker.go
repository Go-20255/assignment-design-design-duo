package src

import (
	"log"
	"sort"
	"sync"
)

func ScanFiles(tasks []ScanTask, rules []ThreatRule, workerCount int, logger *log.Logger) []ScanResult {

	taskCh := make(chan ScanTask)

	resultCh := make(chan ScanResult)

	var workers sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()

			for task := range taskCh {
				resultCh <- ScanSingleFile(task, rules, logger)
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

	results := make([]ScanResult, 0, len(tasks))
	for result := range resultCh {
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Report.Path < results[j].Report.Path
	})

	return results
}
