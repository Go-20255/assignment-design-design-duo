package src

import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestScanFiles_EmptyTaskList(t *testing.T) {
	results := ScanFiles([]ScanTask{}, []ThreatRule{}, 2, log.Default())
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestScanFiles_SingleFile_SingleWorker(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "file1.log")
	os.WriteFile(filePath, []byte("safe content"), 0o644)

	task := ScanTask{
		AbsolutePath: filePath,
		RelativePath: "file1.log",
	}

	results := ScanFiles([]ScanTask{task}, []ThreatRule{}, 1, log.Default())
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Report.Status != "clean" {
		t.Errorf("expected status 'clean', got %q", results[0].Report.Status)
	}
}

func TestScanFiles_MultipleFiles_SingleWorker(t *testing.T) {
	tmpDir := t.TempDir()
	files := []string{"a.log", "b.log", "c.log"}
	for _, f := range files {
		os.WriteFile(filepath.Join(tmpDir, f), []byte("nothing bad here"), 0o644)
	}

	tasks := []ScanTask{}
	for _, f := range files {
		tasks = append(tasks, ScanTask{
			AbsolutePath: filepath.Join(tmpDir, f),
			RelativePath: f,
		})
	}

	results := ScanFiles(tasks, []ThreatRule{}, 1, log.Default())
	if len(results) != len(files) {
		t.Errorf("expected %d results, got %d", len(files), len(results))
	}
	for _, r := range results {
		if r.Report.Status != "clean" {
			t.Errorf("expected status 'clean', got %q", r.Report.Status)
		}
	}
}

func TestScanFiles_WorkerCountDoesNotAffectResults(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "evil.log")
	os.WriteFile(filePath, []byte("bad content"), 0o644)

	task := ScanTask{
		AbsolutePath: filePath,
		RelativePath: "evil.log",
	}

	rules := []ThreatRule{
		{
			Name:        "BadWord",
			Pattern:     "bad",
			Severity:    "high",
			Weight:      3,
			Description: "detects bad",
			Regex:       regexp.MustCompile("bad"),
		},
	}

	// Run with 1 worker
	results1 := ScanFiles([]ScanTask{task}, rules, 1, log.Default())
	// Run with 5 workers
	results5 := ScanFiles([]ScanTask{task}, rules, 5, log.Default())

	if results1[0].Report.ThreatCount != results5[0].Report.ThreatCount {
		t.Errorf("results differ between worker counts: %d vs %d",
			results1[0].Report.ThreatCount, results5[0].Report.ThreatCount)
	}
	if results1[0].Report.ThreatScore != results5[0].Report.ThreatScore {
		t.Errorf("threat score differs between worker counts: %d vs %d",
			results1[0].Report.ThreatScore, results5[0].Report.ThreatScore)
	}
}
