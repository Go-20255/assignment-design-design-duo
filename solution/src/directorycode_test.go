package src

import (
	"log"
	"os"
	"path/filepath"
	"testing"
)

// helper to create temporary files
func writeTempFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to write %s: %v", path, err)
	}
	return path
}

// silent logger to keep test output clean
func testLogger() *log.Logger {
	return log.New(os.Stderr, "", 0)
}

func TestDiscoverFiles_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	tasks, logs := DiscoverFiles(dir, testLogger())
	if len(tasks) != 0 {
		t.Errorf("expected 0 tasks, got %d", len(tasks))
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestDiscoverFiles_SingleFile(t *testing.T) {
	dir := t.TempDir()
	writeTempFile(t, dir, "app.log")

	tasks, logs := DiscoverFiles(dir, testLogger())
	if len(tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].RelativePath != "app.log" {
		t.Errorf("expected RelativePath 'app.log', got %s", tasks[0].RelativePath)
	}
	if len(logs) != 0 {
		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}

func TestDiscoverFiles_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	files := []string{"app.log", "data.json", "readme.txt"}
	for _, f := range files {
		writeTempFile(t, dir, f)
	}

	tasks, _ := DiscoverFiles(dir, testLogger())

	if len(tasks) != len(files) {
		t.Errorf("expected %d tasks, got %d", len(files), len(tasks))
	}

	collected := make(map[string]bool)
	for _, t := range tasks {
		collected[t.RelativePath] = true
	}
	for _, f := range files {
		if !collected[f] {
			t.Errorf("file %s missing from tasks", f)
		}
	}
}

func TestDiscoverFiles_RecursiveWalk(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	os.Mkdir(sub, 0755)

	writeTempFile(t, dir, "root.log")
	writeTempFile(t, sub, "sub1.log")
	writeTempFile(t, sub, "sub2.log")
	writeTempFile(t, sub, "sub3.txt")

	tasks, _ := DiscoverFiles(dir, testLogger())

	// your function collects all regular files, so expect 4
	if len(tasks) != 4 {
		t.Errorf("expected 4 tasks, got %d", len(tasks))
	}
}

func TestDiscoverFiles_AbsolutePathAndRelativePath(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.log")
	os.WriteFile(filePath, []byte("log content"), 0o644)

	logger := log.New(os.Stdout, "", log.LstdFlags)
	tasks, _ := DiscoverFiles(tmpDir, logger)

	if len(tasks) == 0 {
		t.Fatal("expected at least 1 task, got 0")
	}

	task := tasks[0]
	if task.AbsolutePath != filePath {
		t.Errorf("absolute path mismatch, got %q, want %q", task.AbsolutePath, filePath)
	}
	if task.RelativePath != "test.log" {
		t.Errorf("relative path mismatch, got %q, want %q", task.RelativePath, "test.log")
	}
}

func TestDiscoverFiles_NonexistentDirectory(t *testing.T) {
	_, logs := DiscoverFiles("/nonexistent/path", testLogger())

	if len(logs) == 0 {
		t.Error("expected at least 1 log entry for nonexistent directory")
	}
	if logs[0].Level != "ERROR" {
		t.Errorf("expected log level ERROR, got %s", logs[0].Level)
	}
}

func TestDiscoverFiles_FileWithNoPermissions(t *testing.T) {
	dir := t.TempDir()
	file := writeTempFile(t, dir, "locked.log")

	// remove read permissions
	os.Chmod(file, 0000)
	defer os.Chmod(file, 0644)

	tasks, logs := DiscoverFiles(dir, testLogger())
	if len(tasks) != 1 {
		t.Errorf("expected 1 task, got %d", len(tasks))
	}
	if len(logs) != 0 {

		t.Errorf("expected 0 logs, got %d", len(logs))
	}
}
