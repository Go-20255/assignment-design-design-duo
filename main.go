package main

import (
	"assignment-design-design-duo/src"
	"flag"
	"fmt"
	"os"
	"runtime"
)

func main() {

	inputDir := flag.String("input", "./input", "Input directory to scan")
	outputDir := flag.String("output", "./output", "Output directory for report")
	configPath := flag.String("config", "./config/threats.json", "Path to threat rules JSON")
	workerCount := flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers")
	flag.Parse()

	if *workerCount < 1 {
		fmt.Fprintln(os.Stderr, "workers must be at least 1")
		os.Exit(1)
	}

	logger, logFile, err := src.BuildLogger(*outputDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logging: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	config, err := src.LoadConfig(*configPath)
	if err != nil {
		logger.Printf("failed to load config: %v", err)
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}
	logger.Printf("loaded %d rule(s) from %s", len(config.Rules), *configPath)

	logger.Printf("scanning directory: %s", *inputDir)
	tasks, walkLogs := src.DiscoverFiles(*inputDir, logger)
	logger.Printf("discovered %d file(s)", len(tasks))

	logger.Printf("starting scan with %d worker(s)", *workerCount)
	results := src.ScanFiles(tasks, config.Rules, *workerCount, logger)

	report := src.BuildReport(*inputDir, *outputDir, *configPath, *workerCount, walkLogs, results)

	if err := src.WriteReport(*outputDir, report); err != nil {
		logger.Printf("failed to write report: %v", err)
		fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Scan complete\n")
	fmt.Printf("  Files scanned   : %d\n", report.Summary.FilesScanned)
	fmt.Printf("  Files flagged   : %d\n", report.Summary.FilesFlagged)
	fmt.Printf("  Total score     : %d\n", report.Summary.TotalThreatScore)
	fmt.Printf("  Highest risk    : %s (%d)\n",
		report.Summary.HighestThreatScoreFile,
		report.Summary.HighestThreatScore)
	fmt.Printf("  Report saved to : %s/report.json\n", *outputDir)
	fmt.Println("─────────────────────────────────────────")
}
