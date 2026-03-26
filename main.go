package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	// your path -"assignment-design-design-duo/src"
)

func main() {
	//Flags are given to you — DO NOT MODIFY
	inputDir := flag.String("input", "./input", "Input directory")
	outputDir := flag.String("output", "./output", "Output directory")
	configPath := flag.String("config", "./config/threats.json", "Rules config path")
	workerCount := flag.Int("workers", runtime.NumCPU(), "Worker count")
	flag.Parse()

	if *workerCount < 1 {
		fmt.Fprintln(os.Stderr, "workers must be at least 1")
		os.Exit(1)
	}

	// TODO: wire the program together using the src package
	//
	// Step 1: call src.BuildLogger to set up the logger
	// Step 2: call src.LoadConfig to load the rules
	// Step 3: call src.DiscoverFiles to find all log files
	// Step 4: call src.ScanFiles to scan them concurrently
	// Step 5: call src.BuildReport to assemble the report
	// Step 6: call src.WriteReport to save it to disk
	// Step 7: print a summary to the terminal
	//
	// Handle errors from each step with log.Fatalf or os.Exit(1)

	_ = inputDir
	_ = outputDir
	_ = configPath
	_ = workerCount // remove these as you implement
}
