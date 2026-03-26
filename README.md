# Threat Scanner Assignment

This repository is a Go starter for a file-based threat scanner. The goal is to scan files inside an input directory, match suspicious patterns from a JSON config, score those findings, and write a JSON report with both per-file results and overall summary statistics.

The codebase is intentionally split into a small root entrypoint and a `src/` package with TODOs. If someone new receives this repo, they should be able to use this README to understand where each part belongs before they start filling those TODOs in.

## Authors

- Umaima Nisar
- Samrudhi Yadgude

## What The Program Should Do

At a high level, the finished scanner should:

- accept CLI flags for `--input`, `--output`, `--config`, and `--workers`
- walk the input directory recursively and collect regular files
- log inaccessible paths instead of crashing
- load regex-based threat rules from the JSON config
- scan files concurrently using a worker pool
- compute per-file threat scores and risk levels
- write a final JSON report containing file results, logs, and summary stats

## Repo Layout

- `main.go`
  Root entrypoint. This is where the overall program flow gets wired together.
- `src/`
  Package where the missing implementation work belongs.
- `src/directorycode.go`
  File discovery logic.
- `src/threatdector.go`
  Rule loading and per-file scanning logic.
- `src/worker.go`
  Worker-pool concurrency logic.
- `src/json_report.go`
  Report assembly and JSON writing logic.
- `src/starter-code/`
  Snapshot/reference starter area.
- `config/`
  JSON rule definitions the scanner should load.
- `input/`
  Sample input files for testing.
- `output/`
  Generated report/log destination.
- `solution/`
  Separate completed reference copy.

## Where The TODOs Go

### `main.go`

The TODO in `main.go` is not where the real logic should live. It should stay as the coordinator that calls into `src`.

The expected flow is:

1. set up logging
2. load and validate the config
3. discover files under the input directory
4. scan them using the worker pool
5. build the final report object
6. write the report to disk
7. print a short success message or exit on failure

If you are implementing this from scratch, keep `main.go` thin. It should mostly pass values between package functions and handle top-level errors.

### `src/directorycode.go`

This file owns directory traversal.

Whoever implements this should:

- walk `inputDir` recursively
- ignore directories as scan targets
- ignore non-regular files
- create one `ScanTask` per regular file
- compute a relative path for reporting
- record access problems as `LogEntry` values instead of stopping the scan

This function should return both:

- the list of files to process
- the list of discovery-time log entries

### `src/threatdector.go`

This file owns config loading and the actual threat detection logic.

`LoadConfig` should:

- read the config file from disk
- unmarshal JSON into `RuleConfig`
- ensure there is at least one rule
- compile each regex pattern
- fail early if a rule is invalid

`ScanSingleFile` should:

- read one file
- apply every rule to that file’s contents
- record a `ThreatMatch` for every rule that matched
- count occurrences per rule
- compute the file’s total threat score
- return `"error"` status if the file cannot be read

This is also the right place to decide how `risk_level` is derived from the final numeric score.

### `src/worker.go`

This file owns concurrency.

The idea here is:

- create a task channel for `ScanTask`
- create a result channel for `ScanResult`
- start exactly `workerCount` goroutines
- have each worker repeatedly call `ScanSingleFile`
- wait for all workers with a `sync.WaitGroup`
- collect all results and sort them before returning

This file should not duplicate detection logic. It should only distribute work and gather results.

### `src/json_report.go`

This file owns the final output structure.

`BuildReport` should:

- merge discovery logs with scan-time logs
- gather all `FileReport` results
- count totals like files scanned, files flagged, inaccessible files, and total matches
- compute rule-based and severity-based summary maps
- track highest score and average score
- sort report sections so output is stable and easy to review

`WriteReport` should:

- create the output directory if it does not exist
- write the report as indented JSON
- place the final file in the output folder

## Suggested Implementation Order

If someone is using this repo to complete the starter, the easiest order is:

1. finish `LoadConfig`
2. finish `DiscoverFiles`
3. finish `ScanSingleFile`
4. finish `ScanFiles`
5. finish `BuildReport`
6. finish `WriteReport`
7. wire everything together in `main.go`

That order keeps dependencies manageable and makes it easier to test one layer at a time.

## What A Correct Result Should Look Like

Once implemented, running the scanner should produce:

- a JSON report in `output/`
- per-file results with score, risk level, and threat matches
- summary statistics across the full scan
- logs for discovery/read errors instead of crashes

The output should be deterministic enough that rerunning on the same files gives the same logical result aside from timestamps.

## Running The Project

From the repository root:

```bash
go run . --input ./input --output ./output --config ./config/threats.json --workers 4
```

If the root starter is still incomplete, the `solution/` folder can be used as a reference implementation.

## Notes

- The starter intentionally leaves structure in place so the missing parts can be implemented in the expected files.
- Keep the responsibilities separated: discovery in one file, detection in another, concurrency in another, and report generation in another.
- Try not to put all logic into `main.go`, because that makes the project harder to review and maintain.
