# Assignment Design: Concurrent Log Auditor & Security Parser
**Authors:** Samrudhi Yadgude. Umaima Nisar 

## Overview
In this assignment, students build a command-line tool in Go that recursively scans
a directory of server log files, detects potential security threats using configurable
regular-expression rules, and exports a structured JSON report. Threat-detection rules
and their severity scores are loaded at runtime from a JSON configuration file, Files are processed concurrently using a fixed-size worker pool. The final report includes every individual threat as well as aggregate summary statistics 
## Assignment Details
1. **Directory Walking**
   - Recursively scan a directory tree to find `.log` files.
   - Handle inaccessible files safely.
2. **Threat Detection**
   -----plz fill it
3. **Concurrency**
 -------plz fill it
4. **JSON Export**
   - Save threats in `output/report.json`.
5. **CLI Entry Point **

- Parse four command-line flags with the `flag` package:
  - `--input`   (default: `input`)
  - `--output`  (default: `output/report.json`)
  - `--workers` (default: `4`)
  - `--config`  (default: `config/rules.json`)
- It calls to `WalkLogs` → `LoadRules` → `WorkerPoolScan` →
  `SaveJSONReport`.
- Print informative `[INFO]` progress messages and a final summary table to
  `stdout`.

---

## Build & Run

### Prerequisites

- Go 1.22 or later

### Build

```bash
make          
```

Or manually:

```bash
go build -o bin/assignment-design-design-duo main.go
```
### Custom flags

```bash
./bin/assignment-design-design-duor --input mydir --output results.json --workers 8 --config custom_rules.json
```

---

## Submission
Include all source files, `Makefile`, `run.sh`, and sample input logs.
