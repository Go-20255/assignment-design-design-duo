# Threat Scanner Starter

This project is a self-contained Go CLI starter for the assignment's file scanning pipeline.

## Features

- CLI flags: `--input`, `--output`, `--config`, `--workers`
- Regex-based threat detection loaded from JSON config
- Threat scoring and summary statistics
- Worker pool concurrency for file processing
- JSON report output with per-file results
- Log file for inaccessible files and scan errors

## Run

```bash
go run . --input ./input --output ./output --config ./config/threats.json --workers 4
```

## Output

- `output/report.json`: full report with summary stats
- `output/logs/scan.log`: execution log
