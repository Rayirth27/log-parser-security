# Log Parser & Brute-Force Detector

A command-line security tool that parses Apache access logs and detects brute-force login activity, mapping flagged IPs to MITRE ATT&CK **T1110.001 (Password Guessing)**.

## What it does
- Parses raw Apache "combined" log lines into structured entries, with defensive handling so malformed or unexpected lines are skipped rather than crashing the pipeline
- Flags source IPs whose authentication failure count (HTTP 401/403) exceeds a configurable threshold
- Produces a structured report: total events, unique IPs, status code breakdown, top IPs by request volume, and a dedicated section for flagged detections with their MITRE technique mapping
- Validated with an automated pytest suite

## Usage
```bash
python main.py <logfile> [--threshold N] [--output report.txt]
```

Examples:
```bash
python main.py access.log
python main.py access.log --threshold 5
python main.py access.log --threshold 5 --output report.txt
```

| Argument | Description | Default |
|---|---|---|
| `logfile` | Path to the Apache access log to analyze | required |
| `--threshold` | Auth-failure count from a single IP required to flag it | `10` |
| `--output` | Write the report to a file instead of stdout | none (prints to terminal) |

## Design decisions

**Why count failures, not total requests.** A high-volume IP isn't inherently suspicious — search engine crawlers and monitoring tools can generate hundreds of legitimate requests. Authentication failures are a much stronger signal: a normal client doesn't accumulate dozens of wrong-credential attempts by accident. The detector counts 401/403 responses per IP specifically, rather than raw request volume, to avoid flagging high-traffic-but-benign sources.

**Why the threshold is configurable rather than fixed.** What counts as "too many" failures depends on the environment — a public-facing login endpoint with normal user typos has a different baseline than an internal admin panel. Exposing `--threshold` as a CLI argument lets the same detection logic be tuned per deployment rather than requiring a code change.

**Why parsing never raises on bad input.** Real-world logs are messy — truncated lines, encoding issues, unexpected formats. `parse_line()` returns `None` for anything it can't confidently parse instead of throwing, and `parse_file()` reports a skipped-line count rather than failing the whole run. A log analysis tool that crashes on the first malformed line isn't useful in practice.

**Why detection is per-IP.** This is also the tool's current ceiling, covered below — it's a deliberate scope decision, not an oversight.

## Project structure
```
log-parser-security/
├── main.py          # CLI entry point (argparse)
├── parser.py        # Parses raw log lines into LogEntry objects
├── detector.py       # Counts auth failures per IP, flags brute-force candidates
├── report.py         # Formats results into a structured report
└── tests/
    └── test_parser.py
```

> No sample log file is bundled with this repo. To run it against real data, supply any Apache "combined" format access log.

## Running tests
```bash
python -m pytest tests/ -v
```

## Known limitations
- **Per-IP detection only.** A distributed attack spreading login attempts across many IPs against a single account would not currently be flagged — this would require tracking failures by target account/endpoint rather than by source IP, which is a natural next iteration.
- **Log format assumption.** Built against the standard Apache "combined" log format. Other formats may parse partially; missing fields default to `"unknown"` rather than failing the run.
