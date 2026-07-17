# Log Parser & Brute-Force Detector

A command-line security tool that parses Apache access logs, detects brute-force login activity, and now includes an optional AI-powered threat analysis layer. Flagged IPs are mapped to MITRE ATT&CK **T1110.001 (Password Guessing)**.

## What it does

- Parses raw Apache "combined" log lines into structured entries, with defensive handling so malformed or unexpected lines are skipped rather than crashing the pipeline
- Flags source IPs whose authentication failure count (HTTP 401/403) exceeds a configurable threshold
- Produces a structured report: total events, unique IPs, status code breakdown, top IPs by request volume, and a dedicated section for flagged detections with their MITRE technique mapping
- Optionally sends the report to an LLM (via OpenRouter) for a structured AI threat assessment — threat level, attack type, recommended action, and MITRE technique
- Validated with an automated pytest suite

## Usage

```
python main.py <logfile> [--threshold N] [--output report.txt] [--format text|json] [--ai-analysis]
```

Examples:

```
python main.py access.log
python main.py access.log --threshold 5
python main.py access.log --threshold 5 --output report.txt
python main.py access.log --format json
python main.py access.log --format json --ai-analysis
```

| Argument | Description | Default |
|---|---|---|
| `logfile` | Path to the Apache access log to analyze | required |
| `--threshold` | Auth-failure count from a single IP required to flag it | `10` |
| `--output` | Write the report to a file instead of stdout | none (prints to terminal) |
| `--format` | Output format: `text` (human-readable) or `json` (machine-readable) | `text` |
| `--ai-analysis` | Send the report summary to an LLM for AI-powered threat analysis | off |

## JSON output

`--format json` produces a single structured object suitable for piping into a SIEM or another tool, instead of the human-readable text report:

```json
{
  "total_events": 9,
  "unique_ips": 1,
  "threshold": 10,
  "flagged_count": 0,
  "status_code_breakdown": {
    "401": 9
  },
  "top_ips": [
    {"ip": "1.2.3.4", "requests": 9, "flagged": false}
  ],
  "detections": []
}
```

When combined with `--ai-analysis`, the AI's assessment is nested inside the same object under an `ai_analysis` key — the whole output stays a single parseable JSON blob rather than mixing formats.

## AI-Powered Threat Analysis

The `--ai-analysis` flag sends the generated report summary to an LLM through [OpenRouter](https://openrouter.ai) and returns a structured JSON assessment:

- **threat_level** — LOW / MEDIUM / HIGH / CRITICAL
- **attack_type** — e.g. Brute Force
- **recommended_action** — concrete mitigation steps
- **mitre_technique** — mapped ATT&CK technique ID

### Setup

1. Create an account at [openrouter.ai](https://openrouter.ai) and generate an API key.
2. Create a `.env` file in the project root (this file is git-ignored):
   ```
   OPENROUTER_API_KEY=your_key_here
   ```
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

By default this uses a free-tier model via OpenRouter. Free-tier model availability changes over time — if you hit a `404` or `429` error, check [openrouter.ai/models?max_price=0](https://openrouter.ai/models?max_price=0) for a currently available model and update the `model=` string in `ai_analyzer.py`. Paid models (e.g. Claude, GPT-4o) work the same way and typically cost a fraction of a cent per request.

This feature degrades gracefully — if the API key is missing, invalid, or the request fails for any reason, the tool prints a clear error and still completes the standard (non-AI) report.

## Design decisions

**Why count failures, not total requests.** A high-volume IP isn't inherently suspicious — search engine crawlers and monitoring tools can generate hundreds of legitimate requests. Authentication failures are a much stronger signal: a normal client doesn't accumulate dozens of wrong-credential attempts by accident. The detector counts 401/403 responses per IP specifically, rather than raw request volume, to avoid flagging high-traffic-but-benign sources.

**Why the threshold is configurable rather than fixed.** What counts as "too many" failures depends on the environment — a public-facing login endpoint with normal user typos has a different baseline than an internal admin panel. Exposing `--threshold` as a CLI argument lets the same detection logic be tuned per deployment rather than requiring a code change.

**Why parsing never raises on bad input.** Real-world logs are messy — truncated lines, encoding issues, unexpected formats. `parse_line()` returns `None` for anything it can't confidently parse instead of throwing, and `parse_file()` reports a skipped-line count rather than failing the whole run. A log analysis tool that crashes on the first malformed line isn't useful in practice.

**Why the AI layer is a separate module, not merged into `report.py`.** `report.py` formats the deterministic, rule-based output the tool already produces. `ai_analyzer.py` is an optional add-on that consumes that output — keeping them separate means the core tool still works with zero external dependencies or API keys if the AI layer is unavailable or intentionally left off.

**Why detection is per-IP.** This is also the tool's current ceiling, covered below — it's a deliberate scope decision, not an oversight.

## Project structure

```
log-parser-security/
├── main.py          # CLI entry point (argparse)
├── parser.py        # Parses raw log lines into LogEntry objects
├── detector.py       # Counts auth failures per IP, flags brute-force candidates
├── report.py          # Formats results into a text or JSON report
├── ai_analyzer.py     # Optional LLM-powered threat analysis (via OpenRouter)
├── collect_IPs.py     # TODO: describe what this script does
├── requirements.txt
├── .env               # OpenRouter API key (git-ignored, not committed)
└── tests/
    └── test_parser.py
```

> No sample log file is bundled with this repo. To run it against real data, supply any Apache "combined" format access log.

## Running tests

```
python -m pytest tests/ -v
```

## Known limitations

- **Per-IP detection only.** A distributed attack spreading login attempts across many IPs against a single account would not currently be flagged — this would require tracking failures by target account/endpoint rather than by source IP, which is a natural next iteration.
- **Log format assumption.** Built against the standard Apache "combined" log format. Other formats may parse partially; missing fields default to `"unknown"` rather than failing the run.
- **AI analysis depends on an external API.** The `--ai-analysis` flag requires network access and a valid OpenRouter key; free-tier models may be rate-limited or occasionally deprecated.
