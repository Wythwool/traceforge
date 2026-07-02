# TraceForge

TraceForge reads local files as bytes, extracts simple facts (hashes, strings,
indicators, entropy, chunk stats), and writes a case folder with reports.
Standard library only; it never touches the network and never executes inputs.

## Install

```
python -m pip install .
```

Requires Python 3.12+. For running the tests: `python -m pip install ".[test]"`.

## Commands

```
traceforge scan FILE        # scan one file, create a case under .traceforge/cases
traceforge scan-dir DIR     # scan every regular file directly inside DIR
traceforge report CASE_DIR  # regenerate report.html, summary.md, graph.json
traceforge export CASE_DIR  # regenerate indicators.csv and indicators.json
```

## Example

```
printf 'demo http://example.com 10.0.0.1\n' > sample.bin
traceforge scan sample.bin
# case created: .traceforge/cases/sample.bin-ab8ce57d0a6c
traceforge report .traceforge/cases/sample.bin-ab8ce57d0a6c
traceforge export .traceforge/cases/sample.bin-ab8ce57d0a6c
```

## Output files (per case)

- `manifest.json` - file name, source path, size, sha256, timestamp
- `report.json` - all extracted data plus the score (source of truth)
- `report.html` - self-contained, readable report
- `summary.md` - short text summary
- `indicators.csv` / `indicators.json` - `type,value,source` exports
- `graph.json` - nodes (sample, chunk, string, indicator, finding) and edges
  (contains, references, has_indicator, has_finding)

Scores are deterministic (0-100, labeled low/medium/high) and every reason
lists concrete evidence.

## Tests

```
python -m pytest
```
