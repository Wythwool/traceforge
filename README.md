# TraceForge

TraceForge is an offline file inspection workbench. It reads local files as
bytes, extracts structured facts, builds an evidence graph, evaluates local
rules, and writes repeatable case reports.

The tool does not execute input files, make network calls, attach to processes,
or modify the host outside the case/output folders it creates.

## Install

```bash
python -m pip install .
```

Requires Python 3.12+. For tests and linting:

```bash
python -m pip install ".[test,lint]"
```

## Commands

```bash
traceforge scan FILE             # create a case under .traceforge/cases
traceforge scan-dir DIR          # scan regular files directly inside DIR
traceforge scan-dir DIR -r       # scan regular files recursively
traceforge report CASE_DIR       # rebuild report.html, summary.md, graph.json
traceforge export CASE_DIR       # rebuild indicators.csv and indicators.json
traceforge artifacts CASE_DIR    # rebuild strings/chunks/sections/imports/exports CSVs
traceforge identify FILE         # print format metadata as JSON
traceforge rules FILE            # evaluate built-in local rules
traceforge rules FILE --rules rules.json
traceforge carve FILE -o carved  # carve embedded artifacts into a folder
traceforge index                 # write .traceforge/cases/case_index.json
traceforge diff CASE_A CASE_B    # write JSON and Markdown case diff
```

## What It Extracts

- Hashes: SHA-256, SHA-1, MD5
- ASCII and UTF-16LE strings
- URLs, domains, IPv4 values, file paths, registry-style paths
- Overall entropy, byte-window entropy, and 4096-byte chunk entropy
- Format metadata for PE, ELF, Mach-O, ZIP/APK/JAR, and WebAssembly
- PE sections, imports, exports, directories, entry point, subsystem, and
  section observations
- ELF sections and header metadata
- Mach-O header metadata
- ZIP/APK/JAR entries, APK permissions when visible, DEX/native-library counts,
  and JAR manifest preview
- WASM sections, imports, and exports
- Embedded artifact signatures inside larger byte streams
- Built-in and JSON-defined local rule matches

## Case Output

Each scan writes:

- `manifest.json` - case metadata and source file hash
- `report.json` - full structured extraction and score
- `report.html` - self-contained readable report
- `summary.md` - short analyst summary
- `indicators.csv` / `indicators.json` - indicator exports
- `graph.json` - evidence graph with samples, format nodes, sections, imports,
  exports, strings, indicators, rule matches, findings, and embedded artifacts
- `strings.csv`, `chunks.csv`, `sections.csv`, `imports.csv`, `exports.csv`,
  and `findings.csv` - table exports for day-to-day case work
- `hexdump.txt` - bounded source byte view for quick inspection
- `artifacts.json` - manifest for generated workbench files

`traceforge index` writes `case_index.json` with one compact row per case:
source file, hash, size, format, score, indicator count, rule match count,
string count, import/export counts, and embedded artifact count.

`traceforge diff CASE_A CASE_B` writes `diff.json` and `diff.md`. The diff
compares hashes, size, format, score, indicators, rule matches, imports,
exports, sections, embedded artifacts, and string totals.

Scores are deterministic from 0 to 100. Every score reason includes evidence.

## Local Rules

Built-in rules cover format, container entries, high-entropy regions, network
indicators, registry-style paths, PE section observations, and embedded
artifacts.

External rules are JSON:

```json
{
  "rules": [
    {
      "id": "custom.vendor-marker",
      "name": "Vendor marker",
      "level": "info",
      "any": [
        {"contains": "VendorName"},
        {"regex": "v[0-9]+\\.[0-9]+"}
      ],
      "description": "Example local string rule."
    }
  ]
}
```

Supported condition keys: `format_kind`, `indicator_type`, `regex`,
`contains`, `hex`, `high_entropy_chunks_at_least`, `pe_observation`,
`container_entry_suffix`, and `embedded_artifact`.

## Example

```bash
printf 'demo http://example.com 10.0.0.1\n' > sample.bin
traceforge scan sample.bin
traceforge identify sample.bin
traceforge rules sample.bin
```

On Windows, use a Python 3.12 launcher if needed:

```powershell
py -3.12 -m pip install ".[test,lint]"
py -3.12 -m pytest
```

## Tests

```bash
python -m ruff check .
python -m pytest
```
