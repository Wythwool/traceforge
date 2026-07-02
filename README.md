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

For Capstone-backed disassembly:

```bash
python -m pip install ".[disasm]"
```

## Commands

```bash
traceforge scan FILE             # create a case under .traceforge/cases
traceforge scan-dir DIR          # scan regular files directly inside DIR
traceforge scan-dir DIR -r       # scan regular files recursively
traceforge report CASE_DIR       # rebuild report.html, summary.md, graph.json, viewer.html
traceforge export CASE_DIR       # rebuild indicators.csv and indicators.json
traceforge artifacts CASE_DIR    # rebuild workbench CSVs and hexdump files
traceforge view CASE_DIR         # rebuild the self-contained case viewer
traceforge annotate CASE_DIR --status triage --tag packed --note "Needs import review"
traceforge identify FILE         # print format metadata as JSON
traceforge rules FILE            # evaluate built-in local rules
traceforge rules FILE --rules rules.json
traceforge carve FILE -o carved  # carve embedded artifacts into a folder
traceforge search FILE --text api
traceforge search FILE --hex "4d 5a ?? 90"
traceforge search FILE --regex "https?://"
traceforge symbols FILE --json
traceforge symbols FILE --csv symbols.csv
traceforge code FILE --json
traceforge code FILE --csv code.csv
traceforge code FILE --decoder capstone --blocks-csv blocks.csv
traceforge code FILE --xrefs-csv xrefs.csv
traceforge index                 # write .traceforge/cases/case_index.json
traceforge diff CASE_A CASE_B    # write JSON and Markdown case diff
```

## What It Extracts

- Hashes: SHA-256, SHA-1, MD5
- ASCII and UTF-16LE strings
- URLs, domains, IPv4 values, file paths, registry-style paths
- Overall entropy, byte-window entropy, and 4096-byte chunk entropy
- Format metadata for PE, ELF, Mach-O, ZIP/APK/JAR, and WebAssembly
- PE sections with permissions, entropy, hashes, imports with IAT addresses,
  exports, directories, resources, CodeView/PDB debug records, TLS callbacks,
  Authenticode certificate table records, overlay metadata, entry point,
  subsystem, and observations
- ELF program headers, sections, permissions, and header metadata
- Mach-O load commands, linked libraries, segments, sections, and header metadata
- ZIP/APK/JAR entries, APK permissions when visible, DEX/native-library counts,
  and JAR manifest preview
- WASM sections, imports, and exports
- Embedded artifact signatures inside larger byte streams
- Search results with file offsets, match context, and section names when known
- Visible PE/ELF/Mach-O symbols, imports, exports, needed libraries, and PE
  base relocation blocks
- Static executable code ranges, entry point mapping, function candidates, basic
  blocks, call/branch edges, and bounded instruction previews for common native
  code
- Code cross-references that link call and branch sources to resolved function
  candidates, PE imported functions through IAT slots, code ranges, and offsets
  when visible
- Optional Capstone-backed disassembly for x86, x86-64, ARM, and ARM64, with a
  built-in decoder fallback for offline baseline use
- Built-in and JSON-defined local rule matches

## Case Output

Each scan writes:

- `manifest.json` - case metadata and source file hash
- `report.json` - full structured extraction and score
- `report.html` - self-contained readable report
- `viewer.html` - self-contained case viewer with searchable graph nodes,
  related edges, analyst notes, code xrefs, functions, and indicators
- `summary.md` - short analyst summary
- `annotations.json` / `annotations.md` - case status, tags, notes, and update
  history
- `indicators.csv` / `indicators.json` - indicator exports
- `graph.json` - evidence graph with samples, format nodes, sections, imports,
  exports, PE resources/debug metadata, code ranges, functions, basic blocks,
  code xrefs, strings, indicators, rule matches, findings, and embedded artifacts
- `strings.csv`, `chunks.csv`, `sections.csv`, `resources.csv`, `debug.csv`,
  `imports.csv`, `exports.csv`, `symbols.csv`, `code.csv`, `blocks.csv`,
  `xrefs.csv`, and `findings.csv` - table exports for day-to-day case work
- `hexdump.txt` - bounded source byte view for quick inspection
- `artifacts.json` - manifest for generated workbench files

`traceforge index` writes `case_index.json` with one compact row per case:
source file, hash, size, format, score, analyst status, tags, note count,
indicator count, rule match count, string count, PE resource/debug/TLS/certificate
counts, import/export counts, symbol and relocation counts, code range, function,
basic-block and edge counts, xref count, and embedded artifact count.

`traceforge diff CASE_A CASE_B` writes `diff.json` and `diff.md`. The diff
compares hashes, size, format, score, indicators, rule matches, imports,
exports, sections, resources, debug records, symbols, relocations, function
candidates, basic blocks, code xrefs, code edges, certificates, embedded
artifacts, and string totals.

Scores are deterministic from 0 to 100. Every score reason includes evidence.

## Analyst Annotations

Each case has a small annotation log for day-to-day work. The files are plain
JSON and Markdown, and the viewer reads them directly.

```bash
traceforge annotate CASE_DIR --status in_progress
traceforge annotate CASE_DIR --tag packed --tag needs-symbols
traceforge annotate CASE_DIR --note "Check the imported crypto APIs" --title "Next step"
traceforge annotate CASE_DIR
```

The command rewrites `annotations.json`, `annotations.md`, and `viewer.html`.

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
