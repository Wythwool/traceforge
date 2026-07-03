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
traceforge profile FILE          # print compact format profile observations
traceforge profile FILE --csv format_profile.csv
traceforge apis FILE             # summarize imported API families
traceforge apis FILE --csv api_profile.csv
traceforge rules FILE            # evaluate built-in local rules
traceforge rules FILE --rules rules.json
traceforge signatures FILE       # match built-in local signatures
traceforge signatures FILE --signatures signatures.json --csv signatures.csv
traceforge capabilities FILE     # group static capability evidence
traceforge capabilities FILE --csv capabilities.csv
traceforge ruleset validate rules.json
traceforge ruleset list rules.json
traceforge ruleset export -o built-in-rules.json
traceforge schema list
traceforge schema show report
traceforge schema export-all -o schemas
traceforge bundle create CASE_DIR -o case.traceforge.zip
traceforge bundle verify case.traceforge.zip
traceforge bundle import case.traceforge.zip --cases-root .traceforge/cases
traceforge carve FILE -o carved  # carve embedded artifacts into a folder
traceforge extract FILE -o extracted
traceforge extract FILE --resources --overlay -o extracted --json
traceforge search FILE --text api
traceforge search FILE --hex "4d 5a ?? 90"
traceforge search FILE --regex "https?://"
traceforge symbols FILE --json
traceforge symbols FILE --csv symbols.csv
traceforge symbols FILE --relocations-csv relocations.csv
traceforge code FILE --json
traceforge code FILE --csv code.csv
traceforge code FILE --decoder capstone --blocks-csv blocks.csv
traceforge code FILE --xrefs-csv xrefs.csv
traceforge index                 # write .traceforge/cases/case_index.json
traceforge db build              # write .traceforge/cases/traceforge.db
traceforge db query --indicator example.com --json
traceforge workspace             # write case_index.json and workspace.html
traceforge workspace --hunt hunt-out/hunt.json
traceforge hunt                  # evaluate built-in rules across stored cases
traceforge hunt --rules rules.json -o hunt-out
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
- ELF program headers, sections, permissions, dynamic tags, needed libraries,
  SONAME, RPATH/RUNPATH, relocation sections, and header metadata
- Mach-O load commands, linked libraries, segments, sections, and header metadata
- ZIP/APK/JAR entries, APK permissions when visible, DEX/native-library counts,
  and JAR manifest preview
- WASM sections, imports, and exports
- Embedded artifact signatures inside larger byte streams
- Search results with file offsets, match context, and section names when known
- Visible PE/ELF/Mach-O symbols, imports, exports, needed libraries, PE base
  relocation blocks, and ELF REL/RELA relocation entries with symbol names when
  visible
- Normalized API import profiles with library categories and API-family groups
  for network, filesystem, registry, process/thread, memory loading,
  cryptography, compression, services, diagnostics, system information,
  synchronization, and UI calls
- Static executable code ranges, entry point mapping, function candidates, basic
  blocks, call/branch edges, and bounded instruction previews for common native
  code
- Code cross-references that link call and branch sources to resolved function
  candidates, PE imported functions through IAT slots, code ranges, and offsets
  when visible
- Compact format profiles with PE hardening flags, executable/writable section
  observations, overlays, TLS/debug/certificate signals, ELF segment checks,
  Mach-O load-command signals, container path checks, and embedded artifact
  markers
- Optional Capstone-backed disassembly for x86, x86-64, ARM, and ARM64, with a
  built-in decoder fallback for offline baseline use
- Built-in and JSON-defined local rule matches
- Built-in and JSON-defined local signature matches with text, UTF-16LE text,
  hex wildcard, regex, and offset-constrained patterns
- Static capability groups for network, filesystem, registry, process,
  memory/code loading, cryptography, compression, scripting, diagnostics,
  system information, and service-control evidence

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
  `relocations.csv`, `xrefs.csv`, `signature_matches.csv`, `capabilities.csv`,
  `format_profile.csv`, `api_profile.csv`, and `findings.csv` - table exports
  for day-to-day case work
- `hexdump.txt` - bounded source byte view for quick inspection
- `artifacts.json` - manifest for generated workbench files

`traceforge index` writes `case_index.json` with one compact row per case:
source file, hash, size, format, score, analyst status, tags, note count,
indicator count, rule match count, string count, PE resource/debug/TLS/certificate
counts, import/export counts, symbol and relocation counts, code range, function,
basic-block and edge counts, xref count, and embedded artifact count.

`traceforge workspace` writes `case_index.json` and `workspace.html`.
`workspace.html` is a self-contained browser for the cases root, with search,
status/format/tag filters, case metrics, latest-note previews, hunt match
counts, per-case rule hits, and links into each case viewer, report, summary,
and annotation log. When `CASES_ROOT/hunt/hunt.json` exists it is embedded
automatically; `--hunt` can point at another hunt result.

`traceforge db build CASES_ROOT` writes a SQLite database for a cases root.
The database stores case summaries, indicators, rule matches, and tags in
separate tables. `traceforge db query` can filter by format, status, tag,
rule ID, indicator substring, and minimum score. Use `--json` when the output
is being passed to another tool.

`traceforge hunt` evaluates built-in or JSON-defined rules against every stored
case report in a cases root. It writes `hunt.json`, `hunt.csv`, and `hunt.md`
with the matched cases, rule IDs, levels, and evidence.

`traceforge signatures FILE` matches built-in or JSON-defined signatures against
one local file without creating a case. Signature patterns can use literal text,
UTF-16LE text, hex bytes with `??` wildcards, regular expressions over extracted
string runs, exact offsets, and per-pattern match caps. Scans also write built-in
signature results into `report.json` and `signature_matches.csv`.

`traceforge capabilities FILE` groups static evidence into analyst-friendly
capability categories. It uses extracted strings, indicators, imports, symbols,
format facts, and signature matches. Scans also write capability results into
`report.json`, `report.html`, `summary.md`, `capabilities.csv`, and
`findings.csv`.

`traceforge profile FILE` builds a compact profile from parsed format, symbol,
and code facts. It highlights format-specific observations such as missing PE
hardening flags, writable executable ranges, TLS callbacks, overlays, ELF stack
or segment permissions, Mach-O signing commands, unsafe archive paths, and
embedded format markers. Scans also write profile results into `report.json`,
`report.html`, `summary.md`, `format_profile.csv`, and `findings.csv`.

`traceforge apis FILE` normalizes parsed imports into library and API-family
summaries. It groups imports by common analyst categories such as network,
filesystem, registry, process/thread, memory loading, cryptography, services,
diagnostics, system information, synchronization, and UI usage. Scans also write
API profile results into `report.json`, `report.html`, `summary.md`,
`api_profile.csv`, and `findings.csv`.

`traceforge schema` lists, prints, or exports JSON Schemas for the main
machine-readable files: `report.json`, `case_index.json`, `hunt.json`,
`extract_manifest.json`, `bundle_manifest.json`, capability output, format
profile output, API profile output, external rule sets, and external signature
sets. These schemas are intended for pipeline validation, typed clients, and
long-lived case archives.

`traceforge bundle create CASE_DIR -o case.traceforge.zip` writes a portable zip
for one stored case. The bundle contains a `bundle_manifest.json` with every
case file path, size, and SHA-256. `traceforge bundle verify` checks the bundle
before use, and `traceforge bundle import` restores it into a cases root. Import
does not replace an existing case unless `--overwrite` is provided.

`traceforge diff CASE_A CASE_B` writes `diff.json` and `diff.md`. The diff
compares hashes, size, format, score, indicators, rule matches, imports,
exports, sections, resources, debug records, symbols, relocations, function
candidates, basic blocks, code xrefs, code edges, certificates, embedded
artifacts, and string totals.

`traceforge extract FILE -o extracted` writes parsed byte ranges into an output
folder. By default it extracts sections or segments, PE resources, and PE
overlay data when those ranges are present. Use `--sections`, `--resources`, or
`--overlay` to limit the output. The folder includes `extract_manifest.json` and
`extracted_payloads.csv` with offsets, sizes, hashes, and file names.

Scores are deterministic from 0 to 100. Every score reason includes evidence.

## Analyst Annotations

Each case has a small annotation log for day-to-day work. The files are plain
JSON and Markdown, and the viewer reads them directly.

```bash
traceforge annotate CASE_DIR --status in_progress
traceforge annotate CASE_DIR --tag packed --tag needs-symbols
traceforge annotate CASE_DIR --note "Check the imported crypto APIs" --title "Next step"
traceforge annotate CASE_DIR
traceforge workspace
traceforge hunt --rules rules.json
traceforge workspace --hunt hunt/hunt.json
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

The same rule files can be used with `traceforge rules FILE --rules rules.json`
for one file or `traceforge hunt CASES_ROOT --rules rules.json` for an existing
case workspace.

Use `traceforge ruleset validate rules.json` before running a large hunt. It
checks rule IDs, levels, `any`/`all` groups, condition names, regular
expressions, hex byte strings, suffixes, and condition value types. Use
`traceforge ruleset export -o built-in-rules.json` to write the built-in rules
to a file that can be edited and reused.

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

The GitHub Actions workflow runs linting, tests, CLI smoke checks, and package
builds on every push and pull request.
