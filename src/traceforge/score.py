"""Deterministic, explainable 0-100 scoring for TraceForge extractions.

Every reason carries concrete evidence. Labels stay factual: low, medium, high.
"""

HIGH_ENTROPY_THRESHOLD = 7.2
LONG_STRING_LENGTH = 200
LARGE_FILE_BYTES = 5 * 1024 * 1024

URL_POINTS_EACH = 4
IPV4_POINTS_EACH = 4
HIGH_ENTROPY_POINTS_EACH = 5
REGISTRY_POINTS_EACH = 5
LONG_STRING_POINTS_EACH = 3
LARGE_FILE_POINTS = 10

URL_COUNT_CAP = 5
IPV4_COUNT_CAP = 5
HIGH_ENTROPY_COUNT_CAP = 5
REGISTRY_COUNT_CAP = 3
LONG_STRING_COUNT_CAP = 3

MAX_SCORE = 100
LOW_MAX = 29
MEDIUM_MAX = 64

EVIDENCE_LIMIT = 5


def label_for(score: int) -> str:
    if score <= LOW_MAX:
        return "low"
    if score <= MEDIUM_MAX:
        return "medium"
    return "high"


def _indicator_values(extraction: dict, kind: str) -> list[str]:
    return sorted({item["value"] for item in extraction["indicators"] if item["type"] == kind})


def score_extraction(extraction: dict) -> dict:
    """Compute a deterministic score with per-signal evidence."""
    reasons: list[dict] = []

    urls = _indicator_values(extraction, "url")
    if urls:
        points = min(len(urls), URL_COUNT_CAP) * URL_POINTS_EACH
        reasons.append(
            {
                "signal": "urls",
                "points": points,
                "detail": f"{len(urls)} distinct URL value(s) found in strings",
                "evidence": urls[:EVIDENCE_LIMIT],
            }
        )

    addresses = _indicator_values(extraction, "ipv4")
    if addresses:
        points = min(len(addresses), IPV4_COUNT_CAP) * IPV4_POINTS_EACH
        reasons.append(
            {
                "signal": "ipv4_addresses",
                "points": points,
                "detail": f"{len(addresses)} distinct IPv4 value(s) found in strings",
                "evidence": addresses[:EVIDENCE_LIMIT],
            }
        )

    high_chunks = [
        chunk
        for chunk in extraction["chunks"]["records"]
        if chunk["entropy"] >= HIGH_ENTROPY_THRESHOLD
    ]
    if high_chunks:
        points = min(len(high_chunks), HIGH_ENTROPY_COUNT_CAP) * HIGH_ENTROPY_POINTS_EACH
        evidence = [
            f"offset={chunk['offset']} size={chunk['size']} entropy={chunk['entropy']}"
            for chunk in high_chunks[:EVIDENCE_LIMIT]
        ]
        reasons.append(
            {
                "signal": "high_entropy_chunks",
                "points": points,
                "detail": (
                    f"{len(high_chunks)} chunk(s) with entropy >= {HIGH_ENTROPY_THRESHOLD}"
                ),
                "evidence": evidence,
            }
        )

    registry = _indicator_values(extraction, "registry_path")
    if registry:
        points = min(len(registry), REGISTRY_COUNT_CAP) * REGISTRY_POINTS_EACH
        reasons.append(
            {
                "signal": "registry_paths",
                "points": points,
                "detail": f"{len(registry)} registry-style path value(s) found in strings",
                "evidence": registry[:EVIDENCE_LIMIT],
            }
        )

    stored_strings = (
        extraction["strings"]["ascii"]["values"] + extraction["strings"]["utf16le"]["values"]
    )
    long_strings = [value for value in stored_strings if len(value) >= LONG_STRING_LENGTH]
    if long_strings:
        points = min(len(long_strings), LONG_STRING_COUNT_CAP) * LONG_STRING_POINTS_EACH
        evidence = [
            f"length {len(value)}: {value[:40]}" for value in long_strings[:EVIDENCE_LIMIT]
        ]
        reasons.append(
            {
                "signal": "long_strings",
                "points": points,
                "detail": (
                    f"{len(long_strings)} string(s) with length >= {LONG_STRING_LENGTH}"
                ),
                "evidence": evidence,
            }
        )

    size = extraction["size"]
    if size >= LARGE_FILE_BYTES:
        reasons.append(
            {
                "signal": "large_file",
                "points": LARGE_FILE_POINTS,
                "detail": f"file size {size} bytes is at least {LARGE_FILE_BYTES} bytes",
                "evidence": [f"size={size}"],
            }
        )

    total = min(sum(reason["points"] for reason in reasons), MAX_SCORE)
    return {
        "score": total,
        "max_score": MAX_SCORE,
        "label": label_for(total),
        "reasons": reasons,
    }
