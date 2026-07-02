"""Tests for traceforge.core extraction and traceforge.score scoring."""

import hashlib

from traceforge import core, score


def build_sample() -> bytes:
    lines = [
        b"plain ascii marker wxyz",
        b"ab!",
        b"http://example.com/download",
        b"https://files.example.org/x?id=1",
        b"contact host.example.net now",
        b"peers 10.20.30.40 and 192.168.1.77",
        b"C:\\Windows\\System32\\config\\segment",
        b"/usr/local/bin/traceforge-helper",
        b"HKEY_LOCAL_MACHINE\\Software\\Vendor\\App",
    ]
    wide = "wide-marker-string".encode("utf-16-le")
    return b"\n".join(lines) + b"\n" + wide + b"\x00\x00"


def risky_bytes() -> bytes:
    text_lines = [
        "http://one.example.com/a",
        "http://two.example.com/a",
        "http://three.example.com/a",
        "http://four.example.com/a",
        "http://five.example.com/a",
        "10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5",
        "HKEY_CURRENT_USER\\Software\\TraceForgeTest",
        "L" * 300,
    ]
    # Five full 4096-byte chunks with uniform byte values, then plain text.
    return bytes(range(256)) * 80 + "\n".join(text_lines).encode("ascii")


def test_hashes_size_and_first_bytes():
    data = build_sample()
    result = core.extract(data)
    assert result["size"] == len(data)
    assert result["hashes"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["hashes"]["sha1"] == hashlib.sha1(data).hexdigest()
    assert result["hashes"]["md5"] == hashlib.md5(data).hexdigest()
    assert result["first_bytes_hex"] == data[: core.FIRST_BYTES_LENGTH].hex()


def test_ascii_and_utf16le_strings():
    result = core.extract(build_sample())
    ascii_values = result["strings"]["ascii"]["values"]
    assert "plain ascii marker wxyz" in ascii_values
    assert "ab!" not in ascii_values
    assert all(len(value) >= core.MIN_STRING_LENGTH for value in ascii_values)
    assert result["strings"]["ascii"]["total"] == len(ascii_values)
    assert result["strings"]["utf16le"]["values"] == ["wide-marker-string"]


def test_indicators():
    result = core.extract(build_sample())
    triples = {(i["type"], i["value"], i["source"]) for i in result["indicators"]}
    assert ("url", "http://example.com/download", "ascii") in triples
    assert ("url", "https://files.example.org/x?id=1", "ascii") in triples
    assert ("domain", "example.com", "ascii") in triples
    assert ("domain", "host.example.net", "ascii") in triples
    assert ("ipv4", "10.20.30.40", "ascii") in triples
    assert ("ipv4", "192.168.1.77", "ascii") in triples
    assert ("path", "C:\\Windows\\System32\\config\\segment", "ascii") in triples
    assert ("path", "/usr/local/bin/traceforge-helper", "ascii") in triples
    assert ("registry_path", "HKEY_LOCAL_MACHINE\\Software\\Vendor\\App", "ascii") in triples


def test_entropy_bounds():
    assert core.shannon_entropy(b"") == 0.0
    assert core.shannon_entropy(b"\x00" * 100) == 0.0
    assert core.shannon_entropy(bytes(range(256))) == 8.0


def test_chunk_layout():
    data = b"a" * (core.CHUNK_SIZE * 2 + 100)
    chunks = core.extract(data)["chunks"]
    assert chunks["chunk_size"] == core.CHUNK_SIZE
    assert chunks["total"] == 3
    assert chunks["truncated"] is False
    records = chunks["records"]
    assert [r["offset"] for r in records] == [0, 4096, 8192]
    assert [r["size"] for r in records] == [4096, 4096, 100]
    assert records[0]["entropy"] == 0.0


def test_window_entropy_summary():
    data = bytes(range(256)) * 2
    summary = core.extract(data)["entropy"]["byte_window"]
    assert summary["window_size"] == core.WINDOW_SIZE
    assert summary["count"] == 2
    assert summary["min"] == summary["max"] == summary["mean"] == 8.0


def test_score_low_for_plain_text():
    extraction = core.extract(b"just some harmless words\n" * 20)
    result = score.score_extraction(extraction)
    assert result["score"] == 0
    assert result["label"] == "low"
    assert result["reasons"] == []


def test_score_high_with_evidence():
    extraction = core.extract(risky_bytes())
    result = score.score_extraction(extraction)
    assert result["score"] == 73
    assert result["label"] == "high"
    signals = [reason["signal"] for reason in result["reasons"]]
    assert signals == [
        "urls",
        "ipv4_addresses",
        "high_entropy_chunks",
        "registry_paths",
        "long_strings",
    ]
    for reason in result["reasons"]:
        assert reason["points"] > 0
        assert reason["evidence"]
    # Deterministic: same extraction gives an identical result.
    assert score.score_extraction(extraction) == result


def test_score_labels():
    assert score.label_for(0) == "low"
    assert score.label_for(29) == "low"
    assert score.label_for(30) == "medium"
    assert score.label_for(64) == "medium"
    assert score.label_for(65) == "high"
    assert score.label_for(100) == "high"
