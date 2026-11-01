"""Baseline contract tests for analyzer adapters (Step 1).

Each adapter translates a raw analyzer response into the SecFlow contract:

    {analyzer, pass, input, findings, risk_score, raw_output}

The fixtures live in docs/ts-migration/fixtures so the TypeScript port can be
tested against the exact same payloads.
"""

from __future__ import annotations

from typing import Any

from conftest import load_fixture

from app.adapters import macro_adapter, malware_adapter, recon_adapter, steg_adapter, url_adapter, web_adapter


def _assert_contract(result: dict[str, Any], analyzer: str, pass_number: int) -> None:
    assert result["analyzer"] == analyzer
    assert result["pass"] == pass_number
    assert isinstance(result["input"], str)
    assert isinstance(result["findings"], list)
    assert 0.0 <= float(result["risk_score"]) <= 10.0
    assert isinstance(result["raw_output"], str)
    for finding in result["findings"]:
        assert set(finding) >= {"type", "detail", "severity"}
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}


def test_malware_detected_contract() -> None:
    raw = {
        "vt": load_fixture("malware-file-analysis.json"),
        "decompile": load_fixture("malware-decompile.json"),
    }
    result = malware_adapter.adapt(raw, 1, "/tmp/sample.exe")
    _assert_contract(result, "malware", 1)

    types = [f["type"] for f in result["findings"]]
    assert "malware_detection" in types
    assert "decompilation" in types
    assert "disassembly" in types
    assert result["risk_score"] == 10.0  # capped at 10

    detection = next(f for f in result["findings"] if f["type"] == "malware_detection")
    assert detection["severity"] == "critical"
    assert "7 malicious" in detection["detail"]

    # Raw output must carry the full decompiled source (used by the AI router).
    assert "Ghidra decompiled" in result["raw_output"]
    assert "entry(void)" in result["raw_output"]


def test_malware_clean_contract() -> None:
    raw = {
        "vt": load_fixture("malware-file-analysis-clean.json"),
        "decompile": {"success": False, "error": "Ghidra timed out"},
    }
    result = malware_adapter.adapt(raw, 2, "/tmp/sample.out")
    _assert_contract(result, "malware", 2)

    detection = next(f for f in result["findings"] if f["type"] == "malware_detection")
    assert detection["severity"] == "info"
    assert "no detections" in detection["detail"]
    assert any(f["type"] == "error" for f in result["findings"])


def test_steg_contract() -> None:
    result = steg_adapter.adapt(load_fixture("steg-result.json"), 2, "/tmp/sample.png")
    _assert_contract(result, "steg", 2)

    assert result["extracted_files"] == ["/download/abc123/binwalk/embedded.zip"]
    binwalk = next(f for f in result["findings"] if f["type"] == "steg_detection")
    assert binwalk["severity"] == "critical"
    # Errored tools are logged in raw_output but must not become findings.
    assert "zsteg" not in {f["type"] for f in result["findings"]}
    assert "status=error" in result["raw_output"]


def test_steg_empty_payload_is_valid() -> None:
    result = steg_adapter.adapt({}, 1, "/tmp/sample.png")
    _assert_contract(result, "steg", 1)
    assert result["findings"] == []
    assert result["risk_score"] == 0.0


def test_recon_scan_contract() -> None:
    result = recon_adapter.adapt(load_fixture("recon-scan.json"), 2, "recongraph.xyz")
    _assert_contract(result, "recon", 2)

    types = [f["type"] for f in result["findings"]]
    assert "geolocation" in types
    assert "blocklist_check" in types
    assert "ioc_match" in types
    ioc = next(f for f in result["findings"] if f["type"] == "ioc_match")
    assert ioc["severity"] == "critical"
    assert "MintsLoader" in ioc["detail"]


def test_recon_footprint_email_contract() -> None:
    result = recon_adapter.adapt(load_fixture("recon-footprint-email.json"), 2, "analyst@example.org")
    _assert_contract(result, "recon", 2)

    breach = next(f for f in result["findings"] if f["type"] == "email_breach")
    assert breach["severity"] == "critical"
    assert "12 breach" in breach["detail"]


def test_recon_unknown_payload_falls_back_to_raw() -> None:
    result = recon_adapter.adapt({}, 3, "8.8.8.8")
    _assert_contract(result, "recon", 3)
    assert result["findings"] == []
    assert "Recon analysis for: 8.8.8.8" in result["raw_output"]


def test_web_contract() -> None:
    result = web_adapter.adapt(load_fixture("web-aggregated.json"), 3, "https://recongraph.xyz")
    _assert_contract(result, "web", 3)

    missing = [f for f in result["findings"] if f["type"] == "missing_security_header"]
    assert len(missing) == 7
    csp = next(f for f in missing if f["evidence"] == "Content-Security-Policy")
    assert csp["severity"] == "high"
    assert any(f["type"] == "url_clean" for f in result["findings"])
    assert any(f["type"] == "missing_hsts" for f in result["findings"])


def test_macro_contract() -> None:
    result = macro_adapter.adapt(load_fixture("macro-analyze.json"), 1, "/tmp/invoice.docm")
    _assert_contract(result, "macro", 1)

    assert result["risk_score"] == 9.5
    verdict = next(f for f in result["findings"] if f["type"] == "macro_malicious")
    assert verdict["severity"] == "critical"
    assert any(f["type"] == "macro_source" for f in result["findings"])
    # IOCs must be surfaced in raw_output so follow-up routing can find them.
    assert "http://recongraph.xyz/payload.exe" in result["raw_output"]


def test_url_adapter_contract() -> None:
    result = url_adapter.adapt({"example": "value"}, 1, "https://example.com")
    _assert_contract(result, "url", 1)
    assert result["findings"][0]["type"] == "url_analysis"
