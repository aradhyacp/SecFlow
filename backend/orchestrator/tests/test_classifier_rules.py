"""Baseline tests for deterministic classifier routing (Step 1)."""

from __future__ import annotations

import pytest

from app.classifier.rules import apply_rules


def _route(mime: str, magic_output: str, raw: str) -> str | None:
    return apply_rules(mime, magic_output, raw)


@pytest.mark.parametrize(
    ("mime", "magic_output", "raw"),
    [
        ("image/png", "PNG image data, 100 x 100", "sample.png"),
        ("image/jpeg", "JPEG image data", "sample.jpg"),
        ("image/gif", "GIF image data", "sample.gif"),
        ("application/octet-stream", "PNG image data, 100 x 100", "sample.bin"),
    ],
)
def test_images_route_to_steg(mime: str, magic_output: str, raw: str) -> None:
    assert _route(mime, magic_output, raw) == "steg"


@pytest.mark.parametrize(
    ("mime", "magic_output", "raw"),
    [
        ("application/msword", "Composite Document File V2", "a.doc"),
        ("application/vnd.ms-excel", "Composite Document File V2", "a.xls"),
        ("application/vnd.ms-powerpoint", "Composite Document File V2", "a.ppt"),
        (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "Microsoft Word 2007+",
            "a.docx",
        ),
        ("application/rtf", "Rich Text Format data", "a.rtf"),
        ("application/zip", "Zip archive data", "a.docm"),
    ],
)
def test_office_and_rtf_route_to_macro(mime: str, magic_output: str, raw: str) -> None:
    assert _route(mime, magic_output, raw) == "macro"


@pytest.mark.parametrize(
    ("mime", "magic_output", "raw"),
    [
        ("application/x-dosexec", "PE32 executable (GUI) Intel 80386", "sample.exe"),
        ("application/x-executable", "ELF 64-bit LSB executable", "sample.out"),
        ("application/octet-stream", "Mach-O 64-bit executable x86_64", "sample.bin"),
        ("application/octet-stream", "PE32+ executable (console) x86-64", "sample.bin"),
    ],
)
def test_binaries_route_to_malware(mime: str, magic_output: str, raw: str) -> None:
    assert _route(mime, magic_output, raw) == "malware"


def test_url_wins_over_domain_rule() -> None:
    # Regression guard: "https://example.com" must not match the domain rule.
    assert _route("text/plain", "https://example.com", "https://example.com/a") == "web"
    assert _route("text/plain", "EXAMPLE.COM", "HTTPS://EXAMPLE.COM") == "web"


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "192.168.100.200"])
def test_ipv4_routes_to_recon(ip: str) -> None:
    assert _route("text/plain", ip, ip) == "recon"


@pytest.mark.parametrize("domain", ["example.com", "sub.example.co.uk", "a-b.example.io"])
def test_domain_routes_to_recon(domain: str) -> None:
    assert _route("text/plain", domain, domain) == "recon"


@pytest.mark.parametrize(
    ("mime", "magic_output", "raw"),
    [
        ("text/plain", "plain text", "hello world"),
        ("text/plain", "plain text", "a@b.com"),
        ("text/plain", "plain text", "not a domain"),
        ("text/plain", "plain text", "999.999.999.999"),
    ],
)
def test_unknown_inputs_return_none_for_ai_fallback(
    mime: str, magic_output: str, raw: str
) -> None:
    assert _route(mime, magic_output, raw) is None
