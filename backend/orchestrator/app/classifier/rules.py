"""
Deterministic routing rules for the Input Classifier.

Rules are evaluated in order. The first matching rule wins.
Each rule is a tuple of (condition_fn, analyzer_name).
condition_fn(mime_type, magic_output, raw_input) -> bool
"""

import re

# URL must be checked before domain so https://example.com doesn't match domain rule
RULES: list[tuple] = [
    # Images → Steganography Analyzer
    (
        lambda mime, magic, raw: mime.startswith("image/")
        or any(
            kw in magic.upper()
            for kw in ("PNG", "JPEG", "GIF", "BMP", "TIFF", "WEBP")
        ),
        "steg",
    ),

    # Executables / PE / ELF binaries → Malware Analyzer
    (
        lambda mime, magic, raw: mime in (
            "application/x-executable",
            "application/x-dosexec",
            "application/x-msdos-program",
            "application/x-elf",
            "application/vnd.microsoft.portable-executable",
            "application/octet-stream",
        )
        and any(
            kw in magic
            for kw in ("PE32", "ELF", "Mach-O", "MS-DOS", "MS Windows")
        ),
        "malware",
    ),
    (
        lambda mime, magic, raw: any(
            kw in magic for kw in ("PE32", "ELF", "Mach-O", "MS-DOS executable")
        ),
        "malware",
    ),

    # Valid URL string → Web Vulnerability Analyzer
    (
        lambda mime, magic, raw: bool(
            re.match(r"^https?://", raw.strip(), re.IGNORECASE)
        ),
        "web",
    ),

    # Valid IPv4 address → Reconnaissance Analyzer
    (
        lambda mime, magic, raw: bool(
            re.match(
                r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
                r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                raw.strip(),
            )
        ),
        "recon",
    ),

    # Valid domain name → Reconnaissance Analyzer
    (
        lambda mime, magic, raw: bool(
            re.match(
                r"^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$",
                raw.strip(),
            )
        ),
        "recon",
    ),
]


def apply_rules(mime_type: str, magic_output: str, raw_input: str) -> str | None:
    """
    Evaluate rules in order and return the first matching analyzer name.
    Returns None if no rule matches (AI fallback required).
    """
    for condition, analyzer in RULES:
        try:
            if condition(mime_type, magic_output, raw_input):
                return analyzer
        except Exception:
            continue
    return None
