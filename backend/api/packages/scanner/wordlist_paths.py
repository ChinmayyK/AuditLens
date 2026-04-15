"""Shared wordlist resolution for FFUF, Gobuster, and similar tools."""
import os
from pathlib import Path

_BUNDLED = (
    Path(__file__).resolve().parent
    / "wordlists"
    / "ffuf_common.txt"
)


def resolve_scanner_wordlist() -> str | None:
    """Prefer WORDLIST_PATH / image path; fall back to bundled list."""
    candidates = [
        os.environ.get("WORDLIST_PATH", "").strip(),
        "/scanner-tools/wordlists/common.txt",
        str(_BUNDLED),
    ]
    for p in candidates:
        if p and os.path.isfile(p):
            return p
    return None
