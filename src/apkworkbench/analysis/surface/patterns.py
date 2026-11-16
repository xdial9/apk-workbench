"""Shared scan patterns (P0c) — one definition, no drifting copies.

`DOMAIN_RE` existed three times: hardened in ``sweep``, plain in
``apk_surface`` (unused) and plain in ``androguard_dex`` (used on
attacker-controlled DEX strings). The plain form backtracks on a hostile
multi-kilobyte label run. Keeping the pattern here means the DEX pass and the
text sweep can never disagree about what a domain is.
"""
from __future__ import annotations

import re

DOMAIN_RE = re.compile(
    # ReDoS-hardened (S7 finding): the unbounded (label dot)+ structure is
    # possessive so a hostile multi-kilobyte label run cannot backtrack;
    # inner label quantifiers stay plain (bounded <=63, no blowup).
    r"(?<![A-Za-z0-9_])"
    r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?+)\.++)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_])"
)

__all__ = ["DOMAIN_RE"]
