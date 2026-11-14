"""Sweep v2 (plan v2 S4): URL/scheme/host intelligence with zero guessing.

Upgrades over the 0.2.0 loop (surface.txt 1C list):
- generic scheme matching (any `x://`) classified, not a whitelist;
- canonical endpoint grouping + fingerprint identity (dedup law);
- user:pass@ capture; IPv6; host:port pairs; percent-encoded flags;
- private/loopback/IDN/dev-host classification as tags;
- base64 candidate decoding with endpoint reconciliation;
- windowed Retrofit annotation state machine (bounded, no unbounded carry);
- per-line lowercasing only (no whole-file lowercase copies);
- precompiled code rules; ±2-line evidence context with size caps;
- header hits carry a code/doc context class.
All established shapes are preserved (endpoints/api_routes/headers/rate
limit structures keep their consumer keys; new keys are additive).
"""
from __future__ import annotations

import base64
import re
from typing import Any

from collections.abc import Callable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

from apkworkbench.analysis.surface.findings import build_finding

# ---- compiled patterns (module scope; PERFORMANCE LAW) --------------------
GENERIC_URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{0,20}://[^\s\"'<>\\]+")
URI_SPECIAL_RE = re.compile(
    r"(?i)\b(mailto|tel|sms|smsto|geo|intent|javascript|market|content|file|package):[^\s\"'<>]+"
)
SCHEME_NAME_RE = re.compile(r"(?i)^([a-z][a-z0-9+.\-]{0,20})://")
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_])"
)
IPV4_RE = re.compile(
    r"(?<![0-9.])(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})"
    r"(?:\.(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}(?![0-9.])"
)
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])("
    r"(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}"
    r"|[A-Fa-f0-9]{0,4}::[0-9A-Fa-f:]{1,32}"
    r")(?![0-9A-Fa-f:])"
)
BRACKET_IPV6_RE = re.compile(r"\[([0-9A-Fa-f:]{2,45})\]")
HOST_PORT_RE = re.compile(
    r"(?<![0-9.])((?:\d{1,3}\.){3}\d{1,3}|(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}):(\d{2,5})(?![0-9])"
)
BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9\-_]{24,}={0,2})(?![A-Za-z0-9+/=_-])"
)
HTTP_METHOD_RE = re.compile(
    r"""(?:@|->)?(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(?\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
ROUTE_RE = re.compile(
    r"""["']((?:/)(?:api(?:/|$)|v[0-9]+(?:/|$)|graphql(?:/|$)|oauth(?:/|$)|auth(?:/|$)|users?(?:/|$)|accounts?(?:/|$)|tokens?(?:/|$)|payments?(?:/|$)|(?:health|status|login|register)(?:/|$))[^"']*)["']""",
    re.IGNORECASE,
)
RETROFIT_ANNOTATION_RE = re.compile(
    r"\.annotation\s+\S+\s+Lretrofit2/http/(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS);"
)
RETROFIT_WINDOW_LINES = 12

PRIVATE_V4_PREFIXES = ("10.", "127.", "169.254.", "192.168.")
PRIVATE_V4_RANGES = tuple(
    f"172.{octet}." for octet in range(16, 32)
)
RESERVED_HOST_SUFFIXES = (".local", ".test", ".invalid", ".example", ".localhost")
DEV_PATH_MARKERS = ("/debug", "/dev", "/dev/", "/staging", "/qa/", "/test", "/swagger")

CODE_SUFFIXES = frozenset({
    ".smali", ".xml", ".json", ".properties", ".java", ".kt", ".gradle",
    ".yml", ".yaml", ".cfg", ".conf", ".ini", ".js", ".css", ".html", ".htm",
})

SNIPPET_CONTEXT_CHARS = 500

# Tooling namespace hosts are build-tool artifacts, not app endpoints
# (evidence: the xmlns declaration they appear in). Skipped at the URL
# recorder level so the endpoint inventory stays app-focused.
TOOLING_URL_HOSTS = frozenset({"schemas.android.com", "www.w3.org"})


def classify_host(host: str | None) -> str | None:
    """Data-driven host class; None means public/undetermined (not hidden)."""
    if not host:
        return None
    lowered = host.lower().rstrip(".")
    if lowered == "localhost":
        return "reserved"
    if ":" in lowered:  # IPv6 shapes
        if lowered in {"::1", "::"} or lowered.startswith(("fe80:", "fc", "fd")):
            return "private"
        return None
    octets = lowered.split(".")
    if len(octets) == 4 and all(octet.isdigit() for octet in octets):
        dotted = lowered + "."
        if dotted.startswith(PRIVATE_V4_PREFIXES) or dotted.startswith(PRIVATE_V4_RANGES):
            return "private"
        return "public_ipv4"
    if any(label.startswith("xn--") for label in octets):
        return "idn"
    if lowered.endswith(RESERVED_HOST_SUFFIXES):
        return "reserved"
    return None


def canonical_url(value: str, parsed) -> str:
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None
    path = parsed.path or ""
    return f"{scheme}://{host}{f':{port}' if port else ''}{path.rstrip('/')}"


def iter_decoded_b64_candidates(line: str) -> Iterator[tuple[str, str]]:
    for match in BASE64_RE.finditer(line):
        raw = match.group(0)
        compact = raw.replace("-", "+").replace("_", "/")
        if len(compact) % 4:
            continue
        try:
            decoded = base64.b64decode(compact, validate=False)
        except (ValueError, base64.binascii.Error):
            continue
        if len(decoded) < 8:
            continue
        printable = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in decoded)
        if printable / len(decoded) < 0.85:
            continue
        yield raw, decoded.decode("latin-1")


class SweepState:
    """Accumulators for one artifact's text sweep (established shapes kept)."""

    def __init__(self, dependency_markers: dict[str, tuple[str, ...]]):
        self.dependency_evidence: dict[str, list[str]] = {
            name: [] for name in dependency_markers
        }
        self.api_endpoints: dict[str, dict] = {}
        self.endpoint_hosts: set[str] = set()
        self.api_routes: dict[str, dict] = {}
        self.api_call_sites: list[dict] = []
        self.api_clients: dict[str, list[dict]] = {}
        self.api_headers: dict[str, list[dict]] = {}
        self.rate_limit_indicators: list[dict] = []
        self.decoded_strings: list[dict] = []
        self.decoded_seen: set[str] = set()
        self.findings: list[dict] = []

    # -- record helpers ---------------------------------------------------------
    def record_endpoint(self, value: str, kind: str, parsed=None, *,
                        host: str | None = None, port: Any = None,
                        path: str | None = None, scheme: str | None = None,
                        evidence: dict) -> None:
        canonical = canonical_url(value, parsed) if parsed is not None else value.lower()
        record = self.api_endpoints.setdefault(canonical, {
            "value": value, "canonical": canonical, "kind": kind,
            "scheme": scheme if scheme is not None else (
                (parsed.scheme or "").lower() if parsed is not None else None
            ),
            "host": host if host is not None else (
                (parsed.hostname or None) if parsed is not None else None
            ),
            "port": port,
            "path": path if path is not None else (
                (parsed.path or None) if parsed is not None else None
            ),
            "query_present": bool(parsed.query) if parsed is not None else None,
            "evidence": [], "occurrences": 0,
            "flags": [],
        })
        record["occurrences"] += 1
        record["evidence"].append(evidence)
        host_value = record.get("host")
        if isinstance(host_value, str):
            self.endpoint_hosts.add(host_value.lower().rstrip("."))
        flags = record["flags"]
        if parsed is not None and (
            "%" in (parsed.path or "") or "%" in (parsed.query or "")
        ) and "percent_encoded" not in flags:
            flags.append("percent_encoded")
        if parsed is not None and parsed.username and "userinfo" not in flags:
                flags.append("userinfo")
                self.findings.append(build_finding(
                    "url_embedded_credentials", "network_security", "info",
                    f"Credentials embedded in URL: {value}",
                    "user:pass@host URL form observed; verify where these credentials "
                    "are constructed and whether they are real.",
                    evidence["path"], evidence.get("line"), value, 0.85,
                ))
        target_path = (parsed.path if parsed is not None else None) or ""
        lowered_path = target_path.lower()
        for marker in DEV_PATH_MARKERS:
            if marker in lowered_path and "dev_path" not in flags:
                flags.append("dev_path")
        record["host_class"] = classify_host(record.get("host"))

    def sweep_text(
        self,
        *,
        relative: str,
        path: Path,
        text: str,
        code_rules: list[tuple[tuple, re.Pattern[str]]],
        api_client_markers: dict[str, tuple[str, ...]],
        api_invoke_owner_re: re.Pattern[str],
        smali_invoke_re: re.Pattern[str],
        header_re: re.Pattern[str],
        rate_limit_re: re.Pattern[str],
        dependency_markers: dict[str, tuple[str, ...]],
        emit: Callable[[str], None],
    ) -> None:
        """Sweep one text file into the accumulators (single pass, per-line)."""
        lines = text.splitlines()
        file_class = "code" if path.suffix.lower() in CODE_SUFFIXES else "doc_or_other"
        annotation_method: str | None = None
        annotation_line: int | None = None
        for line_number, line in enumerate(lines, start=1):
            lowered_line = line.lower()
            for dependency, markers in dependency_markers.items():
                if any(marker.lower() in lowered_line for marker in markers):
                    self.dependency_evidence[dependency].append(relative)

            if RETROFIT_ANNOTATION_RE.search(line):
                annotation_method = RETROFIT_ANNOTATION_RE.search(line).group(1).upper()
                annotation_line = line_number
            if annotation_method is not None and line_number - (annotation_line or 0) <= RETROFIT_WINDOW_LINES:
                value_match = re.search(r"""\bvalue\s*=\s*["']([^"']+)["']""", line)
                if value_match:
                    route = value_match.group(1)
                    record = self.api_routes.setdefault(route, {
                        "path": route, "http_method": annotation_method,
                        "evidence": [], "occurrences": 0,
                    })
                    record["occurrences"] += 1
                    record["evidence"].append({
                        "path": relative, "line": line_number,
                        "source": "retrofit_annotation",
                    })
            if ".end annotation" in line or (
                annotation_method is not None
                and line_number - (annotation_line or 0) > RETROFIT_WINDOW_LINES
            ):
                annotation_method = None

            for match in GENERIC_URL_RE.finditer(line):
                value = match.group(0).rstrip(".,);]}:")
                if not value:
                    continue
                try:
                    parsed = urlsplit(value)
                except ValueError:
                    parsed = None
                if parsed is not None and parsed.hostname:
                    if parsed.hostname.lower().rstrip(".") in TOOLING_URL_HOSTS:
                        continue
                    self.record_endpoint(
                        value, "url", parsed=parsed,
                        evidence={"path": relative, "line": line_number},
                    )
            for match in URI_SPECIAL_RE.finditer(line):
                self.record_endpoint(
                    match.group(0).rstrip(".,);]}:"), "uri_special",
                    scheme=match.group(1).lower(),
                    evidence={"path": relative, "line": line_number},
                )
            for match in IPV6_RE.finditer(line):
                self.record_endpoint(
                    match.group(1), "ipv6_candidate", host=match.group(1),
                    evidence={"path": relative, "line": line_number},
                )
            for match in BRACKET_IPV6_RE.finditer(line):
                self.record_endpoint(
                    match.group(1), "ipv6_candidate", host=match.group(1),
                    evidence={"path": relative, "line": line_number},
                )
            for match in HOST_PORT_RE.finditer(line):
                host, port_text = match.group(1), match.group(2)
                port = int(port_text)
                if not (0 < port <= 65535):
                    continue
                self.record_endpoint(
                    f"{host}:{port_text}", "host_port", host=host, port=port,
                    evidence={"path": relative, "line": line_number},
                )
            for match in HTTP_METHOD_RE.finditer(line):
                method, route = match.group(1).upper(), match.group(2)
                record = self.api_routes.setdefault(route, {
                    "path": route, "http_method": method, "evidence": [], "occurrences": 0,
                })
                record["occurrences"] += 1
                record["evidence"].append({"path": relative, "line": line_number})
            for match in ROUTE_RE.finditer(line):
                route = match.group(1)
                record = self.api_routes.setdefault(route, {
                    "path": route, "http_method": None, "evidence": [], "occurrences": 0,
                })
                record["occurrences"] += 1
                record["evidence"].append({"path": relative, "line": line_number})
            for match in DOMAIN_RE.finditer(line):
                value = match.group(0).lower().rstrip(".")
                if (
                    value
                    and not value.endswith((".xml", ".json", ".png", ".jpg", ".smali"))
                    and value not in self.endpoint_hosts
                ):
                    self.record_endpoint(
                        value, "domain_candidate",
                        evidence={"path": relative, "line": line_number},
                    )
            for match in IPV4_RE.finditer(line):
                self.record_endpoint(
                    match.group(0), "ip_candidate", host=match.group(0),
                    evidence={"path": relative, "line": line_number},
                )
            for raw, decoded in iter_decoded_b64_candidates(line):
                if raw in self.decoded_seen:
                    continue
                self.decoded_seen.add(raw)
                hits = list(GENERIC_URL_RE.finditer(decoded)) + list(DOMAIN_RE.finditer(decoded))
                if not hits:
                    continue
                self.decoded_strings.append({
                    "encoded": raw,
                    "decoded": decoded,
                    "reveals": [hit.group(0).rstrip(".,);]}:") for hit in hits],
                    "path": relative, "line": line_number,
                })
                self.findings.append(build_finding(
                    "encoded_string_decoded", "secrets_hint", "info",
                    "Base64-encoded string decodes to a network indicator",
                    f"Encoded literal decoded; reveals: {', '.join(h.group(0) for h in hits[:3])}",
                    relative, line_number, raw, 0.7,
                ))
            if path.suffix.lower() == ".smali":
                invoke = smali_invoke_re.search(line)
                if invoke and api_invoke_owner_re.match(invoke.group(1)):
                    self.api_call_sites.append({
                        "owner": invoke.group(1),
                        "method": invoke.group(2),
                        "arguments": invoke.group(3),
                        "return_type": invoke.group(4),
                        "path": relative,
                        "line": line_number,
                        "snippet": line.strip(),
                    })
            for client, patterns in api_client_markers.items():
                if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
                    self.api_clients[client].append({
                        "path": relative, "line": line_number, "snippet": line.strip(),
                    })
            for header_match in header_re.finditer(line):
                header = header_match.group(1)
                self.api_headers.setdefault(header.lower(), []).append({
                    "path": relative, "line": line_number, "context_class": file_class,
                })
            if rate_limit_re.search(line):
                self.rate_limit_indicators.append({
                    "path": relative, "line": line_number, "snippet": line.strip(),
                })

            suffix = path.suffix.lower()
            if suffix in {".smali", ".xml", ".js", ".java", ".kt", ".json",
                          ".properties", ".html", ".htm"}:
                for (rule_id, category, severity, title, _pattern,
                     confidence, rationale), compiled in code_rules:
                    if compiled.search(line):
                        context_start = max(0, line_number - 3)
                        context = "\n".join(lines[context_start:line_number + 2])
                        self.findings.append(build_finding(
                            rule_id, category, severity, title, rationale,
                            relative, line_number, line, confidence,
                        ))
                        # context is additive evidence (never replaces the
                        # compat snippet); capped to keep summaries lean
                        self.findings[-1]["evidence"]["context"] = (
                            context[:SNIPPET_CONTEXT_CHARS]
                        )
        del lines