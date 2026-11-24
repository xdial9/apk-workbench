"""APK Signature Scheme v1 (JAR) cryptographic verification."""
from __future__ import annotations

import base64
import hashlib
import zipfile
from pathlib import Path
from typing import Any

from apkworkbench.security.models import ApkSignatureError
from apkworkbench.security.pkcs7 import verify_pkcs7_signature

V1_BLOCK_SUFFIXES = (".RSA", ".DSA", ".EC")

# JAR manifest digest attribute prefixes -> hashlib algorithm name
DIGEST_ATTR_PREFIXES: tuple[tuple[str, str], ...] = (
    ("SHA-512", "sha512"),
    ("SHA-384", "sha384"),
    ("SHA-256", "sha256"),
    ("SHA-1", "sha1"),
    ("SHA1", "sha1"),
)


def _split_lines_keepends(raw: bytes) -> list[bytes]:
    """Split raw manifest bytes into lines preserving exact line endings."""
    lines: list[bytes] = []
    i = 0
    n = len(raw)
    while i < n:
        cr = raw.find(b"\r", i)
        lf = raw.find(b"\n", i)
        if cr == -1 and lf == -1:
            lines.append(raw[i:])
            break
        if cr != -1 and (lf == -1 or cr < lf):
            end = cr + 2 if (cr + 1 < n and raw[cr + 1:cr + 2] == b"\n") else cr + 1
        else:
            end = lf + 1
        lines.append(raw[i:end])
        i = end
    return lines


def _strip_eol(line: bytes) -> bytes:
    if line.endswith(b"\r\n"):
        return line[:-2]
    if line.endswith((b"\n", b"\r")):
        return line[:-1]
    return line


def _parse_section_attrs(section_bytes: bytes) -> dict[str, str]:
    """Parse RFC822-style manifest attributes with single-space continuation lines."""
    raw_lines = [_strip_eol(line) for line in _split_lines_keepends(section_bytes)]
    unfolded: list[bytes] = []
    for line in raw_lines:
        if not line:
            continue
        if line.startswith(b" "):
            if not unfolded:
                raise ApkSignatureError("Manifest continuation line without header")
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    attrs: dict[str, str] = {}
    for raw_entry in unfolded:
        sep = raw_entry.find(b":")
        if sep <= 0:
            raise ApkSignatureError(f"Malformed manifest header line: {raw_entry!r}")
        key = raw_entry[:sep].decode("utf-8", errors="strict").strip()
        value = raw_entry[sep + 1:].decode("utf-8", errors="strict").lstrip(" ")
        attrs[key] = value
    return attrs


def _parse_manifest_sections(
    raw: bytes,
) -> tuple[bytes, dict[str, str], dict[str, tuple[bytes, dict[str, str]]]]:
    """Parse MANIFEST.MF or .SF returning (main_bytes, main_attrs, entries).

    Each entry maps ``Name`` -> ``(raw_section_bytes, parsed_attrs)`` preserving the
    exact raw section bytes (including its trailing blank line) for .SF digest checks.
    """
    lines = _split_lines_keepends(raw)
    sections_raw: list[bytes] = []
    buf: list[bytes] = []
    in_section = False
    for line in lines:
        stripped = _strip_eol(line)
        if not stripped:
            if in_section:
                buf.append(line)
                sections_raw.append(b"".join(buf))
                buf = []
                in_section = False
        else:
            buf.append(line)
            in_section = True
    if in_section and buf:
        sections_raw.append(b"".join(buf))

    if not sections_raw:
        raise ApkSignatureError("Manifest file is empty")

    main_bytes = sections_raw[0]
    main_attrs = _parse_section_attrs(main_bytes)
    entries: dict[str, tuple[bytes, dict[str, str]]] = {}
    for sec in sections_raw[1:]:
        attrs = _parse_section_attrs(sec)
        name = attrs.get("Name")
        if not name:
            raise ApkSignatureError("Manifest individual section missing 'Name'")
        if name in entries:
            raise ApkSignatureError(f"Duplicate manifest section for entry: {name}")
        entries[name] = (sec, attrs)
    return main_bytes, main_attrs, entries


def _is_jar_signature_file(name: str) -> bool:
    """Return True if ``name`` is a JAR signature metadata file exempt from MANIFEST.MF."""
    upper = name.upper()
    if not upper.startswith("META-INF/"):
        return False
    rel = upper[len("META-INF/"):]
    if "/" in rel:
        return False
    if rel == "MANIFEST.MF":
        return True
    if rel.startswith("SIG-"):
        return True
    return rel.endswith((".SF", ".RSA", ".DSA", ".EC"))


def _extract_digests(attrs: dict[str, str], suffix: str) -> list[tuple[str, str]]:
    """Extract (hashlib_alg, expected_b64) pairs for attributes ending in ``suffix``."""
    found: list[tuple[str, str]] = []
    upper_map = {k.upper(): v for k, v in attrs.items()}
    for prefix, alg in DIGEST_ATTR_PREFIXES:
        key = f"{prefix}{suffix}".upper()
        if key in upper_map:
            found.append((alg, upper_map[key].strip()))
    return found


def _check_digest_bytes(data: bytes, alg: str, expected_b64: str, label: str) -> None:
    actual_b64 = base64.b64encode(hashlib.new(alg, data).digest()).decode("ascii")
    if actual_b64 != expected_b64:
        raise ApkSignatureError(
            f"v1 {alg.upper()} digest mismatch for {label}"
        )


def _verify_sf_against_manifest(
    sf_name: str,
    sf_bytes: bytes,
    manifest_raw: bytes,
    manifest_main_bytes: bytes,
    manifest_entries: dict[str, tuple[bytes, dict[str, str]]],
) -> dict[str, Any]:
    _sf_main_bytes, sf_main_attrs, sf_entries = _parse_manifest_sections(sf_bytes)

    manifest_digests = _extract_digests(sf_main_attrs, "-Digest-Manifest")
    main_attr_digests = _extract_digests(sf_main_attrs, "-Digest-Manifest-Main-Attributes")

    for alg, expected_b64 in manifest_digests:
        _check_digest_bytes(manifest_raw, alg, expected_b64, f"{sf_name}:Manifest")
    for alg, expected_b64 in main_attr_digests:
        _check_digest_bytes(
            manifest_main_bytes, alg, expected_b64, f"{sf_name}:Main-Attributes"
        )

    for entry_name, (_sf_sec_bytes, sf_attrs) in sf_entries.items():
        if entry_name not in manifest_entries:
            raise ApkSignatureError(f"{sf_name} references missing MANIFEST.MF entry: {entry_name}")
        entry_digests = _extract_digests(sf_attrs, "-Digest")
        if not entry_digests:
            raise ApkSignatureError(f"{sf_name} entry {entry_name} has no supported digest")
        manifest_sec_bytes = manifest_entries[entry_name][0]
        for alg, expected_b64 in entry_digests:
            _check_digest_bytes(manifest_sec_bytes, alg, expected_b64, f"{sf_name}:{entry_name}")

    if not manifest_digests:
        # Without whole-manifest digest, every MANIFEST.MF entry must be explicitly verified in .SF.
        if not main_attr_digests:
            raise ApkSignatureError(
                f"{sf_name} lacks both *-Digest-Manifest and *-Digest-Manifest-Main-Attributes"
            )
        missing_sf = set(manifest_entries) - set(sf_entries)
        if missing_sf:
            raise ApkSignatureError(
                f"{sf_name} omits MANIFEST.MF entries without *-Digest-Manifest: {sorted(missing_sf)[:5]}"
            )

    x_apk_signed_raw = sf_main_attrs.get("X-Android-APK-Signed", "")
    x_apk_signed: list[int] = []
    if x_apk_signed_raw:
        for token in x_apk_signed_raw.split(","):
            tok = token.strip()
            if tok:
                try:
                    x_apk_signed.append(int(tok))
                except ValueError:
                    raise ApkSignatureError(
                        f"{sf_name} has invalid X-Android-APK-Signed value: {tok!r}"
                    )

    return {
        "sf_file": sf_name,
        "manifest_digest_checked": bool(manifest_digests),
        "main_attributes_digest_checked": bool(main_attr_digests),
        "sf_entry_count": len(sf_entries),
        "x_android_apk_signed": x_apk_signed,
    }


def verify_v1_jar_signature(apk_path: Path) -> dict[str, Any]:
    """Verify APK Signature Scheme v1 (JAR) signatures and entry digests."""
    result: dict[str, Any] = {
        "scheme": "v1",
        "present": False,
        "verified": False,
        "status": "not_present",
        "signers": [],
        "certificates": [],
        "entries_verified": 0,
        "x_android_apk_signed": [],
        "errors": [],
    }
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                result["present"] = True
                result["status"] = "failed"
                result["errors"].append("ZIP archive contains duplicate entry names")
                return result

            manifest_candidates = [n for n in names if n.upper() == "META-INF/MANIFEST.MF"]
            sf_files: dict[str, str] = {}
            block_files: dict[str, str] = {}
            for name in sorted(names):
                upper = name.upper()
                if not upper.startswith("META-INF/"):
                    continue
                rel = upper[len("META-INF/"):]
                if "/" in rel:
                    continue
                if rel.endswith(".SF"):
                    stem = rel[:-3]
                    if stem in sf_files:
                        result["present"] = True
                        result["status"] = "failed"
                        result["errors"].append(f"Duplicate .SF file stem: {stem}")
                        return result
                    sf_files[stem] = name
                elif rel.endswith(V1_BLOCK_SUFFIXES):
                    stem = rel.rsplit(".", 1)[0]
                    if stem in block_files:
                        result["present"] = True
                        result["status"] = "failed"
                        result["errors"].append(f"Duplicate signature block stem: {stem}")
                        return result
                    block_files[stem] = name

            if not sf_files and not block_files:
                return result

            result["present"] = True
            if not manifest_candidates:
                result["status"] = "failed"
                result["errors"].append("Signature files present without META-INF/MANIFEST.MF")
                return result
            if len(manifest_candidates) > 1:
                result["status"] = "failed"
                result["errors"].append("Multiple META-INF/MANIFEST.MF entries present")
                return result
            if set(sf_files) != set(block_files):
                result["status"] = "failed"
                result["errors"].append(
                    f"Mismatched .SF and signature block files: sf={sorted(sf_files)}, blocks={sorted(block_files)}"
                )
                return result

            manifest_raw = zf.read(manifest_candidates[0])
            manifest_main_bytes, _manifest_main_attrs, manifest_entries = _parse_manifest_sections(
                manifest_raw
            )

            # Verify every protected ZIP entry is covered by MANIFEST.MF and matches its digests.
            protected_names = [n for n in names if not _is_jar_signature_file(n)]
            missing_from_manifest = sorted(set(protected_names) - set(manifest_entries))
            if missing_from_manifest:
                raise ApkSignatureError(
                    f"Unsigned ZIP entries missing from MANIFEST.MF: {missing_from_manifest[:5]}"
                )
            extra_in_manifest = sorted(set(manifest_entries) - set(protected_names))
            if extra_in_manifest:
                raise ApkSignatureError(
                    f"MANIFEST.MF references entries absent from ZIP: {extra_in_manifest[:5]}"
                )
            for entry_name in protected_names:
                _sec_bytes, attrs = manifest_entries[entry_name]
                digests = _extract_digests(attrs, "-Digest")
                if not digests:
                    raise ApkSignatureError(
                        f"MANIFEST.MF entry {entry_name} has no supported digest attribute"
                    )
                entry_bytes = zf.read(entry_name)
                for alg, expected_b64 in digests:
                    _check_digest_bytes(entry_bytes, alg, expected_b64, f"MANIFEST.MF:{entry_name}")

            # Verify every (.SF, block) signer pair.
            seen_certs: dict[str, dict[str, Any]] = {}
            x_apk_signed_all: set[int] = set()
            for stem in sorted(sf_files):
                sf_name = sf_files[stem]
                block_name = block_files[stem]
                sf_bytes = zf.read(sf_name)
                block_bytes = zf.read(block_name)

                pkcs7_res = verify_pkcs7_signature(block_bytes, sf_bytes)
                sf_res = _verify_sf_against_manifest(
                    sf_name, sf_bytes, manifest_raw, manifest_main_bytes, manifest_entries
                )
                x_apk_signed_all.update(sf_res["x_android_apk_signed"])
                for cert in pkcs7_res["certificates"]:
                    seen_certs.setdefault(cert["sha256"], cert)
                result["signers"].append({
                    "stem": stem,
                    "sf_file": sf_name,
                    "block_file": block_name,
                    "pkcs7": pkcs7_res,
                    "sf": sf_res,
                })

            result["entries_verified"] = len(protected_names)
            result["certificates"] = list(seen_certs.values())
            result["x_android_apk_signed"] = sorted(x_apk_signed_all)
            result["verified"] = True
            result["status"] = "verified"
            return result
    except (ApkSignatureError, zipfile.BadZipFile, OSError, UnicodeDecodeError) as exc:
        result["present"] = True
        result["verified"] = False
        result["status"] = "failed"
        result["errors"].append(f"{type(exc).__name__}: {exc}")
        return result
