"""APK identity and signing facts (P1) — who signed this, with what, for which ABI.

The dossier must not guess an app's identity. Until now the scanner never
opened the APK's own signature: it knew the Play download hash (acquisition)
but not the certificate, the signing scheme, or the shipped ABI set.

Everything here is stdlib: a bounds-checked DER reader, the APK Signing Block
(v2/v3), the v1 PKCS#7 certificate, and the zip central directory. No
`cryptography` dependency, no shelling out to `apksigner`.

Laws obeyed:
  * a certificate is cited by the SHA-256 of its DER bytes, never by a name;
  * an unparseable structure returns a reason, not an empty success;
  * no time-dependent verdicts (a "certificate expired" finding would flip
    with the clock and break determinism) — dates are facts, not findings.
"""
from __future__ import annotations

import hashlib
import struct
import zipfile
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.findings import build_finding

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
MAX_BLOCK_BYTES = 8 * 1024 * 1024
MAX_CERT_BYTES = 1024 * 1024
EOCD_TAIL_BYTES = 66_000

SCHEME_V2 = "v2"
SCHEME_V3 = "v3"
SCHEME_V31 = "v3.1"
SCHEME_V1 = "v1"

# DER tags used by X.509.
TAG_INTEGER = 0x02
TAG_BITSTRING = 0x03
TAG_OID = 0x06
TAG_UTF8 = 0x0C
TAG_PRINTABLE = 0x13
TAG_TELETEX = 0x14
TAG_IA5 = 0x16
TAG_UTCTIME = 0x17
TAG_GENERALIZED = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_BMP = 0x1E
TAG_CONTEXT_0 = 0xA0

NAME_OIDS = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.97": "organizationIdentifier",
    "1.2.840.113549.1.9.1": "emailAddress",
}

V1_SIGNATURE_SUFFIXES = (".RSA", ".DSA", ".EC")


class DerError(ValueError):
    """Raised when a DER structure is truncated or malformed."""


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) for the TLV at ``offset``."""
    if offset + 2 > len(data):
        raise DerError("truncated header")
    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4:
            raise DerError(f"unsupported length form ({count} bytes)")
        if cursor + count > len(data):
            raise DerError("truncated length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    else:
        length = length_byte
    end = cursor + length
    if end > len(data):
        raise DerError("truncated value")
    return tag, cursor, end


def _walk(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    """Walk one level of TLVs: (tag, tag_offset, value_start, value_end)."""
    items: list[tuple[int, int, int, int]] = []
    cursor = start
    while cursor < end:
        tag, value_start, value_end = _tlv(data, cursor)
        if value_end > end:
            raise DerError("child overruns its parent")
        items.append((tag, cursor, value_start, value_end))
        cursor = value_end
    return items


def _oid(data: bytes, start: int, end: int) -> str:
    if start >= end:
        raise DerError("empty OID")
    first = data[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _text(data: bytes, tag: int, start: int, end: int) -> str:
    raw = data[start:end]
    if tag == TAG_BMP:
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _time(data: bytes, tag: int, start: int, end: int) -> str:
    raw = data[start:end].decode("ascii", errors="replace").strip()
    if tag == TAG_UTCTIME and len(raw) >= 12 and raw.endswith("Z"):
        year = int(raw[0:2])
        year += 2000 if year < 50 else 1900
        return f"{year:04d}-{raw[2:4]}-{raw[4:6]}T{raw[6:8]}:{raw[8:10]}:{raw[10:12]}Z"
    if tag == TAG_GENERALIZED and len(raw) >= 14 and raw.endswith("Z"):
        return f"{raw[0:4]}-{raw[4:6]}-{raw[6:8]}T{raw[8:10]}:{raw[10:12]}:{raw[12:14]}Z"
    return raw


def parse_name(data: bytes, start: int, end: int) -> dict[str, str]:
    """RDNSequence -> {"CN": ..., "O": ...} (multiple values joined by ', ')."""
    name: dict[str, str] = {}
    for tag, _offset, set_start, set_end in _walk(data, start, end):
        if tag != TAG_SET:
            continue
        for rdn_tag, _rdn_offset, rdn_start, rdn_end in _walk(data, set_start, set_end):
            if rdn_tag != TAG_SEQUENCE:
                continue
            pair = _walk(data, rdn_start, rdn_end)
            if len(pair) != 2:
                continue
            oid_tag, _, oid_start, oid_end = pair[0]
            value_tag, _, value_start, value_end = pair[1]
            if oid_tag != TAG_OID:
                continue
            key = NAME_OIDS.get(_oid(data, oid_start, oid_end), _oid(data, oid_start, oid_end))
            value = _text(data, value_tag, value_start, value_end)
            if key in name:
                name[key] = f"{name[key]}, {value}"
            else:
                name[key] = value
    return name


def _name_text(name: dict[str, str]) -> str:
    order = ("CN", "O", "OU", "C", "L", "ST", "emailAddress", "serialNumber")
    parts = [f"{key}={name[key]}" for key in order if key in name]
    parts.extend(
        f"{key}={value}" for key, value in sorted(name.items()) if key not in order
    )
    return ", ".join(parts)


def parse_certificate(der: bytes) -> dict[str, Any]:
    """Parse one X.509 certificate. Raises DerError on malformed input."""
    tag, start, end = _tlv(der, 0)
    if tag != TAG_SEQUENCE:
        raise DerError("certificate is not a SEQUENCE")
    outer = _walk(der, start, end)
    if not outer:
        raise DerError("empty certificate")
    tbs_tag, _tbs_offset, tbs_start, tbs_end = outer[0]
    if tbs_tag != TAG_SEQUENCE:
        raise DerError("tbsCertificate is not a SEQUENCE")
    fields = _walk(der, tbs_start, tbs_end)
    cursor = 0
    version = 1
    if fields and fields[0][0] == TAG_CONTEXT_0:
        version = 3  # only v3 is legal with the explicit tag; the int is inside
        cursor = 1
    serial = ""
    if cursor < len(fields) and fields[cursor][0] == TAG_INTEGER:
        _tag, _offset, value_start, value_end = fields[cursor]
        serial = hex(int.from_bytes(der[value_start:value_end], "big"))
        cursor += 1
    cursor += 1  # signature AlgorithmIdentifier
    issuer: dict[str, str] = {}
    if cursor < len(fields) and fields[cursor][0] == TAG_SEQUENCE:
        _tag, _offset, value_start, value_end = fields[cursor]
        issuer = parse_name(der, value_start, value_end)
        cursor += 1
    not_before = not_after = ""
    if cursor < len(fields) and fields[cursor][0] == TAG_SEQUENCE:
        _tag, _offset, value_start, value_end = fields[cursor]
        times = _walk(der, value_start, value_end)
        if len(times) >= 2:
            not_before = _time(der, times[0][0], times[0][2], times[0][3])
            not_after = _time(der, times[1][0], times[1][2], times[1][3])
        cursor += 1
    subject: dict[str, str] = {}
    if cursor < len(fields) and fields[cursor][0] == TAG_SEQUENCE:
        _tag, _offset, value_start, value_end = fields[cursor]
        subject = parse_name(der, value_start, value_end)
        cursor += 1
    public_key_algorithm = ""
    if cursor < len(fields) and fields[cursor][0] == TAG_SEQUENCE:
        _tag, _offset, value_start, value_end = fields[cursor]
        inner = _walk(der, value_start, value_end)
        if inner and inner[0][0] == TAG_OID:
            public_key_algorithm = _oid(der, inner[0][2], inner[0][3])
    signature_algorithm = ""
    if len(outer) >= 2 and outer[1][0] == TAG_SEQUENCE:
        inner = _walk(der, outer[1][2], outer[1][3])
        if inner and inner[0][0] == TAG_OID:
            signature_algorithm = _oid(der, inner[0][2], inner[0][3])
    subject_text = _name_text(subject)
    issuer_text = _name_text(issuer)
    return {
        "sha256": hashlib.sha256(der).hexdigest(),
        "subject": subject,
        "subject_text": subject_text,
        "issuer": issuer,
        "issuer_text": issuer_text,
        "serial": serial,
        "version": version,
        "not_before": not_before,
        "not_after": not_after,
        "public_key_algorithm": public_key_algorithm,
        "signature_algorithm": signature_algorithm,
        "self_issued": bool(subject_text) and subject_text == issuer_text,
    }


# ---- APK Signing Block (v2/v3) --------------------------------------------


def _lp(data: bytes, offset: int) -> tuple[bytes, int]:
    """Read one little-endian uint32 length-prefixed chunk."""
    if offset + 4 > len(data):
        raise DerError("truncated length prefix")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise DerError("length prefix overruns the block")
    return data[start:end], end


def _signing_block(path: Path) -> tuple[dict[int, bytes], str]:
    """Return ({block_id: value}, status). Reads only the block, never the APK."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - EOCD_TAIL_BYTES))
        tail = handle.read()
        position = tail.rfind(b"PK\x05\x06")
        if position < 0 or position + 22 > len(tail):
            return {}, "no_eocd"
        cd_offset = struct.unpack_from("<I", tail, position + 16)[0]
        if cd_offset < 32 or cd_offset > size:
            return {}, "no_signing_block"
        handle.seek(cd_offset - 24)
        footer = handle.read(24)
        if len(footer) != 24 or footer[8:] != APK_SIG_BLOCK_MAGIC:
            return {}, "no_signing_block"
        block_size = struct.unpack_from("<Q", footer, 0)[0]
        if block_size < 24 or block_size > size:
            return {}, "signing_block_size_invalid"
        block_start = cd_offset - block_size - 8
        if block_start < 0:
            return {}, "signing_block_size_invalid"
        if block_size > MAX_BLOCK_BYTES:
            return {}, "signing_block_too_large"
        handle.seek(block_start)
        block = handle.read(block_size + 8)
    if len(block) != block_size + 8:
        return {}, "signing_block_truncated"
    pairs: dict[int, bytes] = {}
    cursor = 8
    limit = len(block) - 24
    while cursor < limit:
        if cursor + 8 > limit:
            break
        pair_length = struct.unpack_from("<Q", block, cursor)[0]
        if pair_length < 4 or cursor + 8 + pair_length > len(block):
            break
        block_id = struct.unpack_from("<I", block, cursor + 8)[0]
        pairs[block_id] = block[cursor + 12:cursor + 8 + pair_length]
        cursor += 8 + pair_length
    return pairs, "parsed" if pairs else "no_pairs"


def _v2_certificates(value: bytes) -> list[bytes]:
    """v2 signer block: signed-data -> certificates (list of DER blobs)."""
    signers_blob, _ = _lp(value, 0)
    certificates: list[bytes] = []
    cursor = 0
    while cursor < len(signers_blob):
        signer, cursor = _lp(signers_blob, cursor)
        signed_data, _ = _lp(signer, 0)
        digests, after_digests = _lp(signed_data, 0)
        del digests
        certs, _ = _lp(signed_data, after_digests)
        inner = 0
        while inner < len(certs):
            certificate, inner = _lp(certs, inner)
            certificates.append(certificate)
    return certificates


def _v3_signers(value: bytes) -> list[dict[str, Any]]:
    """v3 signer block: certificates plus the SDK range the signer covers."""
    signers_blob, _ = _lp(value, 0)
    signers: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(signers_blob):
        signer, cursor = _lp(signers_blob, cursor)
        signed_data, after_signed = _lp(signer, 0)
        min_sdk = max_sdk = None
        if after_signed + 8 <= len(signer):
            min_sdk, max_sdk = struct.unpack_from("<II", signer, after_signed)
        _digests, after_digests = _lp(signed_data, 0)
        certs, _ = _lp(signed_data, after_digests)
        certificates: list[bytes] = []
        inner = 0
        while inner < len(certs):
            certificate, inner = _lp(certs, inner)
            certificates.append(certificate)
        signers.append({
            "certificates": certificates,
            "min_sdk": min_sdk,
            "max_sdk": max_sdk,
        })
    return signers


# ---- v1 (JAR) PKCS#7 ------------------------------------------------------


def _certificate_from_pkcs7(der: bytes) -> bytes | None:
    """First certificate inside a PKCS#7 SignedData, or None."""
    try:
        tag, start, end = _tlv(der, 0)
        if tag != TAG_SEQUENCE:
            return None
        content_info = _walk(der, start, end)
        if len(content_info) < 2 or content_info[1][0] != TAG_CONTEXT_0:
            return None
        _tag, _offset, explicit_start, explicit_end = content_info[1]
        inner = _walk(der, explicit_start, explicit_end)
        if not inner or inner[0][0] != TAG_SEQUENCE:
            return None
        signed_data = _walk(der, inner[0][2], inner[0][3])
        for entry_tag, entry_offset, entry_start, entry_end in signed_data:
            if entry_tag != TAG_CONTEXT_0:
                continue
            for cert_tag, cert_offset, _cs, _ce in _walk(der, entry_start, entry_end):
                if cert_tag == TAG_SEQUENCE:
                    return der[cert_offset:_cert_end(der, cert_offset)]
    except (DerError, IndexError):
        return None
    return None


def _cert_end(der: bytes, offset: int) -> int:
    _tag, _start, end = _tlv(der, offset)
    return end


# ---- public entry point ---------------------------------------------------


def _abis_from_zip(names: list[str]) -> list[str]:
    abis = set()
    for name in names:
        parts = name.split("/")
        if len(parts) >= 3 and parts[0] == "lib" and parts[-1].endswith(".so"):
            abis.add(parts[1])
    return sorted(abis)


def parse_apk_identity(apk_path: str | Path) -> dict[str, Any]:
    """Return the APK identity block: schemes, certificates, ABIs, zip totals."""
    path = Path(apk_path)
    identity: dict[str, Any] = {
        "status": "failed",
        "source": path.name,
        "size_bytes": 0,
        "schemes": [],
        "certificates": [],
        "abis": [],
        "zip": {},
        "v1_signature_files": [],
        "signing_block": "unread",
        "diagnostics": [],
    }
    try:
        identity["size_bytes"] = path.stat().st_size
    except OSError as exc:
        identity["diagnostics"].append({
            "code": "apk_identity_stat_failed", "message": str(exc),
        })
        return identity

    schemes: list[str] = []
    certificates: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_certificate(der: bytes, scheme: str, **extra: Any) -> None:
        try:
            parsed = parse_certificate(der)
        except (DerError, IndexError, ValueError) as exc:
            identity["diagnostics"].append({
                "code": "apk_certificate_parse_failed",
                "message": f"{scheme}: {type(exc).__name__}: {exc}",
            })
            return
        if parsed["sha256"] in seen:
            return
        seen.add(parsed["sha256"])
        parsed["scheme"] = scheme
        parsed.update(extra)
        certificates.append(parsed)

    try:
        pairs, block_status = _signing_block(path)
    except (OSError, DerError, struct.error) as exc:
        pairs, block_status = {}, f"error:{type(exc).__name__}"
    identity["signing_block"] = block_status

    if V2_BLOCK_ID in pairs:
        schemes.append(SCHEME_V2)
        try:
            for der in _v2_certificates(pairs[V2_BLOCK_ID]):
                add_certificate(der, SCHEME_V2)
        except (DerError, IndexError, struct.error) as exc:
            identity["diagnostics"].append({
                "code": "apk_v2_signer_parse_failed",
                "message": f"{type(exc).__name__}: {exc}",
            })
    if V3_BLOCK_ID in pairs:
        schemes.append(SCHEME_V3)
        try:
            for signer in _v3_signers(pairs[V3_BLOCK_ID]):
                for der in signer["certificates"]:
                    add_certificate(
                        der, SCHEME_V3,
                        min_sdk=signer["min_sdk"], max_sdk=signer["max_sdk"],
                    )
        except (DerError, IndexError, struct.error) as exc:
            identity["diagnostics"].append({
                "code": "apk_v3_signer_parse_failed",
                "message": f"{type(exc).__name__}: {exc}",
            })
    if V31_BLOCK_ID in pairs:
        schemes.append(SCHEME_V31)

    try:
        with zipfile.ZipFile(path) as archive:
            names = [info.filename for info in archive.infolist() if not info.is_dir()]
            identity["zip"] = {
                "entry_count": len(names),
                "compressed_bytes": sum(
                    info.compress_size for info in archive.infolist() if not info.is_dir()
                ),
                "uncompressed_bytes": sum(
                    info.file_size for info in archive.infolist() if not info.is_dir()
                ),
            }
            identity["abis"] = _abis_from_zip(names)
            for name in sorted(names):
                upper = name.upper()
                if not upper.startswith("META-INF/") or not upper.endswith(V1_SIGNATURE_SUFFIXES):
                    continue
                entry = {
                    "name": name,
                    "sha256": None,
                    "certificate_sha256": None,
                }
                try:
                    with archive.open(name) as stream:
                        payload = stream.read(MAX_CERT_BYTES + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    identity["diagnostics"].append({
                        "code": "apk_v1_signature_unreadable",
                        "message": f"{name}: {type(exc).__name__}: {exc}",
                    })
                    identity["v1_signature_files"].append(entry)
                    continue
                entry["sha256"] = hashlib.sha256(payload).hexdigest()
                certificate = _certificate_from_pkcs7(payload)
                if certificate is not None:
                    entry["certificate_sha256"] = hashlib.sha256(certificate).hexdigest()
                    add_certificate(certificate, SCHEME_V1)
                identity["v1_signature_files"].append(entry)
    except (OSError, zipfile.BadZipFile) as exc:
        identity["diagnostics"].append({
            "code": "apk_zip_unreadable", "message": f"{type(exc).__name__}: {exc}",
        })
        return identity

    if identity["v1_signature_files"]:
        schemes.insert(0, SCHEME_V1)
    identity["schemes"] = sorted(set(schemes), key=_scheme_order)
    identity["certificates"] = certificates
    if not identity["schemes"]:
        identity["status"] = "unsigned"
    elif not certificates:
        identity["status"] = "partial"
    else:
        identity["status"] = "success"
    return identity


def _scheme_order(scheme: str) -> int:
    return {SCHEME_V1: 0, SCHEME_V2: 1, SCHEME_V3: 2, SCHEME_V31: 3}.get(scheme, 9)


def identity_findings(identity: dict[str, Any], manifest_relative: str) -> list[dict[str, Any]]:
    """Findings that follow from identity alone. No time-dependent verdicts."""
    findings: list[dict[str, Any]] = []
    schemes = identity.get("schemes") or []
    if identity.get("status") == "unsigned":
        findings.append(build_finding(
            "apk_unsigned", "signing", "high",
            "APK carries no signature block",
            "No v1 META-INF signature and no v2/v3 APK Signing Block were found. "
            "An unsigned APK cannot be installed by a normal device; treat this "
            "artifact as tampered or incomplete.",
            manifest_relative, None, str(identity.get("source", "")), 0.95,
        ))
    elif schemes == [SCHEME_V1]:
        findings.append(build_finding(
            "apk_signed_v1_only", "signing", "medium",
            "APK is signed with v1 (JAR) only",
            "Only the v1 signature covers this APK. v1 does not protect the "
            "archive as a whole and is rejected for new installs on modern "
            "Android targets; confirm the target SDK and the delivery channel.",
            manifest_relative, None, "v1", 0.9,
        ))
    for certificate in identity.get("certificates") or []:
        subject = certificate.get("subject") or {}
        blob = " ".join(str(value) for value in subject.values())
        if "Android Debug" in blob:
            findings.append(build_finding(
                "apk_debug_certificate", "signing", "high",
                "APK is signed with the Android debug certificate",
                "The signing certificate subject names the Android debug key. "
                "This build was not signed for distribution.",
                manifest_relative, None, certificate.get("sha256", ""), 0.97,
            ))
    return findings
