"""Synthetic DER / X.509 / APK signing-block builders for the identity tests.

Everything is built from bytes: no host toolchain, no committed certificate.
The DER is structurally valid (a parser can walk it); the signatures are not
real, because the scanner never verifies them — it reads identity, not trust.
"""
from __future__ import annotations

import io
import struct
import zipfile

TAG_INTEGER = 0x02
TAG_BITSTRING = 0x03
TAG_OID = 0x06
TAG_UTF8 = 0x0C
TAG_UTCTIME = 0x17
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_CONTEXT_0 = 0xA0

V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def der_int(value: int) -> bytes:
    if value == 0:
        return tlv(TAG_INTEGER, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return tlv(TAG_INTEGER, raw)


def der_oid(dotted: str) -> bytes:
    parts = [int(item) for item in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append((value & 0x7F) | 0x80)
            value >>= 7
        body += bytes(reversed(chunk))
    return tlv(TAG_OID, body)


def der_utf8(text: str) -> bytes:
    return tlv(TAG_UTF8, text.encode("utf-8"))


def der_utctime(text: str) -> bytes:
    return tlv(TAG_UTCTIME, text.encode("ascii"))


def der_seq(*items: bytes) -> bytes:
    return tlv(TAG_SEQUENCE, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return tlv(TAG_SET, b"".join(items))


def _name(cn: str, org: str) -> bytes:
    return der_seq(
        der_set(der_seq(der_oid("2.5.4.3"), der_utf8(cn))),
        der_set(der_seq(der_oid("2.5.4.10"), der_utf8(org))),
    )


def make_certificate(
    *,
    cn: str = "Demo Signing",
    org: str = "Demo Org",
    issuer_cn: str | None = None,
    issuer_org: str | None = None,
    serial: int = 0x1234,
    not_before: str = "240101000000Z",
    not_after: str = "340101000000Z",
) -> bytes:
    subject = _name(cn, org)
    issuer = subject if issuer_cn is None else _name(
        issuer_cn, issuer_org if issuer_org is not None else org
    )
    validity = der_seq(der_utctime(not_before), der_utctime(not_after))
    algorithm = der_seq(der_oid("1.2.840.113549.1.1.11"), b"\x05\x00")
    public_key = der_seq(
        der_seq(der_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
        tlv(TAG_BITSTRING, b"\x00" + b"\x11" * 8),
    )
    tbs = der_seq(
        tlv(TAG_CONTEXT_0, der_int(2)),  # v3
        der_int(serial),
        algorithm,
        issuer,
        validity,
        subject,
        public_key,
    )
    return der_seq(tbs, algorithm, tlv(TAG_BITSTRING, b"\x00" + b"\x22" * 8))


def pkcs7_with_certificate(certificate: bytes) -> bytes:
    """Minimal PKCS#7 SignedData carrying one certificate (v1 META-INF file)."""
    signed_data = der_seq(
        der_int(1),
        der_set(),
        der_seq(der_oid("1.2.840.113549.1.7.1")),
        tlv(TAG_CONTEXT_0, certificate),
        der_set(),
    )
    return der_seq(der_oid("1.2.840.113549.1.7.2"), tlv(TAG_CONTEXT_0, signed_data))


def _lp(payload: bytes) -> bytes:
    return struct.pack("<I", len(payload)) + payload


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _insert_signing_block(archive: bytes, pairs: list[tuple[int, bytes]]) -> bytes:
    eocd = archive.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("no EOCD in fixture")
    cd_offset = struct.unpack_from("<I", archive, eocd + 16)[0]
    body = b"".join(
        struct.pack("<Q", len(value) + 4) + struct.pack("<I", block_id) + value
        for block_id, value in pairs
    )
    size = len(body) + 24
    block = struct.pack("<Q", size) + body + struct.pack("<Q", size) + b"APK Sig Block 42"
    patched = bytearray(archive[:cd_offset] + block + archive[cd_offset:])
    struct.pack_into("<I", patched, eocd + len(block) + 16, cd_offset + len(block))
    return bytes(patched)


def v2_value(certificate: bytes) -> bytes:
    certificates = _lp(certificate)
    signed_data = _lp(_lp(b"")) + _lp(certificates) + _lp(b"")
    signer = _lp(signed_data) + _lp(b"") + _lp(b"\x00")
    return _lp(_lp(signer))


def v3_value(certificate: bytes, min_sdk: int = 24, max_sdk: int = 0x7FFFFFFF) -> bytes:
    certificates = _lp(certificate)
    signed_data = (
        _lp(_lp(b"")) + _lp(certificates)
        + struct.pack("<II", min_sdk, max_sdk) + _lp(b"")
    )
    signer = (
        _lp(signed_data) + struct.pack("<II", min_sdk, max_sdk)
        + _lp(b"") + _lp(b"\x00")
    )
    return _lp(_lp(signer))


BASE_ENTRIES = {
    "AndroidManifest.xml": b"<manifest/>",
    "classes.dex": b"dex\n035\x00",
}


def apk_v2(certificate: bytes, entries: dict[str, bytes] | None = None) -> bytes:
    archive = _zip_bytes(entries or BASE_ENTRIES)
    return _insert_signing_block(archive, [(V2_BLOCK_ID, v2_value(certificate))])


def apk_v3(certificate: bytes, *, min_sdk: int = 24, max_sdk: int = 0x7FFFFFFF,
           entries: dict[str, bytes] | None = None) -> bytes:
    archive = _zip_bytes(entries or BASE_ENTRIES)
    return _insert_signing_block(
        archive, [(V3_BLOCK_ID, v3_value(certificate, min_sdk, max_sdk))]
    )


def apk_v1(certificate: bytes, entries: dict[str, bytes] | None = None) -> bytes:
    payload = dict(entries or BASE_ENTRIES)
    payload["META-INF/CERT.RSA"] = pkcs7_with_certificate(certificate)
    payload["META-INF/CERT.SF"] = b"Signature-Version: 1.0\n"
    payload["META-INF/MANIFEST.MF"] = b"Manifest-Version: 1.0\n"
    return _zip_bytes(payload)


def apk_unsigned(entries: dict[str, bytes] | None = None) -> bytes:
    return _zip_bytes(entries or BASE_ENTRIES)


def apk_with_abis(*abis: str) -> bytes:
    entries = dict(BASE_ENTRIES)
    for abi in abis:
        entries[f"lib/{abi}/libdemo.so"] = b"\x7fELF"
    return _zip_bytes(entries)
