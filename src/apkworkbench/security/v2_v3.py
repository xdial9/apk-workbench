"""APK Signature Scheme v2 and v3 cryptographic verification."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa

from apkworkbench.security.models import ApkSignatureError, summarize_certificate

APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0
V31_BLOCK_ID = 0x1B93AD61
STRIPPING_PROTECTION_ATTR_ID = 0xBEEFF00D
MAX_BLOCK_BYTES = 64 * 1024 * 1024
EOCD_MIN_SIZE = 22
EOCD_MAX_SEARCH = 65_535 + EOCD_MIN_SIZE
CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Signature algorithm ID -> (name, family, hash_cls, content_digest_id, pss_salt_len)
SUPPORTED_SIG_ALGORITHMS: dict[
    int, tuple[str, str, type[hashes.HashAlgorithm], int, int | None]
] = {
    0x0101: ("RSA_PSS_WITH_SHA256", "rsa_pss", hashes.SHA256, 0x0103, 32),
    0x0102: ("RSA_PSS_WITH_SHA512", "rsa_pss", hashes.SHA512, 0x0104, 64),
    0x0103: ("RSA_PKCS1_V1_5_WITH_SHA256", "rsa_pkcs1", hashes.SHA256, 0x0103, None),
    0x0104: ("RSA_PKCS1_V1_5_WITH_SHA512", "rsa_pkcs1", hashes.SHA512, 0x0104, None),
    0x0201: ("ECDSA_WITH_SHA256", "ecdsa", hashes.SHA256, 0x0103, None),
    0x0202: ("ECDSA_WITH_SHA512", "ecdsa", hashes.SHA512, 0x0104, None),
    0x0301: ("DSA_WITH_SHA256", "dsa", hashes.SHA256, 0x0103, None),
}

CONTENT_DIGEST_ALGORITHMS: dict[int, str] = {
    0x0103: "sha256",
    0x0104: "sha512",
}


def _read_lp(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 4 > len(data):
        raise ApkSignatureError("Truncated uint32 length prefix")
    length = struct.unpack_from("<I", data, offset)[0]
    start = offset + 4
    end = start + length
    if end > len(data):
        raise ApkSignatureError("Length-prefixed field overruns buffer")
    return data[start:end], end


def _locate_zip_and_signing_block(apk_path: Path) -> dict[str, Any]:
    """Locate EOCD, Central Directory, and APK Signing Block with strict bounds checks."""
    size = apk_path.stat().st_size
    if size < EOCD_MIN_SIZE:
        raise ApkSignatureError("File is smaller than ZIP EOCD minimum size")

    with apk_path.open("rb") as handle:
        tail_start = max(0, size - EOCD_MAX_SEARCH)
        handle.seek(tail_start)
        tail = handle.read(size - tail_start)

        eocd_offset: int | None = None
        search_end = len(tail)
        while True:
            pos = tail.rfind(b"PK\x05\x06", 0, search_end)
            if pos < 0:
                break
            if pos + EOCD_MIN_SIZE <= len(tail):
                comment_len = struct.unpack_from("<H", tail, pos + 20)[0]
                if tail_start + pos + EOCD_MIN_SIZE + comment_len == size:
                    eocd_offset = tail_start + pos
                    break
            search_end = pos

        if eocd_offset is None:
            raise ApkSignatureError("Valid ZIP End of Central Directory (EOCD) not found")

        eocd = tail[eocd_offset - tail_start:]
        disk_num, cd_disk, entries_disk, entries_total, cd_size, cd_offset = struct.unpack_from(
            "<HHHHII", eocd, 4
        )
        if disk_num != 0 or cd_disk != 0 or entries_disk != entries_total:
            raise ApkSignatureError("Multi-disk ZIP archives are not supported")
        if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            raise ApkSignatureError("ZIP64 EOCD sentinel is not supported")
        if cd_offset + cd_size != eocd_offset:
            raise ApkSignatureError(
                f"Central Directory bounds ({cd_offset}+{cd_size}) do not meet EOCD ({eocd_offset})"
            )

        if cd_offset < 32:
            return {
                "has_signing_block": False,
                "reason": "no_signing_block",
                "file_size": size,
                "eocd_offset": eocd_offset,
                "cd_offset": cd_offset,
                "eocd_bytes": eocd,
            }

        handle.seek(cd_offset - 24)
        footer = handle.read(24)
        if len(footer) != 24 or footer[8:] != APK_SIG_BLOCK_MAGIC:
            return {
                "has_signing_block": False,
                "reason": "no_signing_block",
                "file_size": size,
                "eocd_offset": eocd_offset,
                "cd_offset": cd_offset,
                "eocd_bytes": eocd,
            }

        footer_size = struct.unpack_from("<Q", footer, 0)[0]
        if footer_size < 24 or footer_size > MAX_BLOCK_BYTES or footer_size + 8 > cd_offset:
            raise ApkSignatureError(f"Invalid APK Signing Block footer size: {footer_size}")
        block_start = cd_offset - footer_size - 8
        handle.seek(block_start)
        block = handle.read(footer_size + 8)
        if len(block) != footer_size + 8:
            raise ApkSignatureError("Truncated APK Signing Block")

    header_size = struct.unpack_from("<Q", block, 0)[0]
    if header_size != footer_size:
        raise ApkSignatureError(
            f"APK Signing Block header/footer size mismatch ({header_size} != {footer_size})"
        )

    pairs: dict[int, bytes] = {}
    cursor = 8
    limit = len(block) - 24
    while cursor < limit:
        if cursor + 8 > limit:
            raise ApkSignatureError("Truncated APK Signing Block ID-value length")
        pair_len = struct.unpack_from("<Q", block, cursor)[0]
        if pair_len < 4 or cursor + 8 + pair_len > limit:
            raise ApkSignatureError("APK Signing Block ID-value pair overruns block")
        block_id = struct.unpack_from("<I", block, cursor + 8)[0]
        if block_id in pairs:
            raise ApkSignatureError(f"Duplicate APK Signing Block ID: 0x{block_id:08x}")
        pairs[block_id] = block[cursor + 12:cursor + 8 + pair_len]
        cursor += 8 + pair_len

    if cursor != limit:
        raise ApkSignatureError("APK Signing Block has trailing unparsed bytes")

    return {
        "has_signing_block": True,
        "file_size": size,
        "block_start": block_start,
        "cd_offset": cd_offset,
        "eocd_offset": eocd_offset,
        "eocd_bytes": eocd,
        "pairs": pairs,
    }


def _compute_chunked_digests(
    apk_path: Path,
    block_start: int,
    cd_offset: int,
    eocd_offset: int,
    eocd_bytes: bytes,
    content_digest_ids: set[int],
) -> dict[int, bytes]:
    """Compute Android v2/v3 chunked Merkle-style digests over sections 1, 3, and 4."""
    algs = {did: CONTENT_DIGEST_ALGORITHMS[did] for did in content_digest_ids}
    chunk_lists: dict[int, list[bytes]] = {did: [] for did in algs}
    total_chunks = 0

    def feed_chunk(chunk: bytes) -> None:
        nonlocal total_chunks
        if not chunk:
            return
        total_chunks += 1
        prefix = b"\xa5" + struct.pack("<I", len(chunk))
        for did, alg_name in algs.items():
            h = hashlib.new(alg_name)
            h.update(prefix)
            h.update(chunk)
            chunk_lists[did].append(h.digest())

    def stream_range(handle: Any, start: int, end: int) -> None:
        handle.seek(start)
        remaining = end - start
        while remaining > 0:
            to_read = min(CHUNK_SIZE, remaining)
            buf = handle.read(to_read)
            if len(buf) != to_read:
                raise ApkSignatureError("Unexpected EOF while hashing APK sections")
            feed_chunk(buf)
            remaining -= to_read

    with apk_path.open("rb") as handle:
        # Section 1: ZIP entries before APK Signing Block
        stream_range(handle, 0, block_start)
        # Section 3: ZIP Central Directory
        stream_range(handle, cd_offset, eocd_offset)

    # Section 4: EOCD with cd_offset patched to block_start
    patched_eocd = bytearray(eocd_bytes)
    struct.pack_into("<I", patched_eocd, 16, block_start)
    for offset in range(0, len(patched_eocd), CHUNK_SIZE):
        feed_chunk(bytes(patched_eocd[offset:offset + CHUNK_SIZE]))

    top_prefix = b"\x5a" + struct.pack("<I", total_chunks)
    out: dict[int, bytes] = {}
    for did, alg_name in algs.items():
        h = hashlib.new(alg_name)
        h.update(top_prefix)
        for chunk_digest in chunk_lists[did]:
            h.update(chunk_digest)
        out[did] = h.digest()
    return out


def _verify_v2_v3_signature(
    pub_key: Any,
    sig_alg_id: int,
    signature_bytes: bytes,
    signed_data_bytes: bytes,
) -> None:
    if sig_alg_id not in SUPPORTED_SIG_ALGORITHMS:
        raise ApkSignatureError(f"Unsupported v2/v3 signature algorithm: 0x{sig_alg_id:04x}")
    _name, family, hash_cls, _digest_id, salt_len = SUPPORTED_SIG_ALGORITHMS[sig_alg_id]
    try:
        if family == "rsa_pss":
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise ApkSignatureError("Signer public key is not RSA for RSA-PSS")
            assert salt_len is not None
            pub_key.verify(
                signature_bytes,
                signed_data_bytes,
                padding.PSS(mgf=padding.MGF1(hash_cls()), salt_length=salt_len),
                hash_cls(),
            )
        elif family == "rsa_pkcs1":
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise ApkSignatureError("Signer public key is not RSA for RSA PKCS#1 v1.5")
            pub_key.verify(signature_bytes, signed_data_bytes, padding.PKCS1v15(), hash_cls())
        elif family == "ecdsa":
            if not isinstance(pub_key, ec.EllipticCurvePublicKey):
                raise ApkSignatureError("Signer public key is not EC for ECDSA")
            pub_key.verify(signature_bytes, signed_data_bytes, ec.ECDSA(hash_cls()))
        elif family == "dsa":
            if not isinstance(pub_key, dsa.DSAPublicKey):
                raise ApkSignatureError("Signer public key is not DSA for DSA")
            pub_key.verify(signature_bytes, signed_data_bytes, hash_cls())
    except InvalidSignature as exc:
        raise ApkSignatureError(
            f"Asymmetric signature verification failed for algorithm 0x{sig_alg_id:04x}"
        ) from exc


def _parse_and_verify_signer(
    signer_bytes: bytes,
    is_v3: bool,
    apk_path: Path,
    layout: dict[str, Any],
) -> dict[str, Any]:
    signed_data_bytes, cursor = _read_lp(signer_bytes, 0)
    outer_min_sdk: int | None = None
    outer_max_sdk: int | None = None
    if is_v3:
        if cursor + 8 > len(signer_bytes):
            raise ApkSignatureError("v3 signer missing minSDK/maxSDK")
        outer_min_sdk, outer_max_sdk = struct.unpack_from("<II", signer_bytes, cursor)
        cursor += 8
    signatures_blob, cursor = _read_lp(signer_bytes, cursor)
    public_key_bytes, _cursor = _read_lp(signer_bytes, cursor)

    # Parse signed_data fields (trailing bytes inside forward-compatible containers
    # are ignored per AOSP getLengthPrefixedSlice; the entire signed_data_bytes is signed).
    digests_blob, sd_cursor = _read_lp(signed_data_bytes, 0)
    certs_blob, sd_cursor = _read_lp(signed_data_bytes, sd_cursor)
    inner_min_sdk: int | None = None
    inner_max_sdk: int | None = None
    if is_v3:
        if sd_cursor + 8 > len(signed_data_bytes):
            raise ApkSignatureError("v3 signed_data missing minSDK/maxSDK")
        inner_min_sdk, inner_max_sdk = struct.unpack_from("<II", signed_data_bytes, sd_cursor)
        sd_cursor += 8
        if inner_min_sdk != outer_min_sdk or inner_max_sdk != outer_max_sdk:
            raise ApkSignatureError(
                f"v3 signer SDK range mismatch: outer=({outer_min_sdk},{outer_max_sdk}) "
                f"!= signed_data=({inner_min_sdk},{inner_max_sdk})"
            )
        if inner_min_sdk > inner_max_sdk:
            raise ApkSignatureError(f"Invalid v3 SDK range: {inner_min_sdk} > {inner_max_sdk}")
    attrs_blob, _sd_cursor = _read_lp(signed_data_bytes, sd_cursor)

    stripping_protection_versions: list[int] = []
    a_cur = 0
    while a_cur < len(attrs_blob):
        attr_entry, a_cur = _read_lp(attrs_blob, a_cur)
        if len(attr_entry) < 4:
            raise ApkSignatureError("Additional attribute entry too short")
        attr_id = struct.unpack_from("<I", attr_entry, 0)[0]
        attr_value = attr_entry[4:]
        if attr_id == STRIPPING_PROTECTION_ATTR_ID and len(attr_value) >= 4:
            stripping_protection_versions.append(struct.unpack_from("<I", attr_value, 0)[0])

    # Parse digests
    digests_by_sig_alg: dict[int, bytes] = {}
    d_cur = 0
    while d_cur < len(digests_blob):
        entry, d_cur = _read_lp(digests_blob, d_cur)
        if len(entry) < 4:
            raise ApkSignatureError("Digest entry too short")
        alg_id = struct.unpack_from("<I", entry, 0)[0]
        digest_bytes, _e_cur = _read_lp(entry, 4)
        if alg_id in digests_by_sig_alg:
            raise ApkSignatureError(f"Duplicate digest entry for algorithm 0x{alg_id:04x}")
        digests_by_sig_alg[alg_id] = digest_bytes

    # Parse certificates and verify certs[0] public key == signer.public_key
    cert_summaries: list[dict[str, Any]] = []
    c_cur = 0
    first_cert: x509.Certificate | None = None
    while c_cur < len(certs_blob):
        cert_der, c_cur = _read_lp(certs_blob, c_cur)
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except ValueError as exc:
            raise ApkSignatureError(f"Invalid X.509 certificate in signing block: {exc}") from exc
        if first_cert is None:
            first_cert = cert
        cert_summaries.append(summarize_certificate(cert))
    if first_cert is None:
        raise ApkSignatureError("Signer signed_data contains no certificates")

    try:
        pub_key = serialization.load_der_public_key(public_key_bytes)
    except ValueError as exc:
        raise ApkSignatureError(f"Invalid signer SubjectPublicKeyInfo: {exc}") from exc

    cert_spki = first_cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if cert_spki != public_key_bytes:
        raise ApkSignatureError("Signer public_key does not match signing certificate public key")

    # Parse and verify signatures
    signatures_parsed: list[tuple[int, bytes]] = []
    s_cur = 0
    while s_cur < len(signatures_blob):
        sig_entry, s_cur = _read_lp(signatures_blob, s_cur)
        if len(sig_entry) < 4:
            raise ApkSignatureError("Signature entry too short")
        alg_id = struct.unpack_from("<I", sig_entry, 0)[0]
        sig_bytes, _se_cur = _read_lp(sig_entry, 4)
        signatures_parsed.append((alg_id, sig_bytes))
    if not signatures_parsed:
        raise ApkSignatureError("Signer contains no signatures")

    sig_alg_ids = [alg_id for alg_id, _ in signatures_parsed]
    if len(sig_alg_ids) != len(set(sig_alg_ids)):
        raise ApkSignatureError("Signer contains duplicate signature algorithm entries")
    if set(sig_alg_ids) != set(digests_by_sig_alg):
        raise ApkSignatureError("Signer signature algorithms do not match digest algorithms")

    supported_verified: list[str] = []
    needed_content_digests: set[int] = set()
    for alg_id, sig_bytes in signatures_parsed:
        if alg_id not in SUPPORTED_SIG_ALGORITHMS:
            continue
        _verify_v2_v3_signature(pub_key, alg_id, sig_bytes, signed_data_bytes)
        alg_name, _fam, _hcls, content_digest_id, _salt = SUPPORTED_SIG_ALGORITHMS[alg_id]
        supported_verified.append(alg_name)
        needed_content_digests.add(content_digest_id)

    if not supported_verified:
        raise ApkSignatureError("No supported signature algorithms found in signer block")

    computed_digests = _compute_chunked_digests(
        apk_path,
        layout["block_start"],
        layout["cd_offset"],
        layout["eocd_offset"],
        layout["eocd_bytes"],
        needed_content_digests,
    )
    for alg_id, _sig_bytes in signatures_parsed:
        if alg_id not in SUPPORTED_SIG_ALGORITHMS:
            continue
        alg_name, _fam, _hcls, content_digest_id, _salt = SUPPORTED_SIG_ALGORITHMS[alg_id]
        expected_digest = digests_by_sig_alg[alg_id]
        actual_digest = computed_digests[content_digest_id]
        if expected_digest != actual_digest:
            raise ApkSignatureError(
                f"APK chunked content digest mismatch for {alg_name}"
            )

    signer_info: dict[str, Any] = {
        "verified": True,
        "algorithms_verified": supported_verified,
        "content_digests_verified": [CONTENT_DIGEST_ALGORITHMS[d] for d in sorted(needed_content_digests)],
        "stripping_protection_versions": sorted(set(stripping_protection_versions)),
        "certificates": cert_summaries,
    }
    if is_v3:
        signer_info["min_sdk"] = inner_min_sdk
        signer_info["max_sdk"] = inner_max_sdk
    return signer_info


def _verify_scheme_block(
    scheme_name: str,
    block_bytes: bytes,
    is_v3: bool,
    apk_path: Path,
    layout: dict[str, Any],
) -> dict[str, Any]:
    res: dict[str, Any] = {
        "scheme": scheme_name,
        "present": True,
        "verified": False,
        "status": "failed",
        "signers": [],
        "certificates": [],
        "stripping_protection_versions": [],
        "errors": [],
    }
    try:
        signers_blob, _cursor = _read_lp(block_bytes, 0)
        if not signers_blob:
            raise ApkSignatureError(f"{scheme_name} block has empty signers list")
        s_cur = 0
        seen_certs: dict[str, dict[str, Any]] = {}
        stripping_all: set[int] = set()
        while s_cur < len(signers_blob):
            signer_bytes, s_cur = _read_lp(signers_blob, s_cur)
            signer_res = _parse_and_verify_signer(signer_bytes, is_v3, apk_path, layout)
            res["signers"].append(signer_res)
            stripping_all.update(signer_res.get("stripping_protection_versions") or [])
            for cert in signer_res["certificates"]:
                seen_certs.setdefault(cert["sha256"], cert)
        res["certificates"] = list(seen_certs.values())
        res["stripping_protection_versions"] = sorted(stripping_all)
        res["verified"] = True
        res["status"] = "verified"
    except ApkSignatureError as exc:
        res["errors"].append(str(exc))
    return res


def verify_v2_v3_signatures(apk_path: Path) -> dict[str, Any]:
    """Verify APK Signature Scheme v2 and v3 blocks if present."""
    v2_empty: dict[str, Any] = {
        "scheme": "v2",
        "present": False,
        "verified": False,
        "status": "not_present",
        "signers": [],
        "certificates": [],
        "stripping_protection_versions": [],
        "errors": [],
    }
    v3_empty: dict[str, Any] = {
        "scheme": "v3",
        "present": False,
        "verified": False,
        "status": "not_present",
        "signers": [],
        "certificates": [],
        "stripping_protection_versions": [],
        "errors": [],
    }
    try:
        layout = _locate_zip_and_signing_block(apk_path)
    except (ApkSignatureError, OSError, struct.error) as exc:
        return {
            "signing_block_present": False,
            "signing_block_error": f"{type(exc).__name__}: {exc}",
            "v2": v2_empty,
            "v3": v3_empty,
            "v31_present": False,
        }

    if not layout["has_signing_block"]:
        return {
            "signing_block_present": False,
            "signing_block_error": None,
            "v2": v2_empty,
            "v3": v3_empty,
            "v31_present": False,
        }

    pairs: dict[int, bytes] = layout["pairs"]
    v2_res = (
        _verify_scheme_block("v2", pairs[V2_BLOCK_ID], False, apk_path, layout)
        if V2_BLOCK_ID in pairs
        else v2_empty
    )
    v3_res = (
        _verify_scheme_block("v3", pairs[V3_BLOCK_ID], True, apk_path, layout)
        if V3_BLOCK_ID in pairs
        else v3_empty
    )
    return {
        "signing_block_present": True,
        "signing_block_error": None,
        "v2": v2_res,
        "v3": v3_res,
        "v31_present": V31_BLOCK_ID in pairs,
    }
