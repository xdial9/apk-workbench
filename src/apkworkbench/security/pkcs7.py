"""Strict ASN.1 DER reader and CMS/PKCS#7 SignedData cryptographic verifier."""
from __future__ import annotations

import hashlib
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.x509.oid import ExtensionOID

from apkworkbench.security.models import ApkSignatureError, summarize_certificate

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

# Digest algorithm OIDs -> (hashlib_name, cryptography_hash_cls)
DIGEST_OIDS: dict[str, tuple[str, type[hashes.HashAlgorithm]]] = {
    "1.3.14.3.2.26": ("sha1", hashes.SHA1),
    "2.16.840.1.101.3.4.2.1": ("sha256", hashes.SHA256),
    "2.16.840.1.101.3.4.2.2": ("sha384", hashes.SHA384),
    "2.16.840.1.101.3.4.2.3": ("sha512", hashes.SHA512),
}

# Signature algorithm OIDs -> (family, optional_forced_digest_name)
SIGNATURE_OIDS: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.1": ("rsa_pkcs1", None),
    "1.2.840.113549.1.1.5": ("rsa_pkcs1", "sha1"),
    "1.2.840.113549.1.1.11": ("rsa_pkcs1", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa_pkcs1", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa_pkcs1", "sha512"),
    "1.2.840.113549.1.1.10": ("rsa_pss", None),
    "1.2.840.10045.2.1": ("ecdsa", None),
    "1.2.840.10045.4.1": ("ecdsa", "sha1"),
    "1.2.840.10045.4.3.2": ("ecdsa", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa", "sha512"),
    "1.2.840.10040.4.1": ("dsa", None),
    "1.2.840.10040.4.3": ("dsa", "sha1"),
    "2.16.840.1.101.3.4.3.2": ("dsa", "sha256"),
}

OID_MGF1 = "1.2.840.113549.1.1.8"

TAG_INTEGER = 0x02
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_CONTEXT_0_CONSTRUCTED = 0xA0
TAG_CONTEXT_0_PRIMITIVE = 0x80


def _read_tlv(data: bytes, offset: int) -> tuple[int, int, int, int]:
    """Return (tag, tag_offset, value_start, value_end) for DER TLV at ``offset``."""
    if offset + 2 > len(data):
        raise ApkSignatureError("Truncated DER header")
    tag = data[offset]
    length_byte = data[offset + 1]
    cursor = offset + 2
    if length_byte & 0x80:
        count = length_byte & 0x7F
        if count == 0 or count > 4:
            raise ApkSignatureError(f"Unsupported DER length encoding ({count} bytes)")
        if cursor + count > len(data):
            raise ApkSignatureError("Truncated DER length")
        length = int.from_bytes(data[cursor:cursor + count], "big")
        cursor += count
    else:
        length = length_byte
    end = cursor + length
    if end > len(data):
        raise ApkSignatureError("Truncated DER value")
    return tag, offset, cursor, end


def _walk_tlvs(data: bytes, start: int, end: int) -> list[tuple[int, int, int, int]]:
    items: list[tuple[int, int, int, int]] = []
    cursor = start
    while cursor < end:
        item = _read_tlv(data, cursor)
        if item[3] > end:
            raise ApkSignatureError("DER child overruns parent container")
        items.append(item)
        cursor = item[3]
    return items


def _decode_oid(data: bytes, start: int, end: int) -> str:
    if start >= end:
        raise ApkSignatureError("Empty DER OID")
    first = data[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(str(value))
            value = 0
    if data[end - 1] & 0x80:
        raise ApkSignatureError("Truncated DER OID")
    return ".".join(parts)


def _decode_int(data: bytes, start: int, end: int) -> int:
    if start >= end:
        raise ApkSignatureError("Empty DER INTEGER")
    return int.from_bytes(data[start:end], "big", signed=True)


def _parse_alg_id(data: bytes, start: int, end: int) -> tuple[str, tuple[int, int, int, int] | None]:
    items = _walk_tlvs(data, start, end)
    if not items or items[0][0] != TAG_OID:
        raise ApkSignatureError("AlgorithmIdentifier missing OID")
    oid = _decode_oid(data, items[0][2], items[0][3])
    params = items[1] if len(items) > 1 else None
    return oid, params


def _parse_pss_params(
    data: bytes,
    params: tuple[int, int, int, int] | None,
) -> tuple[type[hashes.HashAlgorithm], type[hashes.HashAlgorithm], int]:
    """Parse RSASSA-PSS-params (RFC 4055), defaulting to SHA-1 / MGF1(SHA-1) / 20."""
    hash_cls: type[hashes.HashAlgorithm] = hashes.SHA1
    mgf_hash_cls: type[hashes.HashAlgorithm] = hashes.SHA1
    salt_length = 20
    if params is None or params[0] == TAG_NULL:
        return hash_cls, mgf_hash_cls, salt_length
    if params[0] != TAG_SEQUENCE:
        raise ApkSignatureError("Malformed RSASSA-PSS-params")
    for tag, _off, v_start, v_end in _walk_tlvs(data, params[2], params[3]):
        inner = _walk_tlvs(data, v_start, v_end)
        if tag == 0xA0 and inner and inner[0][0] == TAG_SEQUENCE:
            alg_oid, _ = _parse_alg_id(data, inner[0][2], inner[0][3])
            if alg_oid not in DIGEST_OIDS:
                raise ApkSignatureError(f"Unsupported PSS hash OID: {alg_oid}")
            hash_cls = DIGEST_OIDS[alg_oid][1]
        elif tag == 0xA1 and inner and inner[0][0] == TAG_SEQUENCE:
            mgf_oid, mgf_param = _parse_alg_id(data, inner[0][2], inner[0][3])
            if mgf_oid != OID_MGF1 or mgf_param is None or mgf_param[0] != TAG_SEQUENCE:
                raise ApkSignatureError(f"Unsupported PSS MGF: {mgf_oid}")
            mgf_hash_oid, _ = _parse_alg_id(data, mgf_param[2], mgf_param[3])
            if mgf_hash_oid not in DIGEST_OIDS:
                raise ApkSignatureError(f"Unsupported PSS MGF1 hash OID: {mgf_hash_oid}")
            mgf_hash_cls = DIGEST_OIDS[mgf_hash_oid][1]
        elif tag == 0xA2 and inner and inner[0][0] == TAG_INTEGER:
            salt_length = _decode_int(data, inner[0][2], inner[0][3])
            if salt_length < 0:
                raise ApkSignatureError("Negative PSS salt length")
    return hash_cls, mgf_hash_cls, salt_length


def _match_certificate(
    data: bytes,
    sid_item: tuple[int, int, int, int],
    certs: list[x509.Certificate],
) -> x509.Certificate:
    """Match CMS SignerIdentifier (IssuerAndSerialNumber or SubjectKeyIdentifier) to a cert."""
    tag, _off, v_start, v_end = sid_item
    if tag == TAG_SEQUENCE:
        fields = _walk_tlvs(data, v_start, v_end)
        if len(fields) != 2 or fields[0][0] != TAG_SEQUENCE or fields[1][0] != TAG_INTEGER:
            raise ApkSignatureError("Malformed IssuerAndSerialNumber")
        issuer_der = data[fields[0][1]:fields[0][3]]
        serial = _decode_int(data, fields[1][2], fields[1][3])
        for cert in certs:
            if cert.serial_number == serial and cert.issuer.public_bytes() == issuer_der:
                return cert
        raise ApkSignatureError(f"No certificate matches IssuerAndSerialNumber (serial={hex(serial)})")
    if tag == TAG_CONTEXT_0_PRIMITIVE:
        ski = data[v_start:v_end]
        for cert in certs:
            try:
                ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            except x509.ExtensionNotFound:
                continue
            if ext.value.digest == ski:
                return cert
        raise ApkSignatureError("No certificate matches SubjectKeyIdentifier")
    raise ApkSignatureError(f"Unsupported SignerIdentifier tag: 0x{tag:02x}")


def _verify_signed_attrs(
    data: bytes,
    attrs_item: tuple[int, int, int, int],
    digest_name: str,
    signed_content: bytes,
    encap_content_type: str,
) -> bytes:
    """Validate CMS signedAttrs (messageDigest & contentType) and return SET OF DER bytes."""
    _tag, off, v_start, v_end = attrs_item
    expected_digest = hashlib.new(digest_name, signed_content).digest()
    found_message_digest = False

    for attr_tag, _attr_off, a_start, a_end in _walk_tlvs(data, v_start, v_end):
        if attr_tag != TAG_SEQUENCE:
            raise ApkSignatureError("SignedAttribute is not a SEQUENCE")
        parts = _walk_tlvs(data, a_start, a_end)
        if len(parts) != 2 or parts[0][0] != TAG_OID or parts[1][0] != TAG_SET:
            raise ApkSignatureError("Malformed SignedAttribute")
        attr_oid = _decode_oid(data, parts[0][2], parts[0][3])
        values = _walk_tlvs(data, parts[1][2], parts[1][3])
        if attr_oid == OID_MESSAGE_DIGEST:
            if len(values) != 1 or values[0][0] != TAG_OCTET_STRING:
                raise ApkSignatureError("Malformed messageDigest attribute")
            if data[values[0][2]:values[0][3]] != expected_digest:
                raise ApkSignatureError("PKCS#7 signedAttrs messageDigest mismatch")
            found_message_digest = True
        elif attr_oid == OID_CONTENT_TYPE:
            if len(values) != 1 or values[0][0] != TAG_OID:
                raise ApkSignatureError("Malformed contentType attribute")
            ct_oid = _decode_oid(data, values[0][2], values[0][3])
            if ct_oid != encap_content_type:
                raise ApkSignatureError(
                    f"PKCS#7 contentType attribute {ct_oid} != {encap_content_type}"
                )

    if not found_message_digest:
        raise ApkSignatureError("PKCS#7 signedAttrs missing required messageDigest attribute")

    # RFC 5652 §5.4: replace implicit [0] tag (0xA0) with SET OF tag (0x31).
    return b"\x31" + data[off + 1:v_end]


def _verify_asymmetric(
    cert: x509.Certificate,
    signature_bytes: bytes,
    message: bytes,
    digest_name: str,
    sig_alg_oid: str,
    sig_alg_params: tuple[int, int, int, int] | None,
    der_data: bytes,
) -> None:
    if sig_alg_oid not in SIGNATURE_OIDS:
        raise ApkSignatureError(f"Unsupported PKCS#7 signatureAlgorithm OID: {sig_alg_oid}")
    family, forced_digest = SIGNATURE_OIDS[sig_alg_oid]
    if forced_digest is not None and forced_digest != digest_name:
        raise ApkSignatureError(
            f"PKCS#7 digest/signature mismatch: digest={digest_name}, sig={sig_alg_oid}"
        )
    hash_cls = next(cls for name, cls in DIGEST_OIDS.values() if name == digest_name)
    pub = cert.public_key()
    try:
        if family == "rsa_pkcs1":
            if not isinstance(pub, rsa.RSAPublicKey):
                raise ApkSignatureError("Certificate key is not RSA for RSA signature")
            pub.verify(signature_bytes, message, padding.PKCS1v15(), hash_cls())
        elif family == "rsa_pss":
            if not isinstance(pub, rsa.RSAPublicKey):
                raise ApkSignatureError("Certificate key is not RSA for RSA-PSS signature")
            pss_hash, mgf_hash, salt_len = _parse_pss_params(der_data, sig_alg_params)
            pub.verify(
                signature_bytes,
                message,
                padding.PSS(mgf=padding.MGF1(mgf_hash()), salt_length=salt_len),
                pss_hash(),
            )
        elif family == "ecdsa":
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise ApkSignatureError("Certificate key is not EC for ECDSA signature")
            pub.verify(signature_bytes, message, ec.ECDSA(hash_cls()))
        elif family == "dsa":
            if not isinstance(pub, dsa.DSAPublicKey):
                raise ApkSignatureError("Certificate key is not DSA for DSA signature")
            pub.verify(signature_bytes, message, hash_cls())
        else:  # pragma: no cover - guarded by SIGNATURE_OIDS
            raise ApkSignatureError(f"Unhandled signature family: {family}")
    except InvalidSignature as exc:
        raise ApkSignatureError("PKCS#7 cryptographic signature verification failed") from exc


def verify_pkcs7_signature(pkcs7_der: bytes, signed_content: bytes) -> dict[str, Any]:
    """Verify a DER-encoded PKCS#7/CMS SignedData block against ``signed_content``."""
    root = _read_tlv(pkcs7_der, 0)
    if root[0] != TAG_SEQUENCE or root[3] != len(pkcs7_der):
        raise ApkSignatureError("PKCS#7 ContentInfo is malformed or has trailing bytes")
    ci_fields = _walk_tlvs(pkcs7_der, root[2], root[3])
    if len(ci_fields) != 2 or ci_fields[0][0] != TAG_OID or ci_fields[1][0] != TAG_CONTEXT_0_CONSTRUCTED:
        raise ApkSignatureError("Malformed PKCS#7 ContentInfo")
    content_type = _decode_oid(pkcs7_der, ci_fields[0][2], ci_fields[0][3])
    if content_type != OID_SIGNED_DATA:
        raise ApkSignatureError(f"Expected SignedData OID, got {content_type}")

    sd_outer = _walk_tlvs(pkcs7_der, ci_fields[1][2], ci_fields[1][3])
    if len(sd_outer) != 1 or sd_outer[0][0] != TAG_SEQUENCE:
        raise ApkSignatureError("Malformed SignedData wrapper")
    sd_fields = _walk_tlvs(pkcs7_der, sd_outer[0][2], sd_outer[0][3])
    if len(sd_fields) < 4:
        raise ApkSignatureError("SignedData has too few fields")

    # version, digestAlgorithms, encapContentInfo
    if sd_fields[0][0] != TAG_INTEGER or sd_fields[1][0] != TAG_SET or sd_fields[2][0] != TAG_SEQUENCE:
        raise ApkSignatureError("Malformed SignedData header fields")
    encap_fields = _walk_tlvs(pkcs7_der, sd_fields[2][2], sd_fields[2][3])
    if not encap_fields or encap_fields[0][0] != TAG_OID:
        raise ApkSignatureError("SignedData encapContentInfo missing eContentType")
    encap_type = _decode_oid(pkcs7_der, encap_fields[0][2], encap_fields[0][3])
    if len(encap_fields) >= 2 and encap_fields[1][0] == TAG_CONTEXT_0_CONSTRUCTED:
        econtent_inner = _walk_tlvs(pkcs7_der, encap_fields[1][2], encap_fields[1][3])
        if len(econtent_inner) != 1 or econtent_inner[0][0] != TAG_OCTET_STRING:
            raise ApkSignatureError("Malformed attached encapContentInfo.eContent")
        attached = pkcs7_der[econtent_inner[0][2]:econtent_inner[0][3]]
        if attached != signed_content:
            raise ApkSignatureError("Attached PKCS#7 eContent does not match .SF content")

    certs: list[x509.Certificate] = []
    signer_infos_item: tuple[int, int, int, int] | None = None
    for item in sd_fields[3:]:
        tag, _off, v_start, v_end = item
        if tag == TAG_CONTEXT_0_CONSTRUCTED:
            for cert_item in _walk_tlvs(pkcs7_der, v_start, v_end):
                if cert_item[0] != TAG_SEQUENCE:
                    continue
                cert_der = pkcs7_der[cert_item[1]:cert_item[3]]
                try:
                    certs.append(x509.load_der_x509_certificate(cert_der))
                except ValueError as exc:
                    raise ApkSignatureError(f"Invalid X.509 certificate in PKCS#7: {exc}") from exc
        elif tag == TAG_SET:
            signer_infos_item = item

    if not certs:
        raise ApkSignatureError("PKCS#7 SignedData contains no certificates")
    if signer_infos_item is None:
        raise ApkSignatureError("PKCS#7 SignedData missing signerInfos")

    signer_items = _walk_tlvs(pkcs7_der, signer_infos_item[2], signer_infos_item[3])
    if not signer_items:
        raise ApkSignatureError("PKCS#7 SignedData has empty signerInfos")

    verified_signers: list[dict[str, Any]] = []
    for si_item in signer_items:
        if si_item[0] != TAG_SEQUENCE:
            raise ApkSignatureError("SignerInfo is not a SEQUENCE")
        si_fields = _walk_tlvs(pkcs7_der, si_item[2], si_item[3])
        if len(si_fields) < 5:
            raise ApkSignatureError("SignerInfo has too few fields")
        idx = 0
        if si_fields[idx][0] != TAG_INTEGER:
            raise ApkSignatureError("SignerInfo missing version")
        idx += 1
        sid_item = si_fields[idx]
        idx += 1
        if si_fields[idx][0] != TAG_SEQUENCE:
            raise ApkSignatureError("SignerInfo missing digestAlgorithm")
        digest_oid, _ = _parse_alg_id(pkcs7_der, si_fields[idx][2], si_fields[idx][3])
        if digest_oid not in DIGEST_OIDS:
            raise ApkSignatureError(f"Unsupported PKCS#7 digestAlgorithm OID: {digest_oid}")
        digest_name = DIGEST_OIDS[digest_oid][0]
        idx += 1

        signed_attrs_item: tuple[int, int, int, int] | None = None
        if idx < len(si_fields) and si_fields[idx][0] == TAG_CONTEXT_0_CONSTRUCTED:
            signed_attrs_item = si_fields[idx]
            idx += 1
        if idx + 1 >= len(si_fields):
            raise ApkSignatureError("SignerInfo missing signatureAlgorithm or signature")
        if si_fields[idx][0] != TAG_SEQUENCE:
            raise ApkSignatureError("SignerInfo signatureAlgorithm is not a SEQUENCE")
        sig_alg_oid, sig_alg_params = _parse_alg_id(
            pkcs7_der, si_fields[idx][2], si_fields[idx][3]
        )
        idx += 1
        if si_fields[idx][0] != TAG_OCTET_STRING:
            raise ApkSignatureError("SignerInfo signature is not an OCTET STRING")
        signature_bytes = pkcs7_der[si_fields[idx][2]:si_fields[idx][3]]

        cert = _match_certificate(pkcs7_der, sid_item, certs)
        if signed_attrs_item is not None:
            message_to_verify = _verify_signed_attrs(
                pkcs7_der, signed_attrs_item, digest_name, signed_content, encap_type
            )
        else:
            message_to_verify = signed_content

        _verify_asymmetric(
            cert,
            signature_bytes,
            message_to_verify,
            digest_name,
            sig_alg_oid,
            sig_alg_params,
            pkcs7_der,
        )
        verified_signers.append({
            "digest_algorithm": digest_name,
            "signature_algorithm_oid": sig_alg_oid,
            "certificate": summarize_certificate(cert),
        })

    return {
        "verified": True,
        "signer_count": len(verified_signers),
        "signers": verified_signers,
        "certificates": [s["certificate"] for s in verified_signers],
    }
