"""Tests for cryptographic APK signature verification (v1 JAR and v2/v3 APK Signing Block)."""
from __future__ import annotations

import base64
import datetime
import hashlib
import io
import struct
import warnings
import zipfile
from pathlib import Path

import asn1crypto.cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from apkworkbench.analysis.surface.identity import parse_apk_identity
from apkworkbench.security import (
    verify_apk_signature,
    verify_pkcs7_signature,
    verify_v1_jar_signature,
    verify_v2_v3_signatures,
)
from apkworkbench.security.v2_v3 import (
    APK_SIG_BLOCK_MAGIC,
    STRIPPING_PROTECTION_ATTR_ID,
    V2_BLOCK_ID,
    V3_BLOCK_ID,
)

FIXTURE_APK = Path(__file__).parent / "fixtures" / "dex_code_model.apk"


def _make_self_signed_cert(key, cn: str = "Test APK Signer") -> x509.Certificate:
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "APK Workbench Tests"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )


def _lp(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def _chunked_digest(sections: list[bytes], alg_name: str = "sha256") -> bytes:
    chunk_digests: list[bytes] = []
    chunk_size = 1024 * 1024
    for sec in sections:
        for i in range(0, len(sec), chunk_size):
            chunk = sec[i:i + chunk_size]
            h = hashlib.new(alg_name)
            h.update(b"\xa5" + struct.pack("<I", len(chunk)) + chunk)
            chunk_digests.append(h.digest())
    top = hashlib.new(alg_name)
    top.update(b"\x5a" + struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        top.update(d)
    return top.digest()


def _build_unsigned_zip_bytes(
    entries: dict[str, bytes], *, compression: int = zipfile.ZIP_DEFLATED
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compression) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _build_dsa_pkcs7_der(cert: x509.Certificate, key: dsa.DSAPrivateKey, data: bytes) -> bytes:
    """Build a valid DER CMS SignedData block for DSA (PKCS7SignatureBuilder omits DSA)."""
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    sig = key.sign(data, hashes.SHA256())
    signer_info = asn1crypto.cms.SignerInfo({
        "version": "v1",
        "sid": asn1crypto.cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": asn1crypto.x509.Name.load(cert.issuer.public_bytes()),
                "serial_number": cert.serial_number,
            }
        }),
        "digest_algorithm": {"algorithm": "2.16.840.1.101.3.4.2.1"},
        "signature_algorithm": {"algorithm": "2.16.840.1.101.3.4.3.2"},
        "signature": sig,
    })
    signed_data = asn1crypto.cms.SignedData({
        "version": "v1",
        "digest_algorithms": [{"algorithm": "2.16.840.1.101.3.4.2.1"}],
        "encap_content_info": {"content_type": "data"},
        "certificates": [asn1crypto.x509.Certificate.load(cert_der)],
        "signer_infos": [signer_info],
    })
    return asn1crypto.cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    }).dump()


def _sign_v1_zip_bytes(
    entries: dict[str, bytes],
    key,
    cert: x509.Certificate,
    *,
    block_ext: str = "RSA",
    stem: str = "CERT",
    hash_alg: str = "sha256",
    x_android_apk_signed: str | None = None,
    pkcs7_options: list[pkcs7.PKCS7Options] | None = None,
    rsa_pss: bool = False,
) -> bytes:
    """Build a real v1 (JAR) signed APK in memory."""
    alg_header = "SHA-256-Digest" if hash_alg == "sha256" else "SHA1-Digest"
    mf_alg_header = (
        "SHA-256-Digest-Manifest" if hash_alg == "sha256" else "SHA1-Digest-Manifest"
    )
    main_alg_header = (
        "SHA-256-Digest-Manifest-Main-Attributes"
        if hash_alg == "sha256"
        else "SHA1-Digest-Manifest-Main-Attributes"
    )

    mf_main = b"Manifest-Version: 1.0\r\nCreated-By: apkworkbench-test\r\n\r\n"
    mf_sections: list[tuple[str, bytes]] = []
    for name in sorted(entries):
        digest_b64 = base64.b64encode(hashlib.new(hash_alg, entries[name]).digest()).decode("ascii")
        sec = f"Name: {name}\r\n{alg_header}: {digest_b64}\r\n\r\n".encode()
        mf_sections.append((name, sec))
    manifest_bytes = mf_main + b"".join(sec for _, sec in mf_sections)

    sf_lines = [
        b"Signature-Version: 1.0\r\n",
        b"Created-By: apkworkbench-test\r\n",
        f"{mf_alg_header}: {base64.b64encode(hashlib.new(hash_alg, manifest_bytes).digest()).decode('ascii')}\r\n".encode(),
        f"{main_alg_header}: {base64.b64encode(hashlib.new(hash_alg, mf_main).digest()).decode('ascii')}\r\n".encode(),
    ]
    if x_android_apk_signed is not None:
        sf_lines.append(f"X-Android-APK-Signed: {x_android_apk_signed}\r\n".encode())
    sf_lines.append(b"\r\n")
    for name, sec in mf_sections:
        sec_digest = base64.b64encode(hashlib.new(hash_alg, sec).digest()).decode("ascii")
        sf_lines.append(f"Name: {name}\r\n{alg_header}: {sec_digest}\r\n\r\n".encode())
    sf_bytes = b"".join(sf_lines)

    if isinstance(key, dsa.DSAPrivateKey):
        block_bytes = _build_dsa_pkcs7_der(cert, key, sf_bytes)
    else:
        opts = pkcs7_options or [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]
        crypto_hash = hashes.SHA256() if hash_alg == "sha256" else hashes.SHA1()
        rsa_pad = (
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            if rsa_pss
            else None
        )
        block_bytes = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(sf_bytes)
            .add_signer(cert, key, crypto_hash, rsa_padding=rsa_pad)
            .sign(serialization.Encoding.DER, opts)
        )

    all_entries = dict(entries)
    all_entries["META-INF/MANIFEST.MF"] = manifest_bytes
    all_entries[f"META-INF/{stem}.SF"] = sf_bytes
    all_entries[f"META-INF/{stem}.{block_ext}"] = block_bytes
    return _build_unsigned_zip_bytes(all_entries)


def _sign_v2_v3_zip_bytes(
    base_zip_bytes: bytes,
    *,
    v2_signers: list[tuple[object, x509.Certificate, int]] | None = None,
    v3_signers: list[tuple[object, x509.Certificate, int, int, int]] | None = None,
) -> bytes:
    """Attach a real APK Signing Block (v2 and/or v3) to ``base_zip_bytes``."""
    eocd_off = base_zip_bytes.rfind(b"PK\x05\x06")
    assert eocd_off >= 0
    cd_offset = struct.unpack_from("<I", base_zip_bytes, eocd_off + 16)[0]
    contents = base_zip_bytes[:cd_offset]
    cd = base_zip_bytes[cd_offset:eocd_off]
    eocd = base_zip_bytes[eocd_off:]

    digest_256 = _chunked_digest([contents, cd, eocd], "sha256")
    digest_512 = _chunked_digest([contents, cd, eocd], "sha512")

    def sign_blob(key, alg_id: int, data: bytes) -> bytes:
        if alg_id == 0x0101:
            return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        if alg_id == 0x0102:
            return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64), hashes.SHA512())
        if alg_id == 0x0103:
            return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        if alg_id == 0x0201:
            return key.sign(data, ec.ECDSA(hashes.SHA256()))
        if alg_id == 0x0301:
            return key.sign(data, hashes.SHA256())
        raise ValueError(f"Unsupported test alg_id {hex(alg_id)}")

    def build_signer_bytes(key, cert: x509.Certificate, alg_id: int, sdk_range: tuple[int, int] | None) -> bytes:
        content_digest = digest_512 if alg_id in (0x0102, 0x0104, 0x0202) else digest_256
        digests_blob = _lp(_lp(struct.pack("<I", alg_id) + _lp(content_digest)))
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        certs_blob = _lp(_lp(cert_der))
        attrs_blob = _lp(b"")
        sdk_bytes = struct.pack("<II", *sdk_range) if sdk_range is not None else b""
        signed_data = digests_blob + certs_blob + sdk_bytes + attrs_blob
        sig = sign_blob(key, alg_id, signed_data)
        sigs_blob = _lp(_lp(struct.pack("<I", alg_id) + _lp(sig)))
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return _lp(signed_data) + sdk_bytes + sigs_blob + _lp(spki)

    pairs_buf = bytearray()
    if v2_signers:
        signers_concat = b"".join(_lp(build_signer_bytes(k, c, a, None)) for k, c, a in v2_signers)
        val = _lp(signers_concat)
        pairs_buf += struct.pack("<QI", 4 + len(val), V2_BLOCK_ID) + val
    if v3_signers:
        signers_concat = b"".join(
            _lp(build_signer_bytes(k, c, a, (min_sdk, max_sdk)))
            for k, c, a, min_sdk, max_sdk in v3_signers
        )
        val = _lp(signers_concat)
        pairs_buf += struct.pack("<QI", 4 + len(val), V3_BLOCK_ID) + val

    block_size = len(pairs_buf) + 24
    signing_block = (
        struct.pack("<Q", block_size)
        + bytes(pairs_buf)
        + struct.pack("<Q", block_size)
        + APK_SIG_BLOCK_MAGIC
    )
    new_cd_offset = len(contents) + len(signing_block)
    new_eocd = bytearray(eocd)
    struct.pack_into("<I", new_eocd, 16, new_cd_offset)
    return contents + signing_block + cd + bytes(new_eocd)


# ---- Tests: Valid APKs (v1, v2, v3, combined, fixture) ----------------------


def test_v1_rsa_ecdsa_dsa_signatures_verify(tmp_path: Path) -> None:
    entries = {
        "AndroidManifest.xml": b"<manifest package='com.example.test'/>",
        "classes.dex": b"dex\n035\x00" + b"\x11" * 128,
        "res/raw/config.json": b'{"endpoint":"https://example.test"}',
    }
    cases = [
        ("rsa_attrs", rsa.generate_private_key(65537, 2048), "RSA", None, False),
        ("rsa_pss", rsa.generate_private_key(65537, 2048), "RSA", None, True),
        (
            "rsa_no_attrs",
            rsa.generate_private_key(65537, 2048),
            "RSA",
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary, pkcs7.PKCS7Options.NoAttributes],
            False,
        ),
        ("ecdsa", ec.generate_private_key(ec.SECP256R1()), "EC", None, False),
        ("dsa", dsa.generate_private_key(2048), "DSA", None, False),
    ]
    for label, key, ext, opts, is_pss in cases:
        cert = _make_self_signed_cert(key, cn=f"Signer-{label}")
        apk_bytes = _sign_v1_zip_bytes(
            entries, key, cert, block_ext=ext, pkcs7_options=opts, rsa_pss=is_pss
        )
        apk = tmp_path / f"{label}.apk"
        apk.write_bytes(apk_bytes)

        res = verify_apk_signature(apk)
        assert res["status"] == "verified", f"{label}: {res}"
        assert res["verified"] is True
        assert res["schemes_present"] == ["v1"]
        assert res["schemes_verified"] == ["v1"]
        assert res["schemes"]["v1"]["entries_verified"] == len(entries)
        expected_sha256 = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assert [c["sha256"] for c in res["certificates"]] == [expected_sha256]


def test_v2_signatures_verify_including_multichunk_and_algorithms(tmp_path: Path) -> None:
    # Over 1 MiB uncompressed/stored payload so chunked Merkle digest spans multiple 1 MiB chunks.
    big_blob = b"A" * (1024 * 1024 + 4096)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest/>")
        zf.writestr("assets/big.bin", big_blob)
    base_zip = buf.getvalue()

    rsa_key = rsa.generate_private_key(65537, 2048)
    rsa_cert = _make_self_signed_cert(rsa_key, cn="v2-rsa")
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_cert = _make_self_signed_cert(ec_key, cn="v2-ec")

    for label, signer in [
        ("pss256", (rsa_key, rsa_cert, 0x0101)),
        ("pss512", (rsa_key, rsa_cert, 0x0102)),
        ("pkcs1_256", (rsa_key, rsa_cert, 0x0103)),
        ("ecdsa256", (ec_key, ec_cert, 0x0201)),
    ]:
        apk = tmp_path / f"v2_{label}.apk"
        apk.write_bytes(_sign_v2_v3_zip_bytes(base_zip, v2_signers=[signer]))
        res = verify_apk_signature(apk)
        assert res["status"] == "verified", f"{label}: {res}"
        assert res["verified"] is True
        assert res["schemes_present"] == ["v2"]
        assert res["schemes_verified"] == ["v2"]


def test_v3_and_combined_v1_v2_v3_verify_and_match_identity(tmp_path: Path) -> None:
    entries = {
        "AndroidManifest.xml": b"<manifest package='com.example.combined'/>",
        "classes.dex": b"dex\n035\x00" + b"\x22" * 64,
    }
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_self_signed_cert(key, cn="Combined Signer")
    v1_zip = _sign_v1_zip_bytes(entries, key, cert, block_ext="EC", x_android_apk_signed="2, 3")
    full_apk_bytes = _sign_v2_v3_zip_bytes(
        v1_zip,
        v2_signers=[(key, cert, 0x0201)],
        v3_signers=[(key, cert, 0x0201, 28, 0xFFFFFFFF)],
    )
    apk = tmp_path / "combined.apk"
    apk.write_bytes(full_apk_bytes)

    res = verify_apk_signature(apk)
    assert res["status"] == "verified", res
    assert res["verified"] is True
    assert res["schemes_present"] == ["v1", "v2", "v3"]
    assert res["schemes_verified"] == ["v1", "v2", "v3"]
    assert res["schemes"]["v3"]["signers"][0]["min_sdk"] == 28
    assert res["schemes"]["v3"]["signers"][0]["max_sdk"] == 0xFFFFFFFF

    # Cross-check certificate SHA-256 with surface.identity (read-only)
    ident = parse_apk_identity(apk)
    assert ident["status"] == "success"
    assert res["certificates"][0]["sha256"] == ident["certificates"][0]["sha256"]


def test_fixture_dex_code_model_apk_state_and_re_signed_copy(tmp_path: Path) -> None:
    assert FIXTURE_APK.is_file()
    fixture_res = verify_apk_signature(FIXTURE_APK)
    # tests/fixtures/dex_code_model.apk is an unsigned minimal fixture APK.
    assert fixture_res["status"] == "unsigned"
    assert fixture_res["verified"] is False
    assert fixture_res["schemes_present"] == []
    assert fixture_res["schemes_verified"] == []

    # Copy its entries, sign with v1 + v2, and prove verification succeeds.
    with zipfile.ZipFile(FIXTURE_APK, "r") as zf:
        entries = {i.filename: zf.read(i.filename) for i in zf.infolist() if not i.is_dir()}
    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key, cn="Fixture Re-signer")
    v1_zip = _sign_v1_zip_bytes(entries, key, cert, x_android_apk_signed="2")
    signed_bytes = _sign_v2_v3_zip_bytes(v1_zip, v2_signers=[(key, cert, 0x0101)])
    signed_copy = tmp_path / "dex_code_model_signed.apk"
    signed_copy.write_bytes(signed_bytes)

    signed_res = verify_apk_signature(signed_copy)
    assert signed_res["status"] == "verified", signed_res
    assert signed_res["verified"] is True
    assert signed_res["schemes_verified"] == ["v1", "v2"]


# ---- Tests: Tampered / malformed APKs fail ----------------------------------


def test_v1_tampered_zip_entry_fails(tmp_path: Path) -> None:
    entries = {"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex-original"}
    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key)
    signed_bytes = _sign_v1_zip_bytes(entries, key, cert)

    # Replace classes.dex content without updating META-INF/MANIFEST.MF
    buf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf, "w") as zout:
        for info in zin.infolist():
            data = b"dex-TAMPERED" if info.filename == "classes.dex" else zin.read(info.filename)
            zout.writestr(info.filename, data)

    apk = tmp_path / "tampered_entry.apk"
    apk.write_bytes(buf.getvalue())
    res = verify_apk_signature(apk)
    assert res["status"] == "failed"
    assert res["verified"] is False
    assert any("digest mismatch" in err.lower() for err in res["errors"])


def test_v1_tampered_manifest_and_sf_and_wrong_key_fail(tmp_path: Path) -> None:
    entries = {"AndroidManifest.xml": b"<manifest/>", "classes.dex": b"dex-original"}
    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key)
    signed_bytes = _sign_v1_zip_bytes(entries, key, cert)

    # 1. Unsigned extra entry injected into ZIP
    buf_extra = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf_extra, "w") as zout:
        for info in zin.infolist():
            zout.writestr(info.filename, zin.read(info.filename))
        zout.writestr("assets/injected.bin", b"evil")
    apk_extra = tmp_path / "extra_entry.apk"
    apk_extra.write_bytes(buf_extra.getvalue())
    assert verify_apk_signature(apk_extra)["verified"] is False

    # 2. Tamper MANIFEST.MF entry digest without updating .SF
    buf_mf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf_mf, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "META-INF/MANIFEST.MF":
                data = data.replace(b"apkworkbench-test", b"apkworkbench-hack")
            zout.writestr(info.filename, data)
    apk_mf = tmp_path / "tampered_mf.apk"
    apk_mf.write_bytes(buf_mf.getvalue())
    res_mf = verify_apk_signature(apk_mf)
    assert res_mf["verified"] is False
    assert any("digest mismatch" in e.lower() for e in res_mf["errors"])

    # 3. Tamper .SF without updating .RSA PKCS#7 signature
    buf_sf = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf_sf, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "META-INF/CERT.SF":
                data = data.replace(b"apkworkbench-test", b"apkworkbench-hack")
            zout.writestr(info.filename, data)
    apk_sf = tmp_path / "tampered_sf.apk"
    apk_sf.write_bytes(buf_sf.getvalue())
    res_sf = verify_apk_signature(apk_sf)
    assert res_sf["verified"] is False

    # 4. Wrong signature: replace CERT.RSA with PKCS#7 signed by a different key/data
    other_key = rsa.generate_private_key(65537, 2048)
    other_cert = _make_self_signed_cert(other_key, cn="Other")
    wrong_rsa = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"not-the-sf-bytes")
        .add_signer(other_cert, other_key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    buf_wrong = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf_wrong, "w") as zout:
        for info in zin.infolist():
            data = wrong_rsa if info.filename == "META-INF/CERT.RSA" else zin.read(info.filename)
            zout.writestr(info.filename, data)
    apk_wrong = tmp_path / "wrong_sig.apk"
    apk_wrong.write_bytes(buf_wrong.getvalue())
    assert verify_apk_signature(apk_wrong)["verified"] is False


def test_v1_duplicate_zip_entry_rejected(tmp_path: Path) -> None:
    entries = {"classes.dex": b"legit"}
    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key)
    signed_bytes = _sign_v1_zip_bytes(entries, key, cert)

    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(io.BytesIO(signed_bytes), "r") as zin, zipfile.ZipFile(buf, "w") as zout:
            for info in zin.infolist():
                zout.writestr(info.filename, zin.read(info.filename))
            zout.writestr("classes.dex", b"shadowed")
    apk = tmp_path / "dup.apk"
    apk.write_bytes(buf.getvalue())
    res = verify_v1_jar_signature(apk)
    assert res["verified"] is False
    assert any("duplicate" in e.lower() for e in res["errors"])


def test_v2_tampered_zip_payload_and_signing_block_and_digest_fail(tmp_path: Path) -> None:
    base_zip = _build_unsigned_zip_bytes(
        {
            "AndroidManifest.xml": b"<manifest package='com.example.v2'/>",
            "classes.dex": b"dex\n035\x00PAYLOAD_MARKER_1234",
        },
        compression=zipfile.ZIP_STORED,
    )
    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key)
    signed = _sign_v2_v3_zip_bytes(base_zip, v2_signers=[(key, cert, 0x0101)])

    # 1. Flip a byte inside the ZIP payload (section 1)
    idx = signed.find(b"PAYLOAD_MARKER_1234")
    assert idx > 0
    tampered_payload = bytearray(signed)
    tampered_payload[idx] ^= 0xFF
    p1 = tmp_path / "v2_tampered_payload.apk"
    p1.write_bytes(bytes(tampered_payload))
    r1 = verify_apk_signature(p1)
    assert r1["verified"] is False
    assert r1["status"] == "failed"

    # 2. Flip a byte inside the APK Signing Block signature/digest area
    magic_pos = signed.find(APK_SIG_BLOCK_MAGIC)
    assert magic_pos > 100
    tampered_block = bytearray(signed)
    tampered_block[magic_pos - 40] ^= 0x01
    p2 = tmp_path / "v2_tampered_block.apk"
    p2.write_bytes(bytes(tampered_block))
    r2 = verify_apk_signature(p2)
    assert r2["verified"] is False
    assert r2["status"] == "failed"

    # 3. Corrupt the APK Signing Block magic / footer size
    tampered_magic = bytearray(signed)
    tampered_magic[magic_pos] = ord("X")
    p3 = tmp_path / "v2_bad_magic.apk"
    p3.write_bytes(bytes(tampered_magic))
    r3 = verify_apk_signature(p3)
    assert r3["status"] == "unsigned"
    assert r3["verified"] is False

    # 4. Append trailing bytes after EOCD
    p4 = tmp_path / "v2_trailing_bytes.apk"
    p4.write_bytes(signed + b"TRAILING")
    r4 = verify_apk_signature(p4)
    assert r4["status"] == "failed"
    assert r4["verified"] is False


def test_v2_key_substitution_attack_fails(tmp_path: Path) -> None:
    """An attacker re-signs signed_data with their own public_key while keeping victim's cert."""
    base_zip = _build_unsigned_zip_bytes({"classes.dex": b"dex"})
    victim_key = rsa.generate_private_key(65537, 2048)
    victim_cert = _make_self_signed_cert(victim_key, cn="Victim")
    attacker_key = rsa.generate_private_key(65537, 2048)

    # Craft a v2 signing block where signed_data contains victim_cert,
    # but signature + public_key come from attacker_key.
    eocd_off = base_zip.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", base_zip, eocd_off + 16)[0]
    contents, cd, eocd = base_zip[:cd_offset], base_zip[cd_offset:eocd_off], base_zip[eocd_off:]
    digest = _chunked_digest([contents, cd, eocd], "sha256")
    signed_data = (
        _lp(_lp(struct.pack("<I", 0x0101) + _lp(digest)))
        + _lp(_lp(victim_cert.public_bytes(serialization.Encoding.DER)))
        + _lp(b"")
    )
    sig = attacker_key.sign(
        signed_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    attacker_spki = attacker_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer = _lp(signed_data) + _lp(_lp(struct.pack("<I", 0x0101) + _lp(sig))) + _lp(attacker_spki)
    val = _lp(_lp(signer))
    pair = struct.pack("<QI", 4 + len(val), V2_BLOCK_ID) + val
    block_size = len(pair) + 24
    block = struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    new_eocd = bytearray(eocd)
    struct.pack_into("<I", new_eocd, 16, len(contents) + len(block))

    apk = tmp_path / "key_sub.apk"
    apk.write_bytes(contents + block + cd + bytes(new_eocd))
    res = verify_v2_v3_signatures(apk)
    assert res["v2"]["verified"] is False
    assert any("public_key does not match" in e for e in res["v2"]["errors"])


def test_v3_sdk_mismatch_and_downgrade_protection_fail(tmp_path: Path) -> None:
    entries = {"classes.dex": b"dex-v3"}
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_self_signed_cert(key)

    # 1. Downgrade: v1 claims X-Android-APK-Signed: 2, 3, but no signing block is attached
    v1_only_claiming_v2 = _sign_v1_zip_bytes(
        entries, key, cert, block_ext="EC", x_android_apk_signed="2, 3"
    )
    apk_down = tmp_path / "downgrade.apk"
    apk_down.write_bytes(v1_only_claiming_v2)
    res_down = verify_apk_signature(apk_down)
    assert res_down["status"] == "failed"
    assert res_down["verified"] is False
    assert any("downgrade" in e for e in res_down["errors"])

    # 2. v3 outer SDK range disagrees with inner signed_data SDK range
    base_zip = _build_unsigned_zip_bytes(entries)
    eocd_off = base_zip.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", base_zip, eocd_off + 16)[0]
    contents, cd, eocd = base_zip[:cd_offset], base_zip[cd_offset:eocd_off], base_zip[eocd_off:]
    digest = _chunked_digest([contents, cd, eocd], "sha256")
    signed_data = (
        _lp(_lp(struct.pack("<I", 0x0201) + _lp(digest)))
        + _lp(_lp(cert.public_bytes(serialization.Encoding.DER)))
        + struct.pack("<II", 28, 0xFFFFFFFF)
        + _lp(b"")
    )
    sig = key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signer = (
        _lp(signed_data)
        + struct.pack("<II", 21, 0xFFFFFFFF)  # mismatched outer min_sdk!
        + _lp(_lp(struct.pack("<I", 0x0201) + _lp(sig)))
        + _lp(spki)
    )
    val = _lp(_lp(signer))
    pair = struct.pack("<QI", 4 + len(val), V3_BLOCK_ID) + val
    block_size = len(pair) + 24
    block = struct.pack("<Q", block_size) + pair + struct.pack("<Q", block_size) + APK_SIG_BLOCK_MAGIC
    new_eocd = bytearray(eocd)
    struct.pack_into("<I", new_eocd, 16, len(contents) + len(block))

    apk_v3_bad = tmp_path / "v3_sdk_mismatch.apk"
    apk_v3_bad.write_bytes(contents + block + cd + bytes(new_eocd))
    res_v3 = verify_apk_signature(apk_v3_bad)
    assert res_v3["verified"] is False
    assert any("SDK range mismatch" in e for e in res_v3["schemes"]["v3"]["errors"])


def test_pkcs7_direct_corrupt_and_missing_file(tmp_path: Path) -> None:
    res_missing = verify_apk_signature(tmp_path / "does_not_exist.apk")
    assert res_missing["status"] == "failed"
    assert res_missing["verified"] is False

    key = rsa.generate_private_key(65537, 2048)
    cert = _make_self_signed_cert(key)
    sig_der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"sf-payload")
        .add_signer(cert, key, hashes.SHA256())
        .sign(
            serialization.Encoding.DER,
            [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
        )
    )
    ok = verify_pkcs7_signature(sig_der, b"sf-payload")
    assert ok["verified"] is True

    # Tampered sf-payload fails
    try:
        verify_pkcs7_signature(sig_der, b"sf-tampered")
    except ValueError as exc:
        assert "mismatch" in str(exc).lower()
    else:  # pragma: no cover
        raise AssertionError("Expected tampered PKCS#7 payload to fail")


def test_v2_apksig_trailing_bytes_in_signed_data_and_stripping_protection(tmp_path: Path) -> None:
    """apksig-style v2 signed_data trailing empty field (00000000) & 0xbeeff00d stripping check."""
    base_zip = _build_unsigned_zip_bytes({"classes.dex": b"dex-apksig-compat"})
    eocd_off = base_zip.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", base_zip, eocd_off + 16)[0]
    contents, cd, eocd = base_zip[:cd_offset], base_zip[cd_offset:eocd_off], base_zip[eocd_off:]
    digest = _chunked_digest([contents, cd, eocd], "sha256")

    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_self_signed_cert(key, cn="Apksig Compat")
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    def build_apk_with_blocks(
        v2_attrs: bytes, v2_trailing: bytes, *, include_v3: bool
    ) -> bytes:
        v2_sd = (
            _lp(_lp(struct.pack("<I", 0x0201) + _lp(digest)))
            + _lp(_lp(cert_der))
            + _lp(v2_attrs)
            + v2_trailing
        )
        v2_sig = key.sign(v2_sd, ec.ECDSA(hashes.SHA256()))
        v2_signer = _lp(v2_sd) + _lp(_lp(struct.pack("<I", 0x0201) + _lp(v2_sig))) + _lp(spki)
        v2_val = _lp(_lp(v2_signer))
        pairs_buf = bytearray(struct.pack("<QI", 4 + len(v2_val), V2_BLOCK_ID) + v2_val)
        if include_v3:
            sdk = struct.pack("<II", 28, 0xFFFFFFFF)
            v3_sd = (
                _lp(_lp(struct.pack("<I", 0x0201) + _lp(digest)))
                + _lp(_lp(cert_der))
                + sdk
                + _lp(b"")
            )
            v3_sig = key.sign(v3_sd, ec.ECDSA(hashes.SHA256()))
            v3_signer = (
                _lp(v3_sd)
                + sdk
                + _lp(_lp(struct.pack("<I", 0x0201) + _lp(v3_sig)))
                + _lp(spki)
            )
            v3_val = _lp(_lp(v3_signer))
            pairs_buf += struct.pack("<QI", 4 + len(v3_val), V3_BLOCK_ID) + v3_val

        block_size = len(pairs_buf) + 24
        block = (
            struct.pack("<Q", block_size)
            + bytes(pairs_buf)
            + struct.pack("<Q", block_size)
            + APK_SIG_BLOCK_MAGIC
        )
        new_eocd = bytearray(eocd)
        struct.pack_into("<I", new_eocd, 16, len(contents) + len(block))
        return contents + block + cd + bytes(new_eocd)

    strip_attr = _lp(struct.pack("<II", STRIPPING_PROTECTION_ATTR_ID, 3))

    # 1. Valid v2 (with 0xbeeff00d=3 and trailing 00000000 in signed_data) + valid v3 -> PASSES
    ok_apk = tmp_path / "apksig_v2_v3_ok.apk"
    ok_apk.write_bytes(build_apk_with_blocks(strip_attr, b"\x00\x00\x00\x00", include_v3=True))
    res_ok = verify_apk_signature(ok_apk)
    assert res_ok["status"] == "verified", res_ok
    assert res_ok["verified"] is True
    assert res_ok["schemes_verified"] == ["v2", "v3"]

    # 2. v2 with trailing 00000000 alone (without 0xbeeff00d) -> PASSES
    v2_only_apk = tmp_path / "apksig_v2_trailing_only.apk"
    v2_only_apk.write_bytes(build_apk_with_blocks(b"", b"\x00\x00\x00\x00", include_v3=False))
    res_v2 = verify_apk_signature(v2_only_apk)
    assert res_v2["status"] == "verified", res_v2
    assert res_v2["verified"] is True

    # 3. Stripping attack: v2 declares 0xbeeff00d=3, but v3 block is absent -> FAILS
    stripped_apk = tmp_path / "apksig_v3_stripped.apk"
    stripped_apk.write_bytes(build_apk_with_blocks(strip_attr, b"\x00\x00\x00\x00", include_v3=False))
    res_stripped = verify_apk_signature(stripped_apk)
    assert res_stripped["status"] == "failed"
    assert res_stripped["verified"] is False
    assert any("0xbeeff00d" in e for e in res_stripped["errors"])

    # 4. Flip a byte inside the trailing 00000000 bytes after signing -> signature verification FAILS
    raw = bytearray(v2_only_apk.read_bytes())
    magic_pos = raw.find(APK_SIG_BLOCK_MAGIC)
    # Locate the 4 trailing zero bytes right after empty attrs inside signed_data
    marker = _lp(cert_der) + _lp(b"") + b"\x00\x00\x00\x00"
    pos = raw.find(marker, 0, magic_pos)
    assert pos != -1
    raw[pos + len(marker) - 1] = 0x01
    tampered_trailing = tmp_path / "apksig_v2_tampered_trailing.apk"
    tampered_trailing.write_bytes(bytes(raw))
    res_tampered = verify_apk_signature(tampered_trailing)
    assert res_tampered["status"] == "failed"
    assert res_tampered["verified"] is False
