"""P1 contracts: APK identity — signing schemes, certificates, ABIs."""
from __future__ import annotations

import hashlib

from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface.handoff import build_location_map
from apkworkbench.analysis.surface.identity import (
    DerError,
    parse_apk_identity,
    parse_certificate,
)
from tests.identity_fixtures import (
    apk_unsigned,
    apk_v1,
    apk_v2,
    apk_v3,
    apk_with_abis,
    make_certificate,
)

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.example.app">
  <application android:label="Example" />
</manifest>"""


def _tree(tmp_path):
    root = tmp_path / "apktool"
    root.mkdir()
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    return root


def _write(tmp_path, payload: bytes, name: str = "base.apk"):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


def test_parse_certificate_reads_identity_fields():
    der = make_certificate(cn="Demo Signing", org="Demo Org", serial=0xABCD)
    parsed = parse_certificate(der)

    assert parsed["sha256"] == hashlib.sha256(der).hexdigest()
    assert parsed["subject"]["CN"] == "Demo Signing"
    assert parsed["subject"]["O"] == "Demo Org"
    assert parsed["issuer_text"] == parsed["subject_text"]
    assert parsed["self_issued"] is True
    assert parsed["serial"] == hex(0xABCD)
    assert parsed["not_before"] == "2024-01-01T00:00:00Z"
    assert parsed["not_after"] == "2034-01-01T00:00:00Z"


def test_parse_certificate_rejects_truncated_der():
    der = make_certificate()
    try:
        parse_certificate(der[: len(der) // 2])
    except DerError:
        return
    raise AssertionError("truncated DER must raise DerError")


def test_v2_signing_block_yields_the_certificate(tmp_path):
    certificate = make_certificate(cn="Release Key")
    apk = _write(tmp_path, apk_v2(certificate))

    identity = parse_apk_identity(apk)

    assert identity["status"] == "success"
    assert identity["schemes"] == ["v2"]
    assert len(identity["certificates"]) == 1
    entry = identity["certificates"][0]
    assert entry["sha256"] == hashlib.sha256(certificate).hexdigest()
    assert entry["subject"]["CN"] == "Release Key"
    assert entry["scheme"] == "v2"


def test_v3_records_the_sdk_range_it_covers(tmp_path):
    certificate = make_certificate(cn="Rotation Key")
    apk = _write(tmp_path, apk_v3(certificate, min_sdk=28, max_sdk=33))

    identity = parse_apk_identity(apk)

    assert identity["schemes"] == ["v3"]
    entry = identity["certificates"][0]
    assert entry["min_sdk"] == 28
    assert entry["max_sdk"] == 33


def test_v1_pkcs7_certificate_is_extracted(tmp_path):
    certificate = make_certificate(cn="Jar Key")
    apk = _write(tmp_path, apk_v1(certificate))

    identity = parse_apk_identity(apk)

    assert identity["schemes"] == ["v1"]
    assert identity["v1_signature_files"][0]["name"] == "META-INF/CERT.RSA"
    assert identity["v1_signature_files"][0]["certificate_sha256"] == hashlib.sha256(
        certificate
    ).hexdigest()
    assert identity["certificates"][0]["subject"]["CN"] == "Jar Key"


def test_unsigned_apk_is_reported_as_unsigned(tmp_path):
    apk = _write(tmp_path, apk_unsigned())

    identity = parse_apk_identity(apk)

    assert identity["status"] == "unsigned"
    assert identity["schemes"] == []


def test_abis_are_read_from_the_zip(tmp_path):
    apk = _write(tmp_path, apk_with_abis("arm64-v8a", "armeabi-v7a"))

    identity = parse_apk_identity(apk)

    assert identity["abis"] == ["arm64-v8a", "armeabi-v7a"]


def test_analyzer_emits_identity_facts_with_apk_citation(tmp_path):
    certificate = make_certificate(cn="Release Key")
    apk = _write(tmp_path, apk_v2(certificate, entries={
        "AndroidManifest.xml": b"<manifest/>",
        "classes.dex": b"dex\n035\x00",
        "lib/arm64-v8a/libx.so": b"\x7fELF",
    }))
    root = _tree(tmp_path)

    result = analyze_apk_surface(root, apk_path=apk)

    assert result["coverage"]["apk_identity"] == "success"
    kinds = {fact["kind"] for fact in result["facts"]}
    assert {"apk_signing_scheme", "apk_signing_certificate", "apk_abi"} <= kinds
    certificate_fact = next(
        fact for fact in result["facts"] if fact["kind"] == "apk_signing_certificate"
    )
    assert certificate_fact["value"] == hashlib.sha256(certificate).hexdigest()
    assert certificate_fact["subject"] == "CN=Release Key, O=Demo Org"
    assert certificate_fact["evidence"][0]["path"] == "apk:base.apk"
    # The APK citation must not be rewritten as a decoded-tree path.
    location_map = build_location_map(result, tree_root="apktool/")
    entry = next(
        item for item in location_map["entries"]
        if item["kind"] == "apk_signing_certificate"
    )
    assert entry["locations"] == ["apk:base.apk"]


def test_unsigned_apk_produces_a_finding(tmp_path):
    apk = _write(tmp_path, apk_unsigned())
    root = _tree(tmp_path)

    result = analyze_apk_surface(root, apk_path=apk)

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert "apk_unsigned" in rules
    assert result["coverage"]["apk_identity"] == "success"


def test_v1_only_and_debug_certificate_are_findings(tmp_path):
    certificate = make_certificate(cn="Android Debug", org="Android")
    apk = _write(tmp_path, apk_v1(certificate))
    root = _tree(tmp_path)

    result = analyze_apk_surface(root, apk_path=apk)

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert "apk_signed_v1_only" in rules
    assert "apk_debug_certificate" in rules


def test_without_an_apk_identity_is_not_guessed(tmp_path):
    root = _tree(tmp_path)

    result = analyze_apk_surface(root)

    assert result["coverage"]["apk_identity"] == "not_found"
    assert result["identity"]["status"] == "not_found"
    assert not any(fact["kind"].startswith("apk_") for fact in result["facts"])
