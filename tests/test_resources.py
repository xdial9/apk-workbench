"""P2a contracts: resources.arsc -> id / type / name / value."""
from __future__ import annotations

import io
import json
import zipfile

from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface.resources import (
    parse_resource_table,
    parse_string_pool,
)
from tests.arsc_fixtures import apk_with_arsc, build_arsc, string_pool

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.example.app">
  <application android:label="Example" />
</manifest>"""


def _apk(tmp_path, arsc: bytes, name: str = "base.apk"):
    path = tmp_path / name
    path.write_bytes(apk_with_arsc(arsc))
    return path


def test_string_pool_decodes_utf8_and_utf16():
    strings = ("Hello", "Wörld", "a" * 200)
    for utf8 in (True, False):
        pool = string_pool(strings, utf8=utf8)
        assert parse_string_pool(pool, 0) == list(strings)


def test_resource_table_maps_ids_to_names_and_values(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    records: list[dict] = []

    summary = parse_resource_table(apk, sink=records.append)

    assert summary["status"] == "success"
    assert summary["entry_count"] == len(records) == 5
    assert summary["packages"] == [{"id": "0x7f", "name": "com.example.app"}]
    by_id = {record["id"]: record for record in records}
    assert by_id["0x7f010000"]["name"] == "app_name"
    assert by_id["0x7f010000"]["value"] == "Hello"
    assert by_id["0x7f010000"]["type"] == "string"
    assert by_id["0x7f010000"]["config"] == "default"
    assert by_id["0x7f020000"]["value"] == "true"
    assert by_id["0x7f020000"]["value_type"] == "boolean"
    assert by_id["0x7f030000"]["value"] == "42"
    assert by_id["0x7f030000"]["value_type"] == "int_dec"


def test_resource_references_are_explicit(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    records: list[dict] = []

    parse_resource_table(apk, sink=records.append)

    reference = next(record for record in records if record["name"] == "alias")
    assert reference["value_type"] == "reference"
    assert reference["reference"] == "@0x7f010000"


def test_missing_resource_table_is_not_found(tmp_path):
    path = tmp_path / "plain.apk"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
    path.write_bytes(buffer.getvalue())

    summary = parse_resource_table(path)

    assert summary["status"] == "not_found"
    assert summary["diagnostics"][0]["code"] == "resource_table_absent"


def _tmp_apk(tmp_path, arsc: bytes):
    path = tmp_path / "corrupt.apk"
    path.write_bytes(apk_with_arsc(arsc, entries={"AndroidManifest.xml": b"<manifest/>"}))
    return path


def test_corrupt_resource_table_fails_honestly(tmp_path):
    apk = _tmp_apk(tmp_path, b"\x02\x00\x0c\x00garbage")

    summary = parse_resource_table(apk)

    assert summary["status"] == "failed"
    assert summary["diagnostics"][0]["code"] == "resource_table_parse_failed"
    assert summary["entry_count"] == 0


def test_analyzer_streams_resources_jsonl(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "res/values/strings.xml").write_text("<resources/>", encoding="utf-8")
    out = tmp_path / "artifact"

    result = analyze_apk_surface(root, output_dir=out, apk_path=apk)

    assert result["coverage"]["resource_model"] == "success"
    assert result["coverage"]["resource_inventory"] == "parsed"
    model = result["inventory"]["resource_model"]
    assert model["entry_count"] == 5
    assert model["resources_jsonl"] == "resources.jsonl"
    assert model["type_counts"] == {"bool": 1, "integer": 1, "string": 3}

    lines = (out / "resources.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    first = json.loads(lines[0])
    assert set(first) == {
        "id", "package", "type", "name", "config", "value", "value_type", "reference",
    }


def test_analyzer_without_apk_does_not_claim_a_resource_model(tmp_path):
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "res/values/strings.xml").write_text("<resources/>", encoding="utf-8")

    result = analyze_apk_surface(root)

    assert result["coverage"]["resource_model"] == "not_found"
    assert result["coverage"]["resource_inventory"] == "counted_not_parsed"
