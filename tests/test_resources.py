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
        "id", "package", "type", "name", "config", "value", "value_type",
        "reference", "file",
    }


def test_analyzer_without_apk_does_not_claim_a_resource_model(tmp_path):
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "res/values/strings.xml").write_text("<resources/>", encoding="utf-8")

    result = analyze_apk_surface(root)

    assert result["coverage"]["resource_model"] == "not_found"
    assert result["coverage"]["resource_inventory"] == "counted_not_parsed"


def test_value_files_index_prefers_the_plain_values_dir(tmp_path):
    from apkworkbench.analysis.surface.resources import index_value_files

    root = tmp_path / "apktool"
    (root / "res/values-fr").mkdir(parents=True)
    (root / "res/values").mkdir(parents=True)
    (root / "res/values-fr/strings.xml").write_text(
        '<resources><string name="app_name">Démo</string></resources>', encoding="utf-8"
    )
    (root / "res/values/strings.xml").write_text(
        '<resources><string name="app_name">Demo</string>'
        '<string name="only_default">x</string></resources>', encoding="utf-8"
    )
    files = sorted(root.rglob("*.xml"))

    index = index_value_files(root, files)

    assert index[("string", "app_name")] == "res/values/strings.xml"
    assert index[("string", "only_default")] == "res/values/strings.xml"


def test_resource_records_carry_their_definition_file(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "res/values/strings.xml").write_text(
        '<resources><string name="app_name">Demo</string>'
        '<string name="greeting">Hi</string></resources>', encoding="utf-8"
    )
    out = tmp_path / "artifact"

    analyze_apk_surface(root, output_dir=out, apk_path=apk)

    records = [
        json.loads(line)
        for line in (out / "resources.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    by_name = {record["name"]: record for record in records}
    assert by_name["app_name"]["file"] == "res/values/strings.xml"
    # A resource that is not declared in the decoded tree has no file, not a guess.
    assert by_name["flag"]["file"] is None


def test_smali_resource_ids_resolve_to_named_facts(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    root = tmp_path / "apktool"
    (root / "res/values").mkdir(parents=True)
    (root / "smali/com/x").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "res/values/strings.xml").write_text(
        '<resources><string name="app_name">Demo</string></resources>', encoding="utf-8"
    )
    (root / "smali/com/x/A.smali").write_text(
        ".class Lcom/x/A;\nconst v0, 0x7f010000\nconst v1, 0x7f010001\n",
        encoding="utf-8",
    )

    result = analyze_apk_surface(root, apk_path=apk)

    used = [fact for fact in result["facts"] if fact["kind"] == "resource_id_used"]
    assert {fact["value"] for fact in used} == {"0x7f010000", "0x7f010001"}
    app_name = next(fact for fact in used if fact["value"] == "0x7f010000")
    assert app_name["type"] == "string"
    assert app_name["name"] == "app_name"
    assert app_name["file"] == "res/values/strings.xml"
    assert app_name["evidence"][0]["path"] == "smali/com/x/A.smali"
    assert app_name["evidence"][0]["line"] == 2
    assert result["coverage"]["resource_links"] == "success"
    assert result["metrics"]["resource_ids_resolved"] == 2
    assert result["metrics"]["resource_ids_unresolved"] == 0


def test_unresolved_resource_id_is_recorded_with_a_reason(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    root = tmp_path / "apktool"
    (root / "smali").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "smali/A.smali").write_text(
        ".class LA;\nconst v0, 0x7f999999\n", encoding="utf-8"
    )

    result = analyze_apk_surface(root, apk_path=apk)

    unresolved = [
        fact for fact in result["facts"] if fact["kind"] == "resource_id_unresolved"
    ]
    assert len(unresolved) == 1
    assert unresolved[0]["value"] == "0x7f999999"
    assert unresolved[0]["reason"] == "not_in_resource_table"
    assert result["coverage"]["resource_links"] == "partial"
    assert result["metrics"]["resource_ids_unresolved"] == 1


def test_no_resource_id_use_is_not_applicable(tmp_path):
    apk = _apk(tmp_path, build_arsc())
    root = tmp_path / "apktool"
    (root / "smali").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    (root / "smali/A.smali").write_text(".class LA;\n", encoding="utf-8")

    result = analyze_apk_surface(root, apk_path=apk)

    assert result["coverage"]["resource_links"] == "not_applicable"
    assert result["metrics"]["resource_id_references"] == 0
