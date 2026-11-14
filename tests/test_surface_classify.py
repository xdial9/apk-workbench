"""S2 contracts: single-pass classification + original-APK zip inventory."""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import classify


def _make_tree(tmp_path):
    root = tmp_path / "decode"
    (root / "smali" / "com" / "x").mkdir(parents=True)
    (root / "smali" / "com" / "x" / "A.smali").write_text(".class Lcom/x/A;")
    (root / "res" / "values").mkdir(parents=True)
    (root / "res" / "values" / "strings.xml").write_text("<resources/>")
    (root / "assets").mkdir()
    (root / "assets" / "config.json").write_text('{"a": 1}')
    (root / "assets" / "bundle.zip").write_bytes(b"PK\x03\x04-not-really")
    (root / "assets" / "libcore.so").write_bytes(b"\x7fELFfake")
    (root / "assets" / "blob").write_bytes(b"\x00\x01\x02opaque")
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    return root


def test_classify_single_pass_counts_and_routes(tmp_path):
    tree = classify.classify_decoded_tree(_make_tree(tmp_path))
    assert tree.symlink_count == 0
    assert tree.extension_counts[".smali"] == 1
    assert tree.extension_counts[".xml"] == 2
    assert tree.extension_counts[".so"] == 1
    assert "(no extension)" in tree.extension_counts          # the opaque blob
    # magic-based routing: sniffed, not guessed from names
    kinds = {entry.relative: entry.content_kind for entry in tree.entries}
    assert kinds["assets/bundle.zip"] == "zip"
    assert kinds["assets/libcore.so"] == "elf"
    assert kinds["assets/blob"] is None                        # unknown binary
    assert kinds["assets/config.json"] is None                 # text candidate
    assert kinds["smali/com/x/A.smali"] is None
    classes = tree.class_counts
    assert classes["zip"] == 1 and classes["elf"] == 1
    assert classes["text"] == 4
    assert classes["unknown_binary"] == 1


def test_classify_counts_symlinks_and_unreadable_without_traversal_death(
    tmp_path,
):
    root = _make_tree(tmp_path)
    (root / "smali" / "link.smali").symlink_to(root / "smali" / "com" / "x" / "A.smali")
    tree = classify.classify_decoded_tree(root)
    assert tree.symlink_count == 1
    assert tree.summary()["symlink_entries_skipped"] == 1
    # files list stays compat-shaped and sorted
    assert tree.files == sorted(tree.files)


def test_analyzer_inventory_includes_classification(tmp_path):
    root = _make_tree(tmp_path)
    result = apk_surface.analyze_apk_surface(root)
    summary = result["inventory"]["classification"]
    assert summary["file_count"] == 7
    assert summary["symlink_entries_skipped"] == 0
    assert summary["content_class_counts"]["zip"] == 1
    # compat: TEXT_SUFFIXES still importable from the analyzer module
    assert apk_surface.TEXT_SUFFIXES == classify.TEXT_SUFFIXES


def test_apk_zip_inventory_maps_every_member(tmp_path):
    apk_path = tmp_path / "base.apk"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", b"dex\n000")
        archive.writestr("assets/nested.jar", b"PK\x03\x04nested")
        archive.writestr("res/values/strings.xml", "<resources><string/></resources>")
    apk_path.write_bytes(buffer.getvalue())

    inventory = classify.inventory_apk_zip(apk_path)

    names = [member["name"] for member in inventory["members"]]
    assert names == [
        "AndroidManifest.xml", "assets/nested.jar", "classes.dex",
        "res/values/strings.xml",
    ]
    by_name = {member["name"]: member for member in inventory["members"]}
    assert by_name["classes.dex"]["content_kind"] == "dex"
    assert by_name["assets/nested.jar"]["content_kind"] == "zip"
    import hashlib as _hashlib

    expected = _hashlib.sha256(b"dex\n000").hexdigest()
    assert by_name["classes.dex"]["sha256"] == expected
    assert inventory["nested_archives"] == ["assets/nested.jar"]
    assert inventory["file_count"] == 4
    assert inventory["total_uncompressed_bytes"] == sum(
        member["size"] for member in inventory["members"]
    )


def test_apk_zip_inventory_tolerates_encrypted_members(tmp_path):
    # An AES-encrypted member cannot be read by zipfile without a password;
    # the inventory must record it rather than crash (never hide).
    apk_path = tmp_path / "enc.apk"
    apk_path.write_bytes(b"not-a-zip")
    with pytest.raises(zipfile.BadZipFile):
        classify.inventory_apk_zip(apk_path)


def test_inventory_serializable_round_trip(tmp_path):
    apk_path = tmp_path / "base.apk"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("x.txt", "hello")
    apk_path.write_bytes(buffer.getvalue())
    inventory = classify.inventory_apk_zip(apk_path)
    assert json.loads(json.dumps(inventory))["file_count"] == 1