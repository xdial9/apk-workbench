"""P0 contracts: the per-file coverage ledger (files.jsonl).

Completeness law: every entry is accounted for, and checked != skipped.
"""
from __future__ import annotations

import json
import stat

from apkworkbench.analysis import apk_surface
from apkworkbench.analysis.surface import classify, ledger


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
    (root / "assets" / "empty.dat").write_bytes(b"")
    (root / "assets" / "packed.so").write_bytes(b"PK\x03\x04packed-so")
    (root / "AndroidManifest.xml").write_text("<manifest/>")
    return root


def test_ledger_accounts_for_every_entry(tmp_path):
    root = _make_tree(tmp_path)
    (root / "smali" / "link.smali").symlink_to(root / "smali" / "com" / "x" / "A.smali")

    out = tmp_path / "artifact"
    result = apk_surface.analyze_apk_surface(root, ledger_dir=out)

    records = [
        json.loads(line)
        for line in (out / "files.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    tree = classify.classify_decoded_tree(root)
    # Every classified entry plus every symlink appears exactly once.
    assert len(records) == len(tree.entries) + len(tree.symlinks)
    assert [item["path"] for item in records] == sorted(item["path"] for item in records)
    assert len({item["path"] for item in records}) == len(records)

    summary = result["inventory"]["file_ledger"]
    assert summary["written"] is True
    assert summary["total"] == len(records)
    assert summary["checked"] + summary["not_checked"] == summary["total"]

    by_path = {item["path"]: item for item in records}
    assert by_path["smali/com/x/A.smali"]["status"] == ledger.SCANNED_TEXT
    assert by_path["res/values/strings.xml"]["status"] == ledger.SCANNED_TEXT
    assert by_path["assets/config.json"]["status"] == ledger.SCANNED_TEXT
    assert by_path["assets/libcore.so"]["status"] == ledger.ANALYSED_NATIVE
    assert by_path["assets/libcore.so"]["analysed_by"] == "native_elf"
    # A .so that is really a zip is still owned by the native pass.
    assert by_path["assets/packed.so"]["status"] == ledger.ANALYSED_NATIVE
    assert by_path["assets/bundle.zip"]["status"] == ledger.SKIPPED_CONTAINER
    assert by_path["assets/bundle.zip"]["reason"] == "container_not_extracted"
    assert by_path["assets/blob"]["status"] == ledger.SKIPPED_UNSUPPORTED
    assert by_path["assets/blob"]["reason"] == "no_text_suffix"
    assert by_path["assets/empty.dat"]["status"] == ledger.SKIPPED_UNSUPPORTED
    assert by_path["assets/empty.dat"]["reason"] == "empty_file"
    assert by_path["smali/link.smali"]["status"] == ledger.SKIPPED_SYMLINK
    assert by_path["smali/link.smali"]["reason"] == "symlink_never_followed"


def test_ledger_marks_unopened_text_candidate_undecodable(tmp_path):
    root = _make_tree(tmp_path)
    tree = classify.classify_decoded_tree(root)
    scanned = {
        entry.relative for entry in tree.entries
        if entry.suffix in apk_surface.TEXT_SUFFIXES
    }
    # Pretend one text file could not be read: it must not be reported as checked.
    victim = "res/values/strings.xml"
    scanned.discard(victim)
    records = ledger.build_file_ledger(
        tree, scanned=scanned, read_failures={victim: "OSError: denied"},
    )
    by_path = {item["path"]: item for item in records}
    assert by_path[victim]["status"] == ledger.UNDECODABLE
    assert by_path[victim]["reason"] == "text_read_failed"


def test_ledger_records_named_unreadable_entry(tmp_path):
    root = _make_tree(tmp_path)
    tree = classify.classify_decoded_tree(root)
    tree.unreadable.append("assets/weird-entry")
    records = ledger.build_file_ledger(tree, scanned=set())
    by_path = {item["path"]: item for item in records}
    assert by_path["assets/weird-entry"]["status"] == ledger.UNDECODABLE
    assert by_path["assets/weird-entry"]["reason"] == "unreadable_entry"


def test_ledger_elf_without_library_suffix_is_reported_not_hidden(tmp_path):
    root = _make_tree(tmp_path)
    (root / "assets" / "payload.bin").write_bytes(b"\x7fELF" + b"\x00" * 64)
    tree = classify.classify_decoded_tree(root)
    records = ledger.build_file_ledger(tree, scanned=set())
    by_path = {item["path"]: item for item in records}
    assert by_path["assets/payload.bin"]["content_kind"] == "elf"
    assert by_path["assets/payload.bin"]["status"] == ledger.SKIPPED_BINARY
    assert by_path["assets/payload.bin"]["reason"] == "elf_without_library_suffix"


def test_ledger_reason_always_matches_status(tmp_path):
    root = _make_tree(tmp_path)
    (root / "smali" / "link.smali").symlink_to(root / "smali" / "com" / "x" / "A.smali")
    tree = classify.classify_decoded_tree(root)
    scanned = {entry.relative for entry in tree.entries if entry.is_text_candidate}
    records = ledger.build_file_ledger(tree, scanned=scanned)
    for record in records:
        assert record["status"] in ledger.STATUSES
        reason = record["reason"]
        if record["status"] in {ledger.SCANNED_TEXT, ledger.ANALYSED_NATIVE}:
            assert reason is None
        else:
            assert reason in ledger.REASONS
            assert ledger.REASONS[reason] == record["status"]
        assert set(record) == {
            "path", "status", "reason", "size_bytes", "suffix",
            "content_kind", "analysed_by",
        }


def test_ledger_writer_is_atomic_private_and_leaves_no_temp(tmp_path):
    out = tmp_path / "artifact"
    records = [{"path": "a", "status": ledger.SCANNED_TEXT, "reason": None,
                "size_bytes": 0, "suffix": "", "content_kind": None,
                "analysed_by": "text_sweep"}]
    path = ledger.write_file_ledger(out, records)
    assert path == out / "files.jsonl"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_text(encoding="utf-8").endswith("\n")
    assert sorted(item.name for item in out.iterdir()) == ["files.jsonl"]


def test_ledger_summary_vocabulary_is_complete(tmp_path):
    root = _make_tree(tmp_path)
    tree = classify.classify_decoded_tree(root)
    records = ledger.build_file_ledger(tree, scanned=set())
    summary = ledger.summarize(records)
    assert set(summary["by_status"]) == set(ledger.STATUSES)
    assert summary["reason_vocabulary"] == dict(sorted(ledger.REASONS.items()))
    assert summary["files_jsonl"] == "files.jsonl"
    assert sum(summary["by_status"].values()) == summary["total"]


def test_analyzer_does_not_write_ledger_without_directory(tmp_path):
    root = _make_tree(tmp_path)
    result = apk_surface.analyze_apk_surface(root)
    summary = result["inventory"]["file_ledger"]
    assert summary["written"] is False
    assert not (root / "files.jsonl").exists()
    assert summary["total"] > 0
