"""P0c contracts: overflow is counted + sharded, never dropped.

Completeness law: "Overflow means counted + sharded + coverage = partial.
Never replace overflow with []."
"""
from __future__ import annotations

import hashlib
import json

from apkworkbench.analysis import androguard_dex
from apkworkbench.analysis.apk_surface import analyze_apk_surface
from apkworkbench.analysis.surface import native, patterns, sweep
from tests.elf_fixtures import symbol, write_elf

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.example.app">
  <application android:label="Example" />
</manifest>"""


def _tree(tmp_path, symbols):
    root = tmp_path / "apktool"
    (root / "lib/arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    write_elf(root / "lib/arm64-v8a/libx.so", symbols=symbols)
    return root


def _symbols(count: int):
    return tuple(symbol(f"sym_{index:03d}") for index in range(count))


def _read_index(out):
    return json.loads((out / "shards-index.json").read_text(encoding="utf-8"))


def test_symbol_overflow_is_sharded_not_dropped(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "MAX_SYMBOL_FACTS_ARTIFACT", 2)
    root = _tree(tmp_path, _symbols(6))
    out = tmp_path / "artifact"

    result = analyze_apk_surface(root, output_dir=out)

    exports = [item for item in result["facts"] if item["kind"] == "native_export"]
    assert len(exports) == 2                      # primary plane stays readable
    metrics = result["metrics"]
    assert metrics["native_exports_total"] == 6
    assert metrics["native_exports_emitted"] == 2
    assert metrics["native_symbol_facts_sharded"] == 4
    assert metrics["native_symbol_facts_dropped"] == 0
    assert metrics["native_shards_index"] is True
    assert result["coverage"]["native_symbols"] == "sharded"

    index = _read_index(out)
    assert index["totals"]["by_kind"]["native_symbol"] == 4
    part = out / index["parts"][0]["file"]
    lines = [json.loads(line) for line in part.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 4
    assert {line["kind"] for line in lines} == {"native_export"}
    # Every sharded value is a real export, not a placeholder.
    assert all(line["value"].startswith("lib/arm64-v8a/libx.so::sym_") for line in lines)


def test_shard_index_is_verifiable(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "MAX_SYMBOL_FACTS_ARTIFACT", 1)
    root = _tree(tmp_path, _symbols(4))
    out = tmp_path / "artifact"

    analyze_apk_surface(root, output_dir=out)

    index = _read_index(out)
    assert index["schema_version"] == 1
    assert index["parts_dir"] == "shards"
    assert sum(part["records"] for part in index["parts"]) == index["totals"]["records"]
    for part in index["parts"]:
        payload = (out / part["file"]).read_bytes()
        assert part["sha256"] == hashlib.sha256(payload).hexdigest()
        assert part["first_key"] and part["last_key"]
        assert part["file"].startswith("shards/")


def test_string_overflow_is_sharded(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "MAX_STRING_FACTS_ARTIFACT", 1)
    root = _tree(tmp_path, _symbols(3))
    out = tmp_path / "artifact"

    result = analyze_apk_surface(root, output_dir=out)

    strings = [item for item in result["facts"] if item["kind"] == "native_string"]
    assert len(strings) == 1
    metrics = result["metrics"]
    assert metrics["native_strings_sharded"] > 0
    assert metrics["native_strings_dropped"] == 0
    assert result["coverage"]["native_strings"] == "sharded"
    index = _read_index(out)
    assert index["totals"]["by_kind"]["native_string"] == metrics["native_strings_sharded"]


def test_without_shard_sink_the_loss_is_counted_and_named(tmp_path, monkeypatch):
    # No output_dir: the caps still count, the metrics admit the loss, and the
    # coverage says "partial" instead of pretending the data is present.
    monkeypatch.setattr(native, "MAX_SYMBOL_FACTS_ARTIFACT", 1)
    root = _tree(tmp_path, _symbols(5))

    result = analyze_apk_surface(root)

    metrics = result["metrics"]
    assert metrics["native_symbol_facts_emitted"] == 1
    assert metrics["native_symbol_facts_sharded"] == 0
    assert metrics["native_symbol_facts_dropped"] == 4
    assert metrics["native_shards_index"] is False
    assert result["coverage"]["native_symbols"] == "partial"
    assert not (root / "shards-index.json").exists()


def test_finding_overflow_is_sharded_and_does_not_flood_diagnostics(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "MAX_NATIVE_FINDINGS_ARTIFACT", 0)
    root = _tree(tmp_path, (symbol("system", shndx=0), symbol("sym_a")))
    out = tmp_path / "artifact"

    result = analyze_apk_surface(root, output_dir=out)

    assert result["metrics"]["native_findings_emitted"] == 0
    assert result["metrics"]["native_findings_sharded"] >= 1
    assert result["metrics"]["native_findings_dropped"] == 0
    codes = [item["code"] for item in result["diagnostics"]]
    assert codes.count("native_finding_limit") <= 1
    index = _read_index(out)
    assert index["totals"]["by_kind"]["native_finding"] >= 1


def test_domain_regex_is_one_hardened_definition():
    assert sweep.DOMAIN_RE is patterns.DOMAIN_RE
    assert androguard_dex.DOMAIN_RE is patterns.DOMAIN_RE
    # The possessive quantifiers are what make a hostile label run cheap.
    assert "?+)" in patterns.DOMAIN_RE.pattern
    assert "\\.++" in patterns.DOMAIN_RE.pattern
