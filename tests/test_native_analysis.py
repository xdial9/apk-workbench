"""N5-N10: JNI mapping, load sites, strings, findings and coverage identities."""
from __future__ import annotations

import json
from pathlib import Path

from apkworkbench.analysis.apk_surface import (
    analyze_apk_surface,
    cross_apk_native_jni_match,
)
from apkworkbench.analysis.surface.native import (
    UNMAPPED_REASONS,
    demangle_jni_symbol,
    extract_library_loads,
    scan_strings,
)
from tests.elf_fixtures import build_elf, symbol, write_elf

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.example.app">
  <application android:label="Example" />
</manifest>"""


def make_tree(tmp_path: Path) -> Path:
    root = tmp_path / "apktool"
    (root / "smali/com/example").mkdir(parents=True)
    (root / "lib/arm64-v8a").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(MANIFEST, encoding="utf-8")
    return root


def write_native_method(root: Path, name: str, signature: str = "()V") -> None:
    (root / "smali/com/example/Main.smali").write_text(
        ".class public Lcom/example/Main;\n"
        ".super Ljava/lang/Object;\n"
        f".method public native {name}{signature}\n"
        ".end method\n",
        encoding="utf-8",
    )


def facts_of(result: dict, kind: str) -> list[dict]:
    return [item for item in result["facts"] if item["kind"] == kind]


# ---- demangling ------------------------------------------------------------


def test_demangle_plain_class_method():
    name = demangle_jni_symbol("Java_com_example_Foo_bar")

    assert name is not None
    assert name.java_class == "Lcom/example/Foo;"
    assert name.java_method == "bar"
    assert name.signature is None
    assert name.problem == ""


def test_demangle_signature_escapes():
    name = demangle_jni_symbol("Java_com_example_Foo_bar__Ljava_lang_String_2")

    assert name.java_class == "Lcom/example/Foo;"
    assert name.java_method == "bar"
    assert name.signature == "Ljava/lang/String;"


def test_demangle_escaped_underscore_array_and_inner_class():
    underscore = demangle_jni_symbol("Java_com_example_Foo_my_1method")
    assert underscore.java_method == "my_method"

    array = demangle_jni_symbol("Java_com_example_Foo_take___3B")
    assert array.method if False else array.java_method == "take"
    assert array.signature == "[B"

    inner = demangle_jni_symbol("Java_com_example_Foo_00024Inner_baz")
    assert inner.java_class == "Lcom/example/Foo$Inner;"
    assert inner.java_method == "baz"


def test_demangle_rejects_non_jni_and_ambiguous_shapes():
    assert demangle_jni_symbol("_Z3foov") is None
    assert demangle_jni_symbol("JNI_OnLoad") is None

    lowercase = demangle_jni_symbol("Java_com_example_foo_bar")
    assert lowercase.problem == "demangle_ambiguous"

    boundary = demangle_jni_symbol("Java_com_example_Foo_bar_baz")
    assert boundary.problem == "demangle_ambiguous"


# ---- JNI join --------------------------------------------------------------


def test_jni_export_maps_to_declared_native_method(tmp_path):
    root = make_tree(tmp_path)
    write_native_method(root, "run")
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Main_run", value=0x810),),
    )

    result = analyze_apk_surface(root)

    entries = facts_of(result, "native_jni_entry")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["value"] == "lib/arm64-v8a/libgood.so::Java_com_example_Main_run"
    assert entry["java_class"] == "Lcom/example/Main;"
    assert entry["java_method"] == "run"
    assert entry["mapping_confidence"] == "hint"
    smali_cite = [item for item in entry["evidence"] if "line" in item]
    assert smali_cite and smali_cite[0]["path"] == "smali/com/example/Main.smali"
    assert smali_cite[0]["line"] == 3
    assert result["metrics"]["native_jni_exports_mapped"] == 1
    assert result["metrics"]["native_jni_mapping_complete"] is True
    assert result["coverage"]["native_jni_mapping"] == "mapped"
    assert result["inventory"]["jni_entries"][0]["java_method"] == "run"


def test_jni_signature_match_is_deduced_confidence(tmp_path):
    root = make_tree(tmp_path)
    write_native_method(root, "run", "(Ljava/lang/String;)V")
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Main_run__Ljava_lang_String_2"),),
    )

    result = analyze_apk_surface(root)

    entry = facts_of(result, "native_jni_entry")[0]
    assert entry["java_signature"] == "(Ljava/lang/String;)V"
    assert entry["mapping_confidence"] == "deduced"


def test_unmapped_jni_export_carries_closed_reason_and_finding(tmp_path):
    root = make_tree(tmp_path)
    write_native_method(root, "run")
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Ghost_x"),),
    )

    result = analyze_apk_surface(root)

    unmapped = facts_of(result, "native_jni_unmapped")
    assert len(unmapped) == 1
    assert unmapped[0]["reason"] == "no_matching_method"
    assert unmapped[0]["reason"] in UNMAPPED_REASONS
    assert any(
        finding["rule_id"] == "native_jni_entry_unmapped" for finding in result["findings"]
    )
    assert result["metrics"]["native_jni_exports_unmapped"] == 1
    assert result["metrics"]["native_jni_mapping_complete"] is True
    assert result["coverage"]["native_jni_mapping"] == "mapped"


def test_overload_without_signature_is_ambiguous_not_guessed(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Main.smali").write_text(
        ".class public Lcom/example/Main;\n"
        ".method public native foo()V\n.end method\n"
        ".method public native foo(I)V\n.end method\n",
        encoding="utf-8",
    )
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Main_foo"),),
    )

    result = analyze_apk_surface(root)

    unmapped = facts_of(result, "native_jni_unmapped")
    assert [item["reason"] for item in unmapped] == ["ambiguous_overload"]
    assert facts_of(result, "native_jni_entry") == []


def test_signature_mismatch_is_reported(tmp_path):
    root = make_tree(tmp_path)
    write_native_method(root, "foo", "()V")
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Main_foo__I"),),
    )

    result = analyze_apk_surface(root)

    unmapped = facts_of(result, "native_jni_unmapped")
    assert [item["reason"] for item in unmapped] == ["signature_mismatch"]


# ---- load sites ------------------------------------------------------------


def test_system_load_library_resolves_to_library_and_citation(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Loader.smali").write_text(
        ".class public Lcom/example/Loader;\n"
        ".method public static init()V\n"
        '    const-string v0, "good"\n'
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("foo"),))

    result = analyze_apk_surface(root)

    loads = facts_of(result, "native_library_load")
    assert len(loads) == 1
    assert loads[0]["value"] == "lib/arm64-v8a/libgood.so"
    assert loads[0]["evidence"] == [
        {"path": "smali/com/example/Loader.smali", "line": 4}
    ]
    assert result["metrics"]["native_libraries_with_load_site"] == 1
    assert result["metrics"]["native_libraries_without_load_site"] == 0
    assert result["inventory"]["native_library_loads"][0]["value"] == "good"


def test_load_of_missing_library_is_recorded_with_reason(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Loader.smali").write_text(
        ".class public Lcom/example/Loader;\n"
        ".method public static init()V\n"
        '    const-string v0, "absent"\n'
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("foo"),))

    result = analyze_apk_surface(root)

    unresolved = facts_of(result, "native_load_unresolved")
    assert len(unresolved) == 1
    assert unresolved[0]["reason"] == "no_matching_library"
    assert result["metrics"]["native_libraries_without_load_site"] == 1


def test_load_sites_survive_a_component_without_native_libraries(tmp_path):
    """Base APK owns the caller, the split owns the .so (cross-component join).

    Dropping the load site here is what made every cross-component native
    join impossible: the load must be preserved with a closed reason.
    """
    root = make_tree(tmp_path)
    (root / "smali/com/example/Loader.smali").write_text(
        ".class public Lcom/example/Loader;\n"
        ".method public static init()V\n"
        '    const-string v0, "good"\n'
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )

    result = analyze_apk_surface(root)

    assert result["coverage"]["native_libraries"] == "not_found"
    assert result["metrics"]["native_load_sites_total"] == 1
    assert result["metrics"]["native_load_sites_unresolved"] == 1
    unresolved = facts_of(result, "native_load_unresolved")
    assert len(unresolved) == 1
    assert unresolved[0]["reason"] == "no_native_library_in_component"
    assert unresolved[0]["library"] == "libgood.so"
    assert unresolved[0]["evidence"] == [
        {"path": "smali/com/example/Loader.smali", "line": 4}
    ]


def test_extract_library_loads_requires_a_real_const_string():
    text = (
        ".method public static init()V\n"
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        ".end method\n"
    )
    loads = extract_library_loads(text, "smali/A.smali")

    assert len(loads) == 1
    assert loads[0]["resolved"] is False
    assert loads[0]["value"] is None


# ---- strings ---------------------------------------------------------------


def test_string_scan_streams_ascii_and_utf16_with_exact_offsets(tmp_path):
    path = tmp_path / "blob.so"
    path.write_bytes(b"\x00" * 16 + b"https://a.example.test\x00" + b"\x00" * 4 + "hello-short".encode("utf-16-le"))

    scan = scan_strings(path)

    values = {value: offset for value, offset in scan.values}
    assert values["https://a.example.test"] == 16
    # UTF-16LE text is invisible to the ASCII scanner and must still be found.
    assert "hello-short" in values
    assert scan.bytes_scanned == path.stat().st_size


def test_string_cap_is_counted_not_silent(tmp_path):
    path = tmp_path / "many.so"
    path.write_bytes(b"\x00".join(b"value_%02d" % index for index in range(10)))

    scan = scan_strings(path, limit=3)

    assert scan.unique == 3
    assert scan.matches == 10
    assert scan.truncated is True


def test_string_cap_flips_coverage_to_partial_and_records_diagnostic(monkeypatch, tmp_path):
    from apkworkbench.analysis.surface import native

    monkeypatch.setattr(native, "MAX_STRINGS_PER_LIBRARY", 2)
    monkeypatch.setattr(native, "scan_strings", lambda path, **kwargs: native.StringScan(
        values=[("a", 0), ("b", 1)], matches=9, unique=2, bytes_scanned=10, truncated=True, limit=2,
    ))
    root = make_tree(tmp_path)
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("foo"),))

    result = analyze_apk_surface(root)

    assert any(item["code"] == "native_string_limit" for item in result["diagnostics"])
    assert result["coverage"]["native_strings"] == "partial"
    assert result["status"] == "partial"


# ---- findings --------------------------------------------------------------


def test_process_exec_dynamic_load_and_anti_debug_findings(tmp_path):
    root = make_tree(tmp_path)
    write_elf(
        root / "lib/arm64-v8a/libbad.so",
        symbols=(
            symbol("system", shndx=0),
            symbol("popen", shndx=0),
            symbol("dlsym", shndx=0),
            symbol("ptrace", shndx=0),
        ),
    )

    result = analyze_apk_surface(root)

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert {"native_process_exec", "native_dynamic_symbol_resolution", "native_anti_debug"} <= rules
    for finding in result["findings"]:
        if finding["rule_id"].startswith("native_"):
            assert isinstance(finding["evidence"]["offset"], int)
            assert finding["evidence"]["offset"] >= 0
            assert finding["evidence"]["line"] is None


def test_clean_library_emits_no_native_findings(tmp_path):
    root = make_tree(tmp_path)
    write_elf(
        root / "lib/arm64-v8a/libclean.so",
        symbols=(symbol("my_helper"), symbol("memcpy", shndx=0)),
    )

    result = analyze_apk_surface(root)

    assert not [item for item in result["findings"] if item["rule_id"].startswith("native_")]


def test_register_natives_candidates_never_paired(tmp_path):
    root = make_tree(tmp_path)
    path = write_elf(
        root / "lib/arm64-v8a/libdyn.so",
        symbols=(symbol("RegisterNatives", shndx=0),),
    )
    with path.open("ab") as handle:
        handle.write(b"\x00Lcom/example/Main;\x00(Ljava/lang/String;)V\x00")

    result = analyze_apk_surface(root)

    candidates = facts_of(result, "native_jni_register_natives_candidate")
    assert len(candidates) == 1
    assert candidates[0]["pairing"] == "unresolved"
    assert candidates[0]["class_descriptor_candidates"] == ["Lcom/example/Main;"]
    assert candidates[0]["signature_candidates"] == ["(Ljava/lang/String;)V"]
    assert any(
        finding["rule_id"] == "native_jni_register_natives" for finding in result["findings"]
    )


# ---- coverage identities ---------------------------------------------------


def test_every_native_file_is_parsed_or_skipped_with_reason(tmp_path):
    root = make_tree(tmp_path)
    write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("Java_com_example_Main_run"),))
    write_elf(root / "lib/arm64-v8a/libstripped.so")
    (root / "lib/arm64-v8a/libbad.so").write_bytes(b"PK\x03\x04 this is a zip, not an elf")

    result = analyze_apk_surface(root)

    metrics = result["metrics"]
    assert metrics["native_files_found"] == 3
    assert metrics["native_files_found"] == (
        metrics["native_files_parsed"] + metrics["native_files_skipped"]
    )
    assert metrics["native_files_parsed"] == 2
    assert metrics["native_files_skipped"] == 1
    states = {item["path"]: item["state"] for item in result["inventory"]["native_analysis"]}
    assert states == {
        "lib/arm64-v8a/libbad.so": "not_elf",
        "lib/arm64-v8a/libgood.so": "parsed",
        "lib/arm64-v8a/libstripped.so": "parsed",
    }
    assert any(item["code"] == "native_not_elf" for item in result["diagnostics"])
    assert result["coverage"]["native_libraries"] == "partial"
    assert result["status"] == "partial"


def test_no_native_library_is_reported_not_applicable(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Main.smali").write_text(
        ".class public Lcom/example/Main;\n", encoding="utf-8"
    )

    result = analyze_apk_surface(root)

    assert result["coverage"]["native_libraries"] == "not_found"
    assert result["coverage"]["native_jni_mapping"] == "not_applicable"
    assert result["metrics"]["native_files_found"] == 0
    assert result["metrics"]["native_jni_mapping_complete"] is True


def test_native_facts_all_carry_a_byte_or_line_citation(tmp_path):
    root = make_tree(tmp_path)
    write_elf(
        root / "lib/arm64-v8a/libgood.so",
        symbols=(symbol("Java_com_example_Ghost_x"), symbol("malloc", shndx=0)),
        soname="libgood.so",
    )

    result = analyze_apk_surface(root)

    native_kinds = {
        "native_elf", "native_export", "native_import", "native_jni_unmapped",
        "native_string", "native_secret_hint",
    }
    for fact in result["facts"]:
        if fact["kind"] not in native_kinds:
            continue
        assert fact["evidence"], fact
        item = fact["evidence"][0]
        assert item.get("path"), fact
        assert isinstance(item.get("offset"), int), fact


def test_elf_build_helper_roundtrip_is_self_consistent():
    # Guards the fixture builder itself: a broken builder would silently make
    # every native test vacuous.
    blob = build_elf(bits=64, symbols=(symbol("x"),), needed=("libc.so",))
    assert blob[:4] == b"\x7fELF"
    assert b"libc.so" in blob


def test_library_without_load_site_gets_a_closed_reason(tmp_path):
    root = make_tree(tmp_path)
    (root / "smali/com/example/Loader.smali").write_text(
        ".class public Lcom/example/Loader;\n"
        ".method public static init()V\n"
        '    const-string v0, "main"\n'
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        "    return-void\n"
        ".end method\n",
        encoding="utf-8",
    )
    write_elf(root / "lib/arm64-v8a/libmain.so", needed=("libdep.so",), symbols=(symbol("foo"),))
    write_elf(root / "lib/arm64-v8a/libdep.so", symbols=(symbol("dep"),))
    write_elf(root / "lib/arm64-v8a/liborphan.so", symbols=(symbol("orphan"),))

    result = analyze_apk_surface(root)

    reasons = {
        fact["value"]: fact["reason"]
        for fact in facts_of(result, "native_library_no_load_site")
    }
    assert reasons == {
        "lib/arm64-v8a/libdep.so": "dependency_of_other_lib",
        "lib/arm64-v8a/liborphan.so": "unreferenced",
    }
    assert all(reason in UNMAPPED_REASONS for reason in reasons.values())
    metrics = result["metrics"]
    assert metrics["native_libraries_with_load_site"] == 1
    assert metrics["native_libraries_without_load_site"] == 2
    inventory = {item["path"]: item for item in result["inventory"]["native_analysis"]}
    assert inventory["lib/arm64-v8a/libmain.so"]["load_status"] == "loaded"
    assert inventory["lib/arm64-v8a/libdep.so"]["load_reason"] == "dependency_of_other_lib"


def test_native_string_evidence_is_retargeted_to_byte_offsets(tmp_path):
    """A line number inside a .so is a fabrication; the cite must be a byte offset."""
    root = make_tree(tmp_path)
    path = write_elf(root / "lib/arm64-v8a/libgood.so", symbols=(symbol("foo"),))
    payload = b"\x00https://native.example.test/v1\x00\x00api.native.example.test\x00"
    with path.open("ab") as handle:
        handle.write(payload)

    result = analyze_apk_surface(root)

    endpoint = next(
        item for item in result["inventory"]["endpoints"]
        if item.get("value") == "https://native.example.test/v1"
    )
    evidence = endpoint["evidence"][0]
    assert evidence["path"] == "lib/arm64-v8a/libgood.so"
    assert "line" not in evidence
    assert evidence["offset"] == path.stat().st_size - len(payload) + 1
    assert result["inventory"]["endpoints"][0]["evidence"][0].get("line") is None

    # No finding may cite a native path with a fabricated line number.
    for finding in result["findings"]:
        evidence = finding.get("evidence") or {}
        if str(evidence.get("path", "")).startswith("lib/"):
            assert evidence.get("line") is None
            assert isinstance(evidence.get("offset"), int)


def test_cross_apk_jni_match_reconciles_inventory_and_unmapped_metrics(tmp_path):
    results_root = tmp_path / "results"
    package_id = "com.example.app"
    version_code = "1"
    base_digest = "a" * 64
    split_digest = "b" * 64
    base_decoded = results_root / package_id / version_code / base_digest / "apktool"
    base_decoded.joinpath("smali/com/example").mkdir(parents=True)
    write_native_method(base_decoded, "run")

    split_root = results_root / package_id / version_code / split_digest
    split_decoded = split_root / "apktool"
    native_path = split_decoded / "lib/arm64-v8a/libgood.so"
    native_path.parent.mkdir(parents=True)
    native_symbol = "Java_com_example_Main_run"
    write_elf(native_path, symbols=(symbol(native_symbol, value=0x810),))

    library = "lib/arm64-v8a/libgood.so"
    split_surface = split_root / "surface"
    split_surface.mkdir()
    static_analysis = {
        "facts": [
            {
                "kind": "native_jni_unmapped",
                "value": f"{library}::{native_symbol}",
                "extra": {"library": library, "symbol": native_symbol},
            }
        ],
        "findings": [
            {
                "rule_id": "native_jni_entry_unmapped",
                "evidence": {"path": library, "snippet": native_symbol},
            }
        ],
        "metrics": {
            "native_jni_exports_total": 1,
            "native_jni_exports_mapped": 0,
            "native_jni_exports_unmapped": 1,
            "native_jni_mapping_complete": True,
            "native_findings_emitted": 1,
        },
        "coverage": {"native_jni_mapping": "mapped"},
        "inventory": {
            "jni_entries": [],
            "jni_unmapped": [
                {
                    "library": library,
                    "symbol": native_symbol,
                    "java_class": "Lcom/example/Main;",
                    "java_method": "run",
                    "java_signature": None,
                    "reason": "no_matching_method",
                    "offset": 0x810,
                }
            ],
            "native_analysis": [{"path": library, "jni_entries": 0, "jni_unmapped": 1}],
        },
    }
    static_path = split_surface / "static-analysis.json"
    static_path.write_text(json.dumps(static_analysis), encoding="utf-8")
    eligible = [
        {
            "package_id": package_id,
            "version_code": version_code,
            "sha256": base_digest,
        },
        {
            "package_id": package_id,
            "version_code": version_code,
            "sha256": split_digest,
        },
    ]

    summary = cross_apk_native_jni_match(results_root, eligible)

    updated = json.loads(static_path.read_text(encoding="utf-8"))
    assert summary["matched"] == 1
    assert summary["unmatched"] == 0
    assert updated["metrics"]["native_jni_exports_total"] == 1
    assert updated["metrics"]["native_jni_exports_mapped"] == 1
    assert updated["metrics"]["native_jni_exports_unmapped"] == 0
    assert updated["metrics"]["native_jni_mapping_complete"] is True
    assert updated["metrics"]["native_findings_emitted"] == 0
    assert updated["metrics"]["distinct_finding_count"] == 0
    assert updated["coverage"]["native_jni_mapping"] == "mapped"
    assert updated["inventory"]["jni_entries"][0]["symbol"] == native_symbol
    assert updated["inventory"]["jni_unmapped"] == []
    assert updated["inventory"]["native_analysis"][0]["jni_entries"] == 1
    assert updated["inventory"]["native_analysis"][0]["jni_unmapped"] == 0
    assert not [fact for fact in updated["facts"] if fact["kind"] == "native_jni_unmapped"]
    assert not updated["findings"]

    cross_apk_native_jni_match(results_root, eligible)
    resumed = json.loads(static_path.read_text(encoding="utf-8"))
    assert len(resumed["inventory"]["jni_entries"]) == 1
    assert len([fact for fact in resumed["facts"] if fact["kind"] == "native_jni_entry"]) == 1
    assert resumed["metrics"]["native_jni_exports_mapped"] == 1
