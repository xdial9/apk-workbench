"""P4 — link graph + entry points, proven against the real fixture APK.

The fixture (``tests/fixtures/dexfixture``) is an apktool-built APK whose smali
sources sit next to it. It declares:

  * an exported launcher activity with a VIEW/BROWSABLE deep link   (Main)
  * an exported service behind a declared permission                (SyncService)
  * an Application class                                            (App)
  * an endpoint constant + a permission-gated platform API call     (Api.fetch)
  * an internal call edge from the launcher entry to that endpoint   (Main.onCreate)
  * a JNI export mapped back to a declared native method            (Main.compute)

The ``.so`` is synthesized at test time (``tests/elf_fixtures``) because this
repo does not commit binary blobs; everything else is the real decoded tree and
the real APK, read by the real surface + androguard analyzers.
"""
from __future__ import annotations

import json
import shutil
import textwrap
from pathlib import Path
from hashlib import sha256

import pytest

from apkworkbench.analysis import androguard_dex
from apkworkbench.analysis.apk_surface import (
    analyze_apk_surface,
    run_static_surface_analysis,
)
from apkworkbench.analysis.contracts import EvidenceLocation
from apkworkbench.analysis.surface import links as link_module
from apkworkbench.analysis.surface.links import (
    EDGE_KEYS,
    EDGE_TYPES,
    build_entry_points,
    build_link_graph,
    citation_to_dict,
    write_links,
)
from apkworkbench.database.workspace import WorkspaceDatabase
from apkworkbench.decompilation.runner import DecompilationRunner
from tests.elf_fixtures import symbol, write_elf

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "dexfixture"
FIXTURE_APK = FIXTURE_DIR / "dexfixture.apk"
JNI_SYMBOL = "Java_com_example_Main_compute"


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _edges(graph: list[dict], edge_type: str) -> list[dict]:
    return [edge for edge in graph if edge["edge_type"] == edge_type]


def _one(edges: list[dict], **match) -> dict:
    found = [
        edge for edge in edges
        if all(edge.get(key) == value for key, value in match.items())
    ]
    assert len(found) == 1, f"expected exactly one edge matching {match}, got {found}"
    return found[0]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """Real decode tree (copied) + real DEX result + the two written files."""
    assert FIXTURE_APK.is_file(), f"missing fixture APK: {FIXTURE_APK}"
    root = tmp_path_factory.mktemp("dexfixture") / "apktool"
    shutil.copytree(FIXTURE_DIR, root)
    (root / "dexfixture.apk").unlink()
    # Native side: same bytes-built ELF the native tests use.
    write_elf(
        root / "lib/arm64-v8a/libdexfixture.so",
        symbols=(symbol(JNI_SYMBOL), symbol("malloc", shndx=0)),
        soname="libdexfixture.so",
    )
    surface_result = analyze_apk_surface(root, apk_path=FIXTURE_APK)
    assert surface_result["status"] == "success", surface_result["diagnostics"]
    dex_result = androguard_dex._analyze_in_worker(str(FIXTURE_APK))
    assert dex_result["status"] == "success", dex_result["diagnostics"]

    diagnostics: list[dict[str, str]] = []
    coverage: dict[str, str] = {}
    graph = build_link_graph(
        surface_result, dex_result, coverage=coverage, diagnostics=diagnostics
    )
    entry_points = build_entry_points(surface_result, dex_result)
    output = tmp_path_factory.mktemp("links")
    paths = write_links(output, graph, entry_points)
    return {
        "directory": output,
        "apktool_root": root,
        "paths": paths,
        "graph": graph,
        "entry_points": entry_points,
        "coverage": coverage,
        "diagnostics": diagnostics,
        "surface_result": surface_result,
        "dex_result": dex_result,
    }


# ---------------------------------------------------------------------------
# EXIT CRITERION 1 — which component is exported, which class implements it,
# what can invoke it?  (links.jsonl + entry_points.jsonl only)
# ---------------------------------------------------------------------------
def test_q1_exported_component_class_and_invocation(built):
    entry_points = _read_jsonl(built["paths"]["entry_points"])
    graph = _read_jsonl(built["paths"]["links"])

    by_id = {entry["entry_point"]: entry for entry in entry_points}
    main = by_id["activity:com.example.Main"]
    assert main["exported"] is True
    assert main["class_descriptor"] == "Lcom/example/Main;"
    assert main["class_in_dex"] is True
    assert main["intent_actions"] == ["android.intent.action.MAIN", "android.intent.action.VIEW"]
    # What can invoke it: the launcher (MAIN/LAUNCHER) and any app with the URI.
    assert "exported" in main["reachability"]
    assert "launcher_activity" in main["reachability"]
    assert "deep_link" in main["reachability"]
    assert main["deep_links"] == [{
        "scheme": "https", "host": "app.example.test", "port": "",
        "path": "/feed", "mime_type": "",
    }]

    # component -> class, with the manifest and the DEX as the two citations.
    edge = _one(
        _edges(graph, "component->class"),
        **{"from": "component:activity:com.example.Main"},
    )
    assert edge["to"] == "class:Lcom/example/Main;"
    assert [cite["evidence_kind"] for cite in edge["citations"]] == [
        "manifest_component", "dex_class"
    ]
    assert edge["citations"][0]["manifest_xpath"] == (
        "/manifest/application/activity[@android:name='com.example.Main']"
    )

    # A second exported component with a declared permission to gate it.
    service = by_id["service:com.example.SyncService"]
    assert service["exported"] is True
    assert service["class_descriptor"] == "Lcom/example/SyncService;"
    assert service["declared_permission"] == "android.permission.BIND_JOB_SERVICE"
    assert service["declared_permission_requested"] is False

    # The Application class is an entry point too, and it resolves to a class.
    app = by_id["application:com.example.App"]
    assert app["class_descriptor"] == "Lcom/example/App;"
    assert app["class_in_dex"] is True
    assert app["reachability"] == ["application_class"]


# ---------------------------------------------------------------------------
# EXIT CRITERION 2 — which endpoint is called by which method, from which
# entry point?  (links.jsonl + entry_points.jsonl only)
# ---------------------------------------------------------------------------
def test_q2_endpoint_method_and_entry_point_trace(built):
    graph = _read_jsonl(built["paths"]["links"])
    entry_points = _read_jsonl(built["paths"]["entry_points"])

    endpoint = "endpoint:https://api.example.test/v1/feed"
    fetch = "method:Lcom/example/Api; fetch ()Ljava/lang/String;"

    # Which endpoint is called by which method.
    call = _one(_edges(graph, "method->endpoint"), to=endpoint)
    assert call["from"] == fetch
    assert call["citations"][1]["evidence_kind"] == "dex_string"
    assert call["citations"][1]["extractor_coordinate"]["value"] == (
        "https://api.example.test/v1/feed"
    )

    # From which entry point: walk the graph backwards, no other file needed.
    class_of_method = call["citations"][0]["dex_class"]
    assert class_of_method == "Lcom/example/Api;"
    owner_edge = _one(
        _edges(graph, "method->method"),
        **{"from": "method:Lcom/example/Main; onCreate ()V"},
    )
    assert owner_edge["to"] == fetch
    assert owner_edge["citations"][0]["dex_class"] == "Lcom/example/Main;"

    class_to_method = _one(
        _edges(graph, "class->method"),
        **{"from": "class:Lcom/example/Main;", "to": "method:Lcom/example/Main; onCreate ()V"},
    )
    assert class_to_method["citations"][0]["evidence_kind"] == "dex_class"

    component_to_class = _one(
        _edges(graph, "component->class"),
        **{"from": "component:activity:com.example.Main"},
    )
    assert component_to_class["to"] == "class:Lcom/example/Main;"

    reachable = [
        entry for entry in entry_points
        if entry["externally_reachable"] is True
        and entry["entry_point"] == "activity:com.example.Main"
    ]
    assert len(reachable) == 1
    # The chain the AI walks:
    #   exported component -> class Main -> onCreate -> Api.fetch -> URL
    assert call["from"].endswith("Lcom/example/Api; fetch ()Ljava/lang/String;")


# ---------------------------------------------------------------------------
# EXIT CRITERION 3 — which permission gates that path, and is it requested?
# (links.jsonl + entry_points.jsonl only)
# ---------------------------------------------------------------------------
def test_q3_permission_gating_and_request_state(built):
    graph = _read_jsonl(built["paths"]["links"])

    endpoint = "endpoint:https://api.example.test/v1/feed"
    gating = {
        edge["to"]: edge["citations"][1]
        for edge in _edges(graph, "endpoint->permission")
        if edge["from"] == endpoint
    }
    # Both permissions the platform API requires are edges — never collapsed
    # to one, and never dropped because the manifest omits one of them.
    assert gating["permission:android.permission.ACCESS_FINE_LOCATION"][
        "extractor_coordinate"
    ]["requested"] is True
    assert gating["permission:android.permission.ACCESS_COARSE_LOCATION"][
        "extractor_coordinate"
    ]["requested"] is False
    requirement = gating["permission:android.permission.ACCESS_FINE_LOCATION"]
    assert requirement["evidence_kind"] == "permission_requirement"
    assert requirement["extractor_coordinate"]["permission"] == (
        "android.permission.ACCESS_FINE_LOCATION"
    )
    assert requirement["extractor_coordinate"]["permissions"] == [
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_FINE_LOCATION",
    ]
    assert "getLastKnownLocation" in requirement["method_signature"]


# ---------------------------------------------------------------------------
# Contract shape: every edge is exactly {edge_type, from, to, 2 citations} and
# every citation IS an EvidenceLocation, not a new ad-hoc shape.
# ---------------------------------------------------------------------------
def test_every_edge_has_two_evidence_locations(built):
    graph = built["graph"]
    assert graph
    assert {edge["edge_type"] for edge in graph} <= set(EDGE_TYPES)
    for edge in graph:
        assert set(edge) == EDGE_KEYS
        assert len(edge["citations"]) == 2
        for citation in edge["citations"]:
            assert citation["evidence_kind"].strip()
            # Round-trips through the shared contract class: same fields, same
            # meaning as facts/findings citations.
            location = EvidenceLocation(**citation)
            assert citation_to_dict(location) == citation


def test_edges_are_deterministic_and_unique(built):
    again = build_link_graph(built["surface_result"], built["dex_result"])
    first = [json.dumps(edge, sort_keys=True) for edge in built["graph"]]
    second = [json.dumps(edge, sort_keys=True) for edge in again]
    assert first == second
    assert len(first) == len(set(first))


def test_method_native_edge_reuses_the_jni_mapping(built):
    graph = built["graph"]
    edge = _one(
        _edges(graph, "method->native"),
        **{"from": "method:Lcom/example/Main; compute ()V"},
    )
    assert edge["to"] == (
        "native:lib/arm64-v8a/libdexfixture.so::Java_com_example_Main_compute"
    )
    method_cite, native_cite = edge["citations"]
    # The Java end cites the smali declaration native.py already matched.
    assert method_cite["evidence_kind"] == "smali_declaration"
    assert method_cite["source_path"] == "apktool/smali/com/example/Main.smali"
    assert method_cite["line_start"] >= 1
    # The native end cites the real byte offset of the export.
    assert native_cite["evidence_kind"] == "native_symbol"
    assert native_cite["source_path"] == "apktool/lib/arm64-v8a/libdexfixture.so"
    assert native_cite["byte_offset_start"] >= 0
    assert native_cite["extractor_coordinate"]["mapping_confidence"] == "hint"


def test_native_secret_edges_come_from_trufflehog_findings(built):
    findings = [{
        "DetectorName": "Generic API Key",
        "DetectorType": 1,
        "DecoderName": "PLAIN",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": str(built["apktool_root"] / "lib/arm64-v8a/libdexfixture.so"),
            "line": 7,
        }}},
    }]
    graph = build_link_graph(
        built["surface_result"], built["dex_result"],
        trufflehog_findings=findings, finding_root=built["apktool_root"],
    )
    edge = _one(_edges(graph, "native->secret"))
    assert edge["from"].startswith("native:lib/arm64-v8a/libdexfixture.so::")
    library_cite, secret_cite = edge["citations"]
    assert library_cite["source_path"] == "apktool/lib/arm64-v8a/libdexfixture.so"
    assert secret_cite["evidence_kind"] == "trufflehog_finding"
    assert secret_cite["line_start"] == 7
    assert secret_cite["extractor_coordinate"]["verification"] == "unverified"

    # Without findings there is no provable second citation: coverage says so.
    coverage: dict[str, str] = {}
    diagnostics: list[dict[str, str]] = []
    build_link_graph(
        built["surface_result"], built["dex_result"],
        coverage=coverage, diagnostics=diagnostics,
    )
    assert coverage["link_type_native_secret"] == "not_applicable"
    assert any(
        item["code"] == "link_native_secret_source_absent" for item in diagnostics
    )


def test_absolute_smali_finding_path_maps_inside_apktool_root(built):
    smali_path = built["apktool_root"] / "smali/com/example/Main.smali"
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": str(smali_path),
            "line": 20,
        }}},
    }]

    graph = build_link_graph(
        built["surface_result"],
        built["dex_result"],
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
    )

    edge = _one(
        _edges(graph, "method->secret"),
        **{"from": "method:Lcom/example/Main; onCreate ()V"},
    )
    assert edge["citations"][1]["source_path"] == (
        "apktool/smali/com/example/Main.smali"
    )
    assert edge["citations"][0]["line_start"] == 19
    assert edge["citations"][1]["line_start"] == 20
    assert len(_edges(graph, "method->secret")) == 1


def test_smali_assets_finding_path_maps_to_exact_method(built):
    source = built["apktool_root"] / "smali/com/example/Main.smali"
    smali_path = (
        built["apktool_root"]
        / "smali_assets/audience_network/classes2/com/example/Main.smali"
    )
    smali_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, smali_path)
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": str(smali_path),
            "line": 20,
        }}},
    }]
    usage: list[dict] = []

    graph = build_link_graph(
        built["surface_result"],
        built["dex_result"],
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
        secret_usage=usage,
    )

    edge = _one(
        _edges(graph, "method->secret"),
        **{"from": "method:Lcom/example/Main; onCreate ()V"},
    )
    assert edge["citations"][1]["source_path"] == (
        "apktool/smali_assets/audience_network/classes2/com/example/Main.smali"
    )
    assert usage[0]["usage_status"] == "mapped"


def test_smali_assets_class_missing_from_dex_model_is_explicitly_unverified(built):
    smali_path = (
        built["apktool_root"]
        / "smali_assets/audience_network/classes2/com/example/Unknown.smali"
    )
    smali_path.parent.mkdir(parents=True, exist_ok=True)
    smali_path.write_text(".class Lcom/example/Unknown;\n", encoding="utf-8")
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": str(smali_path),
            "line": 1,
        }}},
    }]
    usage: list[dict] = []

    build_link_graph(
        built["surface_result"],
        {},
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
        secret_usage=usage,
    )

    assert usage[0]["usage_status"] == "usage_unverified"
    assert usage[0]["reason"] == "class_not_in_dex_model"


def test_secret_outside_method_is_explicitly_unverified(built):
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": "smali/com/example/Main.smali",
            "line": 1,
        }}},
    }]
    usage: list[dict] = []
    graph = build_link_graph(
        built["surface_result"],
        built["dex_result"],
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
        secret_usage=usage,
    )

    assert _edges(graph, "method->secret") == []
    assert usage == [{
        "finding_index": 0,
        "source_path": "apktool/smali/com/example/Main.smali",
        "line": 1,
        "detector": "Generic API Key",
        "verification": "unverified",
        "usage_status": "usage_unverified",
        "method": None,
        "reason": "line_not_inside_method",
    }]


def test_absolute_finding_path_outside_apktool_root_is_not_linked(built, tmp_path):
    smali_path = tmp_path / "smali/com/example/Main.smali"
    smali_path.parent.mkdir(parents=True)
    smali_path.write_text(".class Lcom/example/Main;\n", encoding="utf-8")
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": str(smali_path),
            "line": 1,
        }}},
    }]
    diagnostics: list[dict[str, str]] = []
    coverage: dict[str, str] = {}

    graph = build_link_graph(
        built["surface_result"],
        built["dex_result"],
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
        diagnostics=diagnostics,
        coverage=coverage,
    )

    assert _edges(graph, "method->secret") == []
    assert coverage["link_type_method_secret"] == "partial"
    assert any(
        item["code"] == "link_secret_finding_path_unresolved"
        for item in diagnostics
    )


def test_permission_secret_edge_uses_the_finding_method_not_its_class(built):
    findings = [{
        "DetectorName": "Generic API Key",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {
            "file": "smali/com/example/Api.smali",
            "line": 32,
        }}},
    }]
    graph = build_link_graph(
        built["surface_result"],
        built["dex_result"],
        trufflehog_findings=findings,
        finding_root=built["apktool_root"],
    )

    edges = _edges(graph, "permission->secret")
    assert edges
    assert all(
        edge["citations"][0]["method_signature"]
        == "Lcom/example/Api; fetch ()Ljava/lang/String;"
        for edge in edges
    )


def test_trace_chains_emit_one_shortest_path_per_secret_and_entry_point():
    edges = [{
        "edge_type": "component->class",
        "from": "component:activity:Main",
        "to": "class:LMain;",
        "citations": [],
    }]
    previous = ["class:LMain;"]
    for layer in range(12):
        current = [f"method:layer{layer}:{index}" for index in range(2)]
        edge_type = "class->method" if layer == 0 else "method->method"
        edges.extend({
            "edge_type": edge_type,
            "from": source,
            "to": target,
            "citations": [],
        } for source in previous for target in current)
        previous = current
    edges.extend({
        "edge_type": "method->secret",
        "from": method,
        "to": "secret:token",
        "citations": [],
    } for method in previous)
    edges.extend([
        {
            "edge_type": "class->method",
            "from": "class:LMain;",
            "to": "method:shortcut",
            "citations": [],
        },
        {
            "edge_type": "method->secret",
            "from": "method:shortcut",
            "to": "secret:token",
            "citations": [],
        },
    ])

    chains = link_module.build_trace_chains(edges, [], max_depth=20)

    assert len(chains) == 1
    assert chains[0]["start_node"] == "component:activity:Main"
    assert chains[0]["end_node"] == "secret:token"
    assert chains[0]["chain_length"] == 3


def test_asset_reader_is_not_applicable_with_a_reason(built):
    assert built["coverage"]["link_type_asset_reader"] == "not_applicable"
    assert any(
        item["code"] == "link_asset_reader_not_derivable"
        for item in built["diagnostics"]
    )


def test_coverage_marks_present_edge_types_success(built):
    coverage = built["coverage"]
    for edge_type in (
        "component->class", "class->method", "method->method",
        "method->endpoint", "endpoint->permission", "method->native",
    ):
        assert coverage[link_module.COVERAGE_KEYS[edge_type]] == "success", edge_type
    assert set(coverage) == set(link_module.COVERAGE_KEYS.values())


def test_component_without_a_dex_class_is_named_not_guessed():
    """A manifest component whose class is absent produces a diagnostic, not an edge."""
    surface_result = {
        "manifest": {
            "package": "com.example.app",
            "permissions": [],
            "application": {"name": "com.example.App"},
            "components": [{
                "type": "activity", "name": "com.example.Ghost",
                "exported": "true", "has_intent_filter": False,
                "permission": None, "intent_filters": [],
            }],
        },
        "facts": [],
        "inventory": {},
    }
    diagnostics: list[dict[str, str]] = []
    graph = build_link_graph(
        surface_result, {"class_model": [], "method_model": []},
        diagnostics=diagnostics,
    )
    assert _edges(graph, "component->class") == []
    assert any(
        item["code"] == "link_component_class_unresolved" for item in diagnostics
    )
    entry_points = build_entry_points(surface_result, {"class_model": []})
    assert entry_points[0]["class_in_dex"] is False
    assert entry_points[0]["class_citation"] is None


def test_write_links_is_atomic_and_leaves_the_facts_plane_alone(built, tmp_path):
    """Links are their own plane: writing them never rewrites facts.jsonl."""
    facts = tmp_path / "facts.jsonl"
    facts.write_text('{"kind":"endpoint","value":"x"}\n', encoding="utf-8")
    before = facts.read_bytes()

    paths = write_links(tmp_path, built["graph"], built["entry_points"])

    assert paths["links"] == tmp_path / "links.jsonl"
    assert paths["entry_points"] == tmp_path / "entry_points.jsonl"
    assert facts.read_bytes() == before
    # Temp files from the write are gone, and nothing else appeared.
    assert sorted(item.name for item in tmp_path.iterdir()) == [
        "entry_points.jsonl", "facts.jsonl", "links.jsonl",
    ]
    assert len(_read_jsonl(paths["links"])) == len(built["graph"])
    assert len(_read_jsonl(paths["entry_points"])) == len(built["entry_points"])


# ---------------------------------------------------------------------------
# Pipeline wiring: a real surface run must land both files in the bundle, not
# just build them in memory.
# ---------------------------------------------------------------------------
def test_pipeline_writes_links_and_entry_points(tmp_path):
    package_id, version_code = "com.example.dexfixture", 1
    workspace = tmp_path / "workspace"
    database = WorkspaceDatabase(workspace)
    database.ensure()

    payload = FIXTURE_APK.read_bytes()
    digest = sha256(payload).hexdigest()
    apk_path = (
        workspace / "downloads" / package_id / str(version_code) / digest
        / "dexfixture.apk"
    )
    apk_path.parent.mkdir(parents=True)
    apk_path.write_bytes(payload)

    run_id = "p4-links-run"
    row = {
        "run_id": run_id,
        "selection_order": 1,
        "selected_at": "2026-11-16T12:00:00+00:00",
        "package_id": package_id,
        "app_name": "DEX Fixture",
        "version_code": version_code,
        "version_name": "1.0",
        "source": "google_play",
        "download_url": f"google-play://{package_id}/1/base.apk",
        "sha256": digest,
        "size": len(payload),
        "signer_sha256": "",
        "local_path": str(apk_path),
        "index_sha256": "b" * 64,
    }
    database.write_manifest(run_id, [row])
    database.append_history({**row, "downloaded_at": row["selected_at"]})

    # Decode tree the fake apktool publishes, including the synthesized .so.
    staging = tmp_path / "decode"
    shutil.copytree(FIXTURE_DIR, staging)
    (staging / "dexfixture.apk").unlink()
    write_elf(
        staging / "lib/arm64-v8a/libdexfixture.so",
        symbols=(symbol(JNI_SYMBOL), symbol("malloc", shndx=0)),
        soname="libdexfixture.so",
    )

    apktool = tmp_path / "apktool-fixture"
    apktool.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import pathlib
            import shutil
            import sys

            args = sys.argv[1:]
            output = pathlib.Path(args[args.index("-o") + 1])
            shutil.copytree({str(staging)!r}, output, dirs_exist_ok=True)
            print("Apktool links fixture completed")
            """
        ),
        encoding="utf-8",
    )
    apktool.chmod(0o755)

    decompilation = DecompilationRunner(
        database,
        workspace=workspace,
        apktool_executable=str(apktool),
        timeout_seconds=60,
    ).run(run_id=run_id)
    assert decompilation.completed == 1, decompilation
    assert decompilation.failed == 0

    surface = run_static_surface_analysis(database, workspace, run_id=run_id)
    assert surface["completed"] == 1
    assert surface["failed"] == 0

    bundle = workspace / "results" / package_id / str(version_code) / digest
    links_path = bundle / "surface" / "links.jsonl"
    entry_path = bundle / "surface" / "entry_points.jsonl"
    assert links_path.is_file(), sorted(item.name for item in bundle.iterdir())
    assert entry_path.is_file()

    payload_json = json.loads(
        (bundle / "surface" / "static-analysis.json").read_text(encoding="utf-8")
    )
    assert payload_json["status"] == "success", payload_json["diagnostics"]
    metrics = payload_json["metrics"]
    graph = _read_jsonl(links_path)
    entry_points = _read_jsonl(entry_path)
    assert metrics["link_edge_count"] == len(graph) > 0
    assert metrics["entry_point_count"] == len(entry_points) >= 3
    # Coverage sourced from the written report, not from an in-memory dict.
    for key in link_module.COVERAGE_KEYS.values():
        assert key in payload_json["coverage"], key
    assert payload_json["coverage"]["link_type_component_class"] == "success"

    # The files came from this run: the launcher and its URL are in them.
    assert _one(
        _edges(graph, "component->class"),
        **{"from": "component:activity:com.example.Main"},
    )["to"] == "class:Lcom/example/Main;"
    assert _one(_edges(graph, "method->endpoint"))["to"] == (
        "endpoint:https://api.example.test/v1/feed"
    )
    assert {
        entry["entry_point"] for entry in entry_points
    } >= {
        "activity:com.example.Main",
        "service:com.example.SyncService",
        "application:com.example.App",
    }
