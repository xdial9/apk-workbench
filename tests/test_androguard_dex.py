from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from apkworkbench.analysis import androguard_dex

# Real, tiny APK: apktool-built from smali (sources kept next to it) with one
# classes.dex, three internal classes, literal + dynamic Class.forName and
# Method.invoke call sites. Used for the code-model join assertions.
FIXTURE_APK = Path(__file__).parent / "fixtures" / "dexfixture" / "dexfixture.apk"


class FakeMethod:
    def __init__(
        self,
        class_name,
        name,
        descriptor,
        *,
        external=False,
        android_api=False,
        xref_from=None,
        xref_to=None,
        method_idx=0,
    ):
        self.class_name = class_name
        self.name = name
        self.descriptor = descriptor
        self.external = external
        self.android_api = android_api
        self.full_name = f"{class_name} {name} {descriptor}"
        self.method_idx = method_idx
        self._xref_from = xref_from
        self._xref_to = xref_to or []

    def is_external(self):
        return self.external

    def is_android_api(self):
        return self.android_api

    def get_xref_from(self):
        return list(self._xref_from or [])

    def get_xref_to(self):
        return list(self._xref_to)

    def get_access_flags_string(self):
        return "public static"

    def get_method(self):
        return self

    def get_method_idx(self):
        return self.method_idx


class FakeString:
    def __init__(self, value, reference_caller=None):
        self.value = value
        self.reference_caller = reference_caller

    def get_value(self):
        return self.value

    def get_xref_from(self, with_offset=False):
        assert with_offset is True
        if self.reference_caller is None:
            return []
        return [(object(), self.reference_caller, 789)]


class FakeApk:
    def __init__(self, _path):
        pass

    def get_effective_target_sdk_version(self):
        return 35

    def get_target_sdk_version(self):
        return 35

    def get_all_dex(self):
        return [b"fake dex"]

    def get_package(self):
        return "com.example.app"

    def get_androidversion_code(self):
        return "17"

    def get_androidversion_name(self):
        return "17.0"

    def get_min_sdk_version(self):
        return "23"

    def get_permissions(self):
        return ["android.permission.ACCESS_FINE_LOCATION"]

    def get_uses_implied_permission_list(self):
        return []

    def get_features(self):
        return []

    def get_libraries(self):
        return []

    def get_main_activity(self):
        return "com.example.Main"


class FakeDex:
    def __init__(self, _data, using_api=None):
        assert using_api == 35


class FakeClassManager:
    def __init__(self, vm=None):
        self.vm = vm

    def get_string(self, index):
        return "Main.java" if index == 0 else None


class FakeClassDef:
    def __init__(self, name):
        self.name = name
        self.CM = FakeClassManager()
        self.annotations_directory_item = None

    def get_name(self):
        return self.name

    def get_access_flags_string(self):
        return "public"

    def get_superclassname(self):
        return "Ljava/lang/Object;"

    def get_interfaces(self):
        return []

    def get_source_file_idx(self):
        return 0

    def get_annotations(self):
        return []


class FakeClassAnalysis:
    def __init__(self, name, methods):
        self.name = name
        self._methods = methods
        self._class_def = FakeClassDef(name)

    def get_vm_class(self):
        return self._class_def

    def get_methods(self):
        return list(self._methods)

    def get_fields(self):
        return []


def install_fake_androguard(monkeypatch):
    """Hermetic androguard stand-in used by the code-path tests.

    Mirrors the real 4.1.4 surface confirmed by introspection:
    ClassAnalysis.get_vm_class() -> ClassDefItem, MethodAnalysis.get_method(),
    get_access_flags_string(), get_xref_from/to() with offsets.
    """
    import androguard.core.analysis.analysis as analysis_module
    import androguard.core.apk as apk_module
    import androguard.core.dex as dex_module

    network_method = FakeMethod(
        "Lokhttp3/Call;", "execute", "()Lokhttp3/Response;", external=True
    )
    permission_method = FakeMethod(
        "Landroid/location/LocationManager;",
        "getLastKnownLocation",
        "(Ljava/lang/String;)Landroid/location/Location;",
        external=True,
        android_api=True,
    )
    # D4: referenced external method that no instruction calls.
    callerless_method = FakeMethod(
        "Lokhttp3/Interceptor;", "intercept", "(Lokhttp3/Chain;)Lokhttp3/Response;",
        external=True,
    )

    caller = FakeMethod(
        "Lcom/example/Main;",
        "load",
        "()V",
        xref_from=[(object(), FakeMethod("Lcom/example/Helper;", "caller", "()V"), 1)],
        xref_to=[(object(), network_method, 456)],
    )
    unrelated_caller = FakeMethod("Lcom/example/Helper;", "format", "()V")
    network_method._xref_from = [(object(), caller, 123)]
    permission_method._xref_from = [(object(), caller, 124)]
    caller._xref_from = [(object(), unrelated_caller, 122)]

    for method, index in ((caller, 0), (unrelated_caller, 1)):
        method.method_idx = index

    strings = [
        FakeString("https://api.example.test/v1", caller),
        FakeString("/catalog/products", caller),
        FakeString("/catalog/categories", unrelated_caller),
        FakeString("/res/drawable/logo.png", caller),
    ]

    internal_class = FakeClassAnalysis("Lcom/example/Main;", [caller])

    class FakeAnalysis:
        def add(self, _vm):
            pass

        def create_xref(self):
            pass

        def get_internal_methods(self):
            return [caller]

        def get_external_methods(self):
            return [network_method, permission_method, callerless_method]

        def get_internal_classes(self):
            return [internal_class]

        def get_external_classes(self):
            return [object()]

        def get_strings(self):
            return strings

        def get_permissions(self, api_level):
            assert api_level == 35
            return [(permission_method, ["android.permission.ACCESS_FINE_LOCATION"])]

    monkeypatch.setattr(apk_module, "APK", FakeApk)
    monkeypatch.setattr(dex_module, "DEX", FakeDex)
    monkeypatch.setattr(analysis_module, "Analysis", FakeAnalysis)
    return {
        "caller": caller,
        "network_method": network_method,
        "permission_method": permission_method,
        "callerless_method": callerless_method,
    }


@pytest.fixture(scope="module")
def fixture_result():
    """One real-APK analysis shared by the code-model tests (read-only)."""
    assert FIXTURE_APK.is_file(), f"missing fixture APK: {FIXTURE_APK}"
    result = androguard_dex._analyze_in_worker(str(FIXTURE_APK))
    assert result["status"] == "success", result["diagnostics"]
    return result


def test_androguard_worker_result_is_returned_from_isolated_process(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"fixture")
    payload = {
        "status": "success",
        "metrics": {"dex_files": 2, "external_methods_referenced": 7},
        "coverage": {"dex_parsing": "success"},
        "external_method_references": [{"full_name": "Lokhttp3/Call; execute ()"}],
    }
    monkeypatch.setattr(androguard_dex, "_analyze_in_worker", lambda _path: payload)

    result = androguard_dex.analyze_apk_dex(apk, timeout_seconds=5)

    assert result == payload


def test_androguard_analysis_timeout_terminates_worker(monkeypatch, tmp_path):
    apk = tmp_path / "fixture.apk"
    apk.write_bytes(b"fixture")

    def slow_worker(_path):
        time.sleep(5)
        return {"status": "success"}

    monkeypatch.setattr(androguard_dex, "_analyze_in_worker", slow_worker)

    result = androguard_dex.analyze_apk_dex(apk, timeout_seconds=1)

    assert result["status"] == "timed_out"
    assert result["coverage"]["dex_parsing"] == "timed_out"


def test_androguard_rejects_missing_symlink_and_non_apk_paths(tmp_path):
    missing = tmp_path / "missing.apk"
    text_file = tmp_path / "notes.txt"
    text_file.write_text("not an APK", encoding="utf-8")
    outside = tmp_path / "outside.apk"
    outside.write_bytes(b"fixture")
    symlink = tmp_path / "linked.apk"
    symlink.symlink_to(outside)

    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(missing)
    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(text_file)
    with pytest.raises(ValueError, match="regular APK file"):
        androguard_dex.analyze_apk_dex(symlink)


def test_androguard_extracts_external_api_calls_strings_and_permission_usage(monkeypatch):
    methods = install_fake_androguard(monkeypatch)
    caller = methods["caller"]
    network_method = methods["network_method"]

    result = androguard_dex._analyze_in_worker("fixture.apk")

    assert result["status"] == "success"
    assert result["metrics"]["dex_files"] == 1
    assert result["external_method_references"][0]["full_name"] == network_method.full_name
    assert result["external_method_references"][0]["call_sites"][0]["caller"] == caller.full_name
    url_string = next(
        item for item in result["dex_api_strings"]
        if item["value"] == "https://api.example.test/v1"
    )
    assert url_string["urls"] == ["https://api.example.test/v1"]
    relative_route = next(
        item for item in result["dex_api_strings"]
        if item["value"] == "/catalog/products"
    )
    assert relative_route["route_candidate"] is True
    assert relative_route["relative_path_candidate"] is True
    assert relative_route["network_call_context"] is True
    assert relative_route["rate_limit_or_retry_indicator"] is False
    assert relative_route["references"][0]["caller"] == caller.full_name
    assert not any(
        item["value"] == "/catalog/categories"
        for item in result["dex_api_strings"]
    )
    assert not any(
        item["value"] == "/res/drawable/logo.png"
        for item in result["dex_api_strings"]
    )
    assert result["permission_api_usage"][0]["permissions"] == [
        "android.permission.ACCESS_FINE_LOCATION"
    ]


def test_embedded_dex_permission_usage_is_json_serializable(monkeypatch):
    methods = install_fake_androguard(monkeypatch)

    result = androguard_dex._analyze_dex_payloads(
        [(b"fake dex", "assets/embedded/classes.dex")],
        target_sdk=35,
    )

    assert result["permission_api_usage"][0] == {
        "api_method": methods["permission_method"].full_name,
        "permissions": ["android.permission.ACCESS_FINE_LOCATION"],
        "call_sites": [{
            "caller": methods["caller"].full_name,
            "caller_class": "Lcom/example/Main;",
            "offset": 124,
        }],
    }
    json.dumps(result)


def test_class_model_shape_matches_dex_class_count(fixture_result):
    result = fixture_result
    assert result["coverage"]["code_model"] == "success"
    # Exit criteria: class_model count == the DEX class count in metrics.
    assert len(result["class_model"]) == result["metrics"]["classes"]
    assert result["metrics"]["class_model_count"] == result["metrics"]["classes"]

    expected_keys = {
        "dex_index",
        "class_name",
        "access_flags",
        "superclass",
        "interfaces",
        "source_file",
        "method_count",
        "field_count",
        "annotations",
    }
    for entry in result["class_model"]:
        assert set(entry) == expected_keys
        assert isinstance(entry["dex_index"], int)
        assert isinstance(entry["interfaces"], list)
        assert isinstance(entry["annotations"], list)
        assert isinstance(entry["method_count"], int)
        assert isinstance(entry["field_count"], int)

    by_name = {entry["class_name"]: entry for entry in result["class_model"]}
    secret = by_name["Lcom/example/Secret;"]
    assert secret["dex_index"] == 0
    assert secret["superclass"] == "Ljava/lang/Object;"
    assert secret["source_file"] == "Secret.java"
    assert secret["method_count"] == 2
    assert secret["field_count"] == 2
    assert secret["annotations"] == ["Lcom/example/Marked;"]


def test_method_model_and_call_graph_join_back_to_class_model(fixture_result):
    result = fixture_result
    class_names = {entry["class_name"] for entry in result["class_model"]}
    method_names = {entry["full_name"] for entry in result["method_model"]}

    assert result["method_model"]
    assert result["metrics"]["method_model_count"] == len(result["method_model"])
    assert result["metrics"]["method_model_count"] == result["metrics"]["internal_methods"]
    for entry in result["method_model"]:
        assert set(entry) == {
            "class_name",
            "method_name",
            "full_name",
            "access_flags",
            "descriptor",
            "annotations",
        }
        # Exit criteria: every method resolves back to a class in class_model.
        assert entry["class_name"] in class_names

    assert result["internal_call_graph"]
    for edge in result["internal_call_graph"]:
        # Every edge endpoint is a method, and its class is in class_model.
        assert edge["caller"] in method_names
        assert edge["caller"].split(" ")[0] in class_names
        assert edge["callee"].split(" ")[0].startswith("L")


def test_dex_class_key_is_present_on_every_edge_and_external_reference(fixture_result):
    result = fixture_result
    assert result["internal_call_graph"]
    for edge in result["internal_call_graph"]:
        assert "dex_class" in edge
        assert edge["dex_class"] == 0
    assert result["external_method_references"]
    for entry in result["external_method_references"]:
        assert "dex_class" in entry
        for site in entry["call_sites"]:
            assert site["dex_class"] == 0


def test_dex_class_key_is_present_when_origin_is_unknown(monkeypatch):
    install_fake_androguard(monkeypatch)

    result = androguard_dex._analyze_in_worker("fixture.apk")

    # The fake stack has no DEX object on its methods, so origin is unknown —
    # the key must still be present (None), never missing.
    for edge in result["internal_call_graph"]:
        assert edge["dex_class"] is None
    for entry in result["external_method_references"]:
        assert "dex_class" in entry
        for site in entry["call_sites"]:
            assert site["dex_class"] is None


def test_external_method_without_callers_is_emitted_not_dropped(monkeypatch):
    methods = install_fake_androguard(monkeypatch)

    result = androguard_dex._analyze_in_worker("fixture.apk")

    # D4: the callerless method is still a finding, with an explicit empty
    # call_sites list, and the drop is visible in metrics.
    assert result["metrics"]["external_methods_without_callers"] == 1
    orphan = next(
        entry for entry in result["external_method_references"]
        if entry["full_name"] == methods["callerless_method"].full_name
    )
    assert orphan["call_sites"] == []
    assert "dex_class" in orphan
    assert result["metrics"]["external_methods_referenced"] == len(
        result["external_method_references"]
    ) == 3


def test_reflection_sites_keep_literal_and_dynamic_for_name(fixture_result):
    sites = fixture_result["reflection_sites"]
    assert sites
    assert fixture_result["metrics"]["reflection_site_count"] == len(sites)

    for_name_sites = [site for site in sites if site["api"] == "Ljava/lang/Class;->forName"]
    # Three call sites: two literal, one parameter. None may be dropped.
    assert len(for_name_sites) == 3

    literal = next(
        site for site in for_name_sites
        if site["caller"].startswith("Lcom/example/Main; reflectLiteral")
    )
    assert literal["argument_resolved"] is True
    assert literal["resolved_target"] == "com.example.Secret"
    assert literal["resolution_kind"] == "class_name"
    assert literal["unresolved_reason"] is None
    assert literal["caller_class"] == "Lcom/example/Main;"

    dynamic = next(
        site for site in for_name_sites
        if site["caller"].startswith("Lcom/example/Main; reflectDynamic")
    )
    assert dynamic["argument_resolved"] is False
    assert dynamic["resolved_target"] is None
    assert dynamic["unresolved_reason"] == "no_string_constant_before_call_site"


def test_reflection_sites_cover_get_method_and_invoke(fixture_result):
    sites = fixture_result["reflection_sites"]

    declared = next(
        site for site in sites if site["api"] == "Ljava/lang/Class;->getDeclaredMethod"
    )
    assert declared["argument_resolved"] is True
    assert declared["resolved_target"] == "load"
    assert declared["resolution_kind"] == "member_name"

    invoke_sites = [
        site for site in sites if site["api"] == "Ljava/lang/reflect/Method;->invoke"
    ]
    assert len(invoke_sites) == 2
    for site in invoke_sites:
        # invoke takes objects, not literals: never a guessed target.
        assert site["argument_resolved"] is False
        assert site["resolved_target"] is None
        assert site["unresolved_reason"] == "no_literal_argument"


def test_string_class_index_links_values_to_referencing_classes(fixture_result):
    index = fixture_result["string_class_index"]
    assert index["com.example.Secret"] == ["Lcom/example/Main;"]
    assert index["load"] == ["Lcom/example/Main;"]
    assert fixture_result["metrics"]["string_class_index_entries"] == len(index)
    # Unreferenced pool strings are absent (unreferenced, not dropped silently):
    # the class-name literal is the piece Class.forName resolution depends on.
    assert all(isinstance(classes, list) and classes for classes in index.values())
