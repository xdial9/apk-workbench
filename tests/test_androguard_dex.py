from __future__ import annotations

import time
from pathlib import Path

import pytest

from apkworkbench.analysis import androguard_dex


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
    import androguard.core.analysis.analysis as analysis_module
    import androguard.core.apk as apk_module
    import androguard.core.dex as dex_module

    class FakeMethod:
        def __init__(self, class_name, name, descriptor, *, external=False, android_api=False):
            self.class_name = class_name
            self.name = name
            self.descriptor = descriptor
            self.external = external
            self.android_api = android_api
            self.full_name = f"{class_name} {name} {descriptor}"

        def is_external(self):
            return self.external

        def is_android_api(self):
            return self.android_api

        def get_xref_from(self):
            return [(object(), caller, 123)]

        def get_xref_to(self):
            return [(object(), network_method, 456)]

    caller = FakeMethod("Lcom/example/Main;", "load", "()V")
    network_method = FakeMethod(
        "Lokhttp3/Call;", "execute", "()Lokhttp3/Response;",
        external=True,
    )
    permission_method = FakeMethod(
        "Landroid/location/LocationManager;",
        "getLastKnownLocation",
        "(Ljava/lang/String;)Landroid/location/Location;",
        external=True,
        android_api=True,
    )

    class FakeString:
        def __init__(self, value):
            self.value = value

        def get_value(self):
            return self.value

        def get_xref_from(self, with_offset=False):
            assert with_offset is True
            return [(object(), caller, 789)]

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

    class FakeAnalysis:
        def add(self, _vm):
            pass

        def create_xref(self):
            pass

        def get_internal_methods(self):
            return [caller]

        def get_external_methods(self):
            return [network_method, permission_method]

        def get_internal_classes(self):
            return [object()]

        def get_external_classes(self):
            return [object()]

        def get_strings(self):
            return [
                FakeString("https://api.example.test/v1"),
                FakeString("/catalog/products"),
                FakeString("/res/drawable/logo.png"),
            ]

        def get_permissions(self, api_level):
            assert api_level == 35
            return [(permission_method, ["android.permission.ACCESS_FINE_LOCATION"])]

    monkeypatch.setattr(apk_module, "APK", FakeApk)
    monkeypatch.setattr(dex_module, "DEX", FakeDex)
    monkeypatch.setattr(analysis_module, "Analysis", FakeAnalysis)

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
    assert relative_route["references"][0]["caller"] == caller.full_name
    assert not any(
        item["value"] == "/res/drawable/logo.png"
        for item in result["dex_api_strings"]
    )
    assert result["permission_api_usage"][0]["permissions"] == [
        "android.permission.ACCESS_FINE_LOCATION"
    ]
