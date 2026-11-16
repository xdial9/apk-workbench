"""P2c contracts: FileProvider roots and layout inventory."""
from __future__ import annotations

from apkworkbench.analysis.apk_surface import analyze_apk_surface

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
     package="com.example.app">
  <application android:label="Example">
    <provider android:name="androidx.core.content.FileProvider"
              android:authorities="com.example.files"
              android:exported="{exported}"
              android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/{paths}"/>
    </provider>
    <provider android:name="com.example.PlainProvider"
              android:authorities="com.example.plain"
              android:exported="false"/>
  </application>
</manifest>"""

FILE_PATHS = """<paths>
  <files-path name="files" path="."/>
  <cache-path name="cache" path="images/"/>
</paths>"""

LAYOUT = """<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:id="@+id/root">
  <TextView android:id="@+id/title"/>
  <com.example.MyView android:id="@+id/custom"/>
</LinearLayout>"""


def _tree(tmp_path, *, exported="true", paths="file_paths", layout=True):
    root = tmp_path / "apktool"
    (root / "res/xml").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        MANIFEST.format(exported=exported, paths=paths), encoding="utf-8"
    )
    if paths == "file_paths":
        (root / "res/xml/file_paths.xml").write_text(FILE_PATHS, encoding="utf-8")
    if layout:
        (root / "res/layout").mkdir(parents=True)
        (root / "res/layout/main.xml").write_text(LAYOUT, encoding="utf-8")
    return root


def test_file_provider_roots_are_joined_to_the_provider(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path))

    roots = [fact for fact in result["facts"] if fact["kind"] == "file_provider_root"]
    by_value = {fact["value"]: fact for fact in roots}
    assert set(by_value) == {"com.example.files/files", "com.example.files/cache"}
    files_root = by_value["com.example.files/files"]
    assert files_root["root_type"] == "files-path"
    assert files_root["authority"] == "com.example.files"
    assert files_root["provider"] == "androidx.core.content.FileProvider"
    assert files_root["exported"] is True
    assert files_root["evidence"][0]["path"] == "res/xml/file_paths.xml"
    assert result["coverage"]["file_provider_paths"] == "success"
    assert result["metrics"]["file_provider_root_count"] == 2


def test_exported_file_provider_is_a_finding(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path, exported="true"))

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert "file_provider_exported" in rules


def test_private_file_provider_is_not_flagged(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path, exported="false"))

    rules = {finding["rule_id"] for finding in result["findings"]}
    assert "file_provider_exported" not in rules


def test_missing_file_paths_is_a_diagnostic_not_a_guess(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path, paths="does_not_exist"))

    codes = [item["code"] for item in result["diagnostics"]]
    assert "file_provider_paths_missing" in codes
    assert result["coverage"]["file_provider_paths"] == "failed"
    assert not [
        fact for fact in result["facts"] if fact["kind"] == "file_provider_root"
    ]


def test_provider_without_file_paths_meta_data_is_ignored(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path))

    # The plain provider has no FILE_PROVIDER_PATHS meta-data.
    values = {
        fact["value"] for fact in result["facts"]
        if fact["kind"] == "file_provider_root"
    }
    assert all(value.startswith("com.example.files/") for value in values)


def test_layout_inventory_lists_views_ids_and_custom_views(tmp_path):
    result = analyze_apk_surface(_tree(tmp_path))

    layouts = [fact for fact in result["facts"] if fact["kind"] == "layout"]
    assert len(layouts) == 1
    layout = layouts[0]
    assert layout["value"] == "res/layout/main.xml"
    assert layout["view_count"] == 3
    assert layout["ids"] == ["root", "title", "custom"]
    assert layout["custom_views"] == ["com.example.MyView"]

    custom = [fact for fact in result["facts"] if fact["kind"] == "custom_view"]
    assert [fact["value"] for fact in custom] == ["com.example.MyView"]
    assert custom[0]["layout"] == "res/layout/main.xml"
    assert result["coverage"]["layout_inventory"] == "success"
    assert result["metrics"]["layout_count"] == 1
    assert result["metrics"]["custom_view_count"] == 1


def test_malformed_layout_is_recorded(tmp_path):
    root = _tree(tmp_path)
    (root / "res/layout/broken.xml").write_text("<LinearLayout", encoding="utf-8")

    result = analyze_apk_surface(root)

    codes = [item["code"] for item in result["diagnostics"]]
    assert "layout_unparseable" in codes
    assert result["coverage"]["layout_inventory"] == "partial"
    assert result["metrics"]["layout_count"] == 1
