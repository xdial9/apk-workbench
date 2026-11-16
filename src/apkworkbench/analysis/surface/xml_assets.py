"""Structured facts from decoded XML resources (P2c).

Two surfaces the manifest and the resource table cannot describe on their own:

1. FileProvider roots. A `<provider>` with a `FILE_PROVIDER_PATHS` meta-data
   declares which directories it will serve as `content://` URIs. The mapping
   lives in `res/xml/file_paths.xml`, not in the manifest, so without this a
   provider is just a name and an authority.
2. Layouts. `res/layout*/*.xml` maps a layout resource to the views it
   inflates and the ids it defines — the join between `R.layout.x`, a view
   class and the `findViewById` ids used in smali.

Nothing is guessed: a meta-data reference that cannot be resolved becomes a
diagnostic, an unparseable layout is recorded as failed, and a view is called
custom only when its tag is qualified or unknown to the framework list.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from apkworkbench.analysis.surface.findings import build_finding

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

FILE_PROVIDER_META_NAMES = frozenset({
    "android.support.FILE_PROVIDER_PATHS",
    "androidx.core.content.FileProvider",
})

FILE_PROVIDER_ROOT_TAGS = frozenset({
    "files-path", "cache-path", "external-path", "external-files-path",
    "external-cache-path", "external-media-path", "root-path",
})

# Framework view tags that are not fully qualified in a layout. Anything else
# (a dotted tag, or an unknown simple name) is reported as a custom view: it is
# either app code or a library view, and both matter for the code map.
FRAMEWORK_VIEWS = frozenset({
    "View", "ViewGroup", "ViewStub", "ViewFlipper", "ViewAnimator", "ViewSwitcher",
    "LinearLayout", "RelativeLayout", "FrameLayout", "AbsoluteLayout", "GridLayout",
    "TableLayout", "TableRow", "ScrollView", "HorizontalScrollView", "NestedScrollView",
    "CoordinatorLayout", "ConstraintLayout", "MotionLayout", "DrawerLayout",
    "SlidingPaneLayout", "SwipeRefreshLayout", "Toolbar", "AppBarLayout",
    "CollapsingToolbarLayout", "TabLayout", "BottomNavigationView", "NavigationView",
    "TextView", "EditText", "Button", "ImageButton", "ImageView",
    "CheckBox", "RadioButton", "RadioGroup", "Switch", "ToggleButton", "SeekBar",
    "ProgressBar", "RatingBar", "Spinner", "AutoCompleteTextView", "MultiAutoCompleteTextView",
    "ListView", "GridView", "ExpandableListView", "RecyclerView", "ViewPager",
    "ViewPager2", "WebView", "VideoView", "SurfaceView", "TextureView", "GLSurfaceView",
    "CalendarView", "DatePicker", "TimePicker", "NumberPicker", "SearchView",
    "Chip", "ChipGroup", "CardView", "Space", "Guideline", "Barrier", "Flow",
    "include", "merge", "requestFocus", "tag", "fragment", "androidx.fragment.app.FragmentContainerView",
})


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_file_paths(path: Path, relative: str) -> dict[str, Any]:
    """Parse one `res/xml/*.xml` FileProvider declaration."""
    result: dict[str, Any] = {
        "reference": relative,
        "status": "parsed",
        "roots": [],
        "error": None,
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    for node in root.iter():
        tag = _local(node.tag)
        if tag not in FILE_PROVIDER_ROOT_TAGS:
            continue
        result["roots"].append({
            "root_type": tag,
            "name": node.attrib.get("name"),
            "path": node.attrib.get("path"),
        })
    return result


def parse_layout(path: Path, relative: str) -> dict[str, Any]:
    """Parse one layout: view tags, custom views and the ids it defines."""
    result: dict[str, Any] = {
        "layout": relative,
        "status": "parsed",
        "view_count": 0,
        "views": [],
        "custom_views": [],
        "ids": [],
        "error": None,
    }
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    views: list[str] = []
    custom: set[str] = set()
    ids: list[str] = []
    for node in root.iter():
        tag = _local(node.tag)
        if tag in {"layout", "data", "variable", "import", "requestFocus", "tag"}:
            continue
        views.append(tag)
        if "." in tag or tag not in FRAMEWORK_VIEWS:
            custom.add(tag)
        identifier = node.attrib.get(ANDROID_NS + "id") or node.attrib.get("id")
        if identifier:
            name = identifier.split("/", 1)[-1].removeprefix("+")
            if name and name not in ids:
                ids.append(name)
    result["view_count"] = len(views)
    result["views"] = sorted(set(views))
    result["custom_views"] = sorted(custom)
    result["ids"] = ids
    return result


def collect_file_providers(
    components: list[dict[str, Any]],
    root: Path,
    files: list[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve every FileProvider meta-data to its roots.

    Returns (facts, findings, diagnostics). A provider without the meta-data is
    not a FileProvider and is left alone.
    """
    facts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    xml_files = [
        path for path in files
        if path.suffix.lower() == ".xml"
        and path.relative_to(root).as_posix().startswith("res/xml")
    ]
    for component in components or []:
        if component.get("type") != "provider":
            continue
        meta_entries = component.get("meta_data") or []
        reference = next(
            (entry for entry in meta_entries
             if entry.get("name") in FILE_PROVIDER_META_NAMES),
            None,
        )
        if reference is None:
            continue
        resource = str(reference.get("resource") or "")
        config_name = resource.rsplit("/", 1)[-1]
        if not config_name:
            diagnostics.append({
                "code": "file_provider_reference_missing",
                "message": f"{component.get('name')}: meta-data has no resource",
            })
            continue
        target = next(
            (path for path in xml_files if path.stem == config_name),
            None,
        )
        if target is None:
            diagnostics.append({
                "code": "file_provider_paths_missing",
                "message": (
                    f"{component.get('name')}: {resource} has no decoded "
                    f"res/xml/{config_name}.xml"
                ),
            })
            continue
        parsed = parse_file_paths(target, target.relative_to(root).as_posix())
        if parsed["status"] != "parsed":
            diagnostics.append({
                "code": "file_provider_paths_unparseable",
                "message": f"{parsed['reference']}: {parsed['error']}",
            })
            continue
        authority_list = (component.get("provider") or {}).get("authorities") or []
        authority = authority_list[0] if authority_list else ""
        exported = component.get("exported") == "true"
        for item in parsed["roots"]:
            facts.append({
                "kind": "file_provider_root",
                "value": f"{authority}/{item.get('name') or '?'}",
                "evidence": {"path": parsed["reference"]},
                "extra": {
                    "provider": component.get("name"),
                    "authority": authority,
                    "root_type": item.get("root_type"),
                    "name": item.get("name"),
                    "path": item.get("path"),
                    "exported": exported,
                    "meta_data": reference.get("name"),
                },
            })
        if exported and parsed["roots"]:
            findings.append(build_finding(
                "file_provider_exported", "components", "high",
                f"Exported FileProvider serves {len(parsed['roots'])} root(s)",
                "The provider is exported and resolves FileProvider paths; any "
                "app that can reach the authority can request those URIs. "
                "Check grantUriPermissions and the served directories.",
                parsed["reference"], None,
                ", ".join(str(item.get("path")) for item in parsed["roots"]),
                0.9,
            ))
    return facts, findings, diagnostics


def collect_layouts(
    root: Path,
    files: list[Path],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Inventory every layout file: views, custom views and defined ids."""
    facts: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for path in files:
        relative = path.relative_to(root).as_posix()
        if not relative.startswith("res/layout") or not relative.endswith(".xml"):
            continue
        parsed = parse_layout(path, relative)
        if parsed["status"] != "parsed":
            diagnostics.append({
                "code": "layout_unparseable",
                "message": f"{relative}: {parsed['error']}",
            })
            continue
        facts.append({
            "kind": "layout",
            "value": relative,
            "evidence": {"path": relative},
            "extra": {
                "view_count": parsed["view_count"],
                "views": parsed["views"],
                "ids": parsed["ids"],
                "custom_views": parsed["custom_views"],
            },
        })
        for custom in parsed["custom_views"]:
            facts.append({
                "kind": "custom_view",
                "value": custom,
                "evidence": {"path": relative},
                "extra": {"layout": relative},
            })
    return facts, diagnostics
