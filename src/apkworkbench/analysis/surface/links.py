"""P4 link graph: typed edges (two citations each) + entry points.

Three separate lists is not a program. ``facts.jsonl`` says *what exists*;
``links.jsonl`` says *what is joined to what*, and every edge carries exactly
two citations — one for each end — so the AI can walk from an exported
component to the method that hits a URL, and from that URL to the permission
that gates it, without guessing.

Edge types and where each comes from (no new raw sources are introduced):

  component->class     manifest_v2 ``components[]`` x P3 ``class_model``
  class->method        P3 ``class_model`` + ``method_model`` (join on class_name)
  method->method       P3 ``internal_call_graph`` (caller/callee + dex_class)
  method->endpoint     ``dex_api_strings`` with url_matches/route_candidate,
                       joined through its ``references`` (real xref callers)
  endpoint->permission ``permission_api_usage`` (API -> permission) joined to the
                       methods that reference an endpoint, plus the manifest's
                       requested-permission list
  method->native       ``native_jni_entry`` facts written by native.py's
                       ``_map_jni_symbol`` (reused, not re-derived here)
  native->secret       TruffleHog findings whose file path is a modelled .so
  asset->reader        NOT derivable yet — see COVERAGE_KEYS + the diagnostic

Folding decision (explicit, not assumed): links are NOT folded into the
FactStore. A fact is deduped by value and its ``count`` means "occurrences of
this value"; an edge is a *relation* whose identity is the (from, to, citation)
triple, and publishing the same relation in two planes invites silent drift
between ``facts.jsonl`` and ``links.jsonl``. One edge lives in exactly one
plane. If a future phase does fold an edge in, it must go through
``FactStore.add(..., extra=...)`` so the RESERVED_FACT_KEYS guard
(kind/value/fingerprint/count/evidence) rejects an overwrite instead of
letting the record corrupt the facts plane.

Citations are :class:`EvidenceLocation` objects serialized field by field —
never an ad-hoc dict — so one key means one thing across facts, findings and
links. ``citations`` always holds exactly two entries: an edge with one
provable end is not an edge, and the half-relation belongs in the facts /
findings plane instead.
"""
from __future__ import annotations

import json
import os
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any

from apkworkbench.analysis.contracts import EvidenceLocation
from apkworkbench.analysis.surface.manifest_v2 import deep_link_targets

LINKS_FILENAME = "links.jsonl"
ENTRY_POINTS_FILENAME = "entry_points.jsonl"
LINKS_SCHEMA = 1

LAUNCHER_ACTION = "android.intent.action.MAIN"
LAUNCHER_CATEGORY = "android.intent.category.LAUNCHER"
BROWSABLE_CATEGORY = "android.intent.category.BROWSABLE"
DEFAULT_CATEGORY = "android.intent.category.DEFAULT"

EDGE_TYPES = (
    "component->class",
    "class->method",
    "method->method",
    "method->endpoint",
    "endpoint->permission",
    "method->native",
    "native->secret",
    "asset->reader",
)

EDGE_KEYS = frozenset({"edge_type", "from", "to", "citations"})

# One coverage key per edge type: "success" when at least one edge was proven,
# "not_applicable" when the data genuinely does not exist for this artifact.
# Never "success" with zero edges — that would read as "checked, found none".
COVERAGE_KEYS = {
    "component->class": "link_type_component_class",
    "class->method": "link_type_class_method",
    "method->method": "link_type_method_method",
    "method->endpoint": "link_type_method_endpoint",
    "endpoint->permission": "link_type_endpoint_permission",
    "method->native": "link_type_method_native",
    "native->secret": "link_type_native_secret",
    "asset->reader": "link_type_asset_reader",
}

# Analyzer evidence paths are tree-relative; handoff.py owns the rule for
# prefixing them with the per-component citation root. Same rule, same order,
# so a link citation and a fact citation never disagree about a directory.
NON_PATH_CITE_PREFIXES = (
    "sdk_root:", "permission:", "coverage:", "endpoint:", "route:", "fact:",
    "apk:",
)

# EvidenceLocation fields in their declared order (evidence_kind first).
EVIDENCE_FIELDS = tuple(
    item.name for item in dataclass_fields(EvidenceLocation)
)


def _cite_path(location: str, tree_root: str) -> str:
    """Prefix a tree-relative path with the citation root (mirror of handoff)."""
    if not location or not tree_root:
        return location
    if location.startswith((tree_root, "/", "~")):
        return location
    if location.startswith(NON_PATH_CITE_PREFIXES):
        return location
    return tree_root + location


def citation_to_dict(location: EvidenceLocation) -> dict[str, Any]:
    """Serialize an EvidenceLocation; omit empty fields, keep the key names."""
    payload: dict[str, Any] = {}
    for name in EVIDENCE_FIELDS:
        value = getattr(location, name)
        if value is None:
            continue
        if name == "extractor_coordinate":
            if not value:
                continue
            payload[name] = dict(value)
            continue
        payload[name] = value
    return payload


# ---- node identifiers ------------------------------------------------------
# Stable strings, not positional indexes: an AI can join two files on them.
def component_node(component_type: str, name: str) -> str:
    return f"component:{component_type}:{name}"


def class_node(class_descriptor: str) -> str:
    return f"class:{class_descriptor}"


def method_node(full_name: str) -> str:
    return f"method:{full_name}"


def endpoint_node(value: str) -> str:
    return f"endpoint:{value}"


def permission_node(name: str) -> str:
    return f"permission:{name}"


def native_node(library: str, symbol: str) -> str:
    return f"native:{library}::{symbol}"


def secret_node(detector: str, source_path: str, line: int | None) -> str:
    return f"secret:{detector}:{source_path}:{line if line is not None else '-'}"


# ---- citation builders -----------------------------------------------------
def _component_cite(
    component_type: str, name: str, manifest_relative: str, tree_root: str
) -> EvidenceLocation:
    return EvidenceLocation(
        evidence_kind="manifest_component",
        source_path=_cite_path(manifest_relative, tree_root),
        manifest_xpath=(
            f"/manifest/application/{component_type}"
            f"[@android:name='{name}']"
        ),
    )


def _class_cite(class_entry: dict[str, Any]) -> EvidenceLocation:
    """A class is declared in a DEX: the DEX index is the real coordinate."""
    return EvidenceLocation(
        evidence_kind="dex_class",
        dex_class=str(class_entry.get("class_name") or ""),
        extractor_coordinate={
            "dex_index": class_entry.get("dex_index"),
            "source_file": class_entry.get("source_file"),
        },
    )


def _method_cite(
    full_name: str,
    class_name: str | None,
    *,
    dex_index: Any = None,
    offset: Any = None,
    descriptor: str | None = None,
) -> EvidenceLocation:
    coordinate: dict[str, Any] = {}
    if dex_index is not None:
        coordinate["dex_index"] = dex_index
    if descriptor is not None:
        coordinate["descriptor"] = descriptor
    if offset is not None:
        coordinate["dex_offset"] = offset
    return EvidenceLocation(
        evidence_kind="dex_method",
        dex_class=class_name,
        method_signature=full_name,
        extractor_coordinate=coordinate,
    )


def _string_cite(
    value: str, caller: str, caller_class: str | None, offset: Any
) -> EvidenceLocation:
    coordinate: dict[str, Any] = {"value": value}
    if offset is not None:
        coordinate["dex_offset"] = offset
    return EvidenceLocation(
        evidence_kind="dex_string",
        dex_class=caller_class,
        method_signature=caller,
        extractor_coordinate=coordinate,
    )


def _permission_cite(
    permission: str,
    api_method: str,
    api_owner: str | None,
    permissions: list[str],
    requested: list[str] | None,
    manifest_relative: str,
    tree_root: str,
) -> EvidenceLocation:
    return EvidenceLocation(
        evidence_kind="permission_requirement",
        source_path=_cite_path(manifest_relative, tree_root),
        dex_class=api_owner,
        method_signature=api_method,
        extractor_coordinate={
            "permission": permission,
            "permissions": list(permissions),
            # Is THIS permission requested by the manifest? A requirement the
            # app never requested is still an edge, and this is where the AI
            # reads the difference.
            "requested": permission in (requested or ()),
            "manifest_path": _cite_path(manifest_relative, tree_root),
        },
    )


def _make_edge(
    edge_type: str,
    from_node: str,
    to_node: str,
    from_cite: EvidenceLocation,
    to_cite: EvidenceLocation,
) -> dict[str, Any]:
    if edge_type not in EDGE_TYPES:
        raise ValueError(f"unsupported edge type: {edge_type}")
    return {
        "edge_type": edge_type,
        "from": from_node,
        "to": to_node,
        "citations": [citation_to_dict(from_cite), citation_to_dict(to_cite)],
    }


# ---- derivation ------------------------------------------------------------
def _descriptor(java_name: str | None, package: str | None) -> str | None:
    """``com.example.Main`` -> ``Lcom/example/Main;`` (Android manifest rule).

    A leading ``.`` or a bare class name is package-relative; anything else is
    already fully qualified. No guessing: the package comes from the manifest.
    """
    name = (java_name or "").strip()
    if not name:
        return None
    if name.startswith("."):
        if not package:
            return None
        name = package + name
    elif "." not in name:
        if not package:
            return None
        name = f"{package}.{name}"
    return "L" + name.replace(".", "/") + ";"


def _manifest(surface_result: dict[str, Any]) -> dict[str, Any]:
    manifest = surface_result.get("manifest")
    return manifest if isinstance(manifest, dict) else {}


def _inventory(surface_result: dict[str, Any]) -> dict[str, Any]:
    inventory = surface_result.get("inventory")
    return inventory if isinstance(inventory, dict) else {}


def _dex(dex_result: dict[str, Any] | None) -> dict[str, Any]:
    return dex_result if isinstance(dex_result, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _record(
    diagnostics: list[dict[str, str]] | None, code: str, message: str
) -> None:
    if diagnostics is not None:
        diagnostics.append({"code": code, "message": message})


def _mark(
    coverage: dict[str, str] | None, edge_type: str, status: str
) -> None:
    if coverage is None:
        return
    key = COVERAGE_KEYS[edge_type]
    current = coverage.get(key)
    # "success" outranks "not_applicable"; a later empty bucket must not
    # downgrade an edge type that did produce edges.
    if current == "success" and status != "success":
        return
    coverage[key] = status


def _class_index(
    dex_result: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    classes: dict[str, dict[str, Any]] = {}
    for entry in _list(dex_result.get("class_model")):
        if isinstance(entry, dict) and entry.get("class_name"):
            classes[str(entry["class_name"])] = entry
    methods: dict[str, dict[str, Any]] = {}
    for entry in _list(dex_result.get("method_model")):
        if isinstance(entry, dict) and entry.get("full_name"):
            methods[str(entry["full_name"])] = entry
    return classes, methods


def _component_edges(
    surface_result: dict[str, Any],
    classes: dict[str, dict[str, Any]],
    *,
    manifest_relative: str,
    tree_root: str,
    diagnostics: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    package = _manifest(surface_result).get("package")
    for component in _list(_manifest(surface_result).get("components")):
        if not isinstance(component, dict):
            continue
        component_type = str(component.get("type") or "")
        name = str(component.get("name") or "")
        descriptor = _descriptor(name, package)
        if not component_type or not descriptor:
            continue
        class_entry = classes.get(descriptor)
        if class_entry is None:
            # The component class is not in the DEX: that is a real finding
            # (stub/missing/multidex gap), but there is no second citation to
            # prove an edge with, so no edge is invented here.
            _record(
                diagnostics,
                "link_component_class_unresolved",
                f"{component_type} {name}: no class {descriptor} in class_model",
            )
            continue
        edges.append(_make_edge(
            "component->class",
            component_node(component_type, name),
            class_node(descriptor),
            _component_cite(component_type, name, manifest_relative, tree_root),
            _class_cite(class_entry),
        ))
    return edges


def _class_method_edges(
    classes: dict[str, dict[str, Any]],
    methods: dict[str, dict[str, Any]],
    *,
    diagnostics: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for full_name, method in methods.items():
        class_name = str(method.get("class_name") or "")
        class_entry = classes.get(class_name)
        if class_entry is None:
            _record(
                diagnostics,
                "link_class_method_unresolved",
                f"method {full_name}: class {class_name!r} not in class_model",
            )
            continue
        edges.append(_make_edge(
            "class->method",
            class_node(class_name),
            method_node(full_name),
            _class_cite(class_entry),
            _method_cite(
                full_name,
                class_name,
                dex_index=class_entry.get("dex_index"),
                descriptor=method.get("descriptor"),
            ),
        ))
    return edges


def _method_method_edges(
    dex_result: dict[str, Any], classes: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    dex_index_by_class = {
        name: entry.get("dex_index") for name, entry in classes.items()
    }
    edges: list[dict[str, Any]] = []
    for edge in _list(dex_result.get("internal_call_graph")):
        if not isinstance(edge, dict):
            continue
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if not caller or not callee:
            continue
        caller_class = caller.split(" ", 1)[0] if " " in caller else None
        callee_class = callee.split(" ", 1)[0] if " " in callee else None
        offset = edge.get("offset")
        edges.append(_make_edge(
            "method->method",
            method_node(caller),
            method_node(callee),
            _method_cite(
                caller,
                caller_class,
                dex_index=dex_index_by_class.get(caller_class),
                offset=offset,
            ),
            # The callee side is the referenced method itself; an external
            # callee has no owning DEX, so no dex_index is claimed for it.
            _method_cite(
                callee,
                callee_class,
                dex_index=dex_index_by_class.get(callee_class),
            ),
        ))
    return edges


def _endpoint_value(entry: dict[str, Any]) -> str | None:
    if not isinstance(entry, dict):
        return None
    value = str(entry.get("value") or "")
    if not value:
        return None
    if _list(entry.get("urls")) or entry.get("route_candidate") is True:
        return value
    return None


def _endpoint_edges(
    dex_result: dict[str, Any],
    methods: dict[str, dict[str, Any]],
    classes: dict[str, dict[str, Any]],
    *,
    diagnostics: list[dict[str, str]] | None,
) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    """method->endpoint edges, plus caller -> {endpoints it references}.

    The second return value is what the permission join needs: the endpoint
    values reached from one method. It is derived here to keep one definition
    of "this method references this endpoint".
    """
    dex_index_by_class = {
        name: entry.get("dex_index") for name, entry in classes.items()
    }
    edges: list[dict[str, Any]] = []
    caller_endpoints: dict[str, set[str]] = {}
    for entry in _list(dex_result.get("dex_api_strings")):
        value = _endpoint_value(entry)
        if value is None:
            continue
        for reference in _list(entry.get("references")):
            if not isinstance(reference, dict):
                continue
            caller = str(reference.get("caller") or "")
            if not caller:
                continue
            if caller not in methods:
                # The xref caller must resolve to a modelled method, otherwise
                # the method end of the edge has no citation of its own.
                _record(
                    diagnostics,
                    "link_method_endpoint_unresolved",
                    f"{caller} references {value!r} but is not in method_model",
                )
                continue
            caller_class = str(
                reference.get("caller_class")
                or methods[caller].get("class_name")
                or ""
            )
            offset = reference.get("offset")
            edges.append(_make_edge(
                "method->endpoint",
                method_node(caller),
                endpoint_node(value),
                _method_cite(
                    caller,
                    caller_class,
                    dex_index=dex_index_by_class.get(caller_class),
                    offset=offset,
                ),
                _string_cite(value, caller, caller_class, offset),
            ))
            caller_endpoints.setdefault(caller, set()).add(value)
    return edges, caller_endpoints


def _endpoint_permission_edges(
    dex_result: dict[str, Any],
    caller_endpoints: dict[str, set[str]],
    methods: dict[str, dict[str, Any]],
    classes: dict[str, dict[str, Any]],
    requested_permissions: list[str],
    *,
    manifest_relative: str,
    tree_root: str,
    diagnostics: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for usage in _list(dex_result.get("permission_api_usage")):
        if not isinstance(usage, dict):
            continue
        api_method = str(usage.get("api_method") or "")
        permissions = [str(name) for name in _list(usage.get("permissions"))]
        if not api_method or not permissions:
            continue
        api_owner = (
            api_method.split(" ", 1)[0] if " " in api_method else None
        )
        for site in _list(usage.get("call_sites")):
            if not isinstance(site, dict):
                continue
            caller = str(site.get("caller") or "")
            caller_class = str(
                site.get("caller_class")
                or (methods.get(caller, {}) or {}).get("class_name")
                or ""
            )
            # Every endpoint this caller reaches is gated by the permission
            # the caller's API call requires.
            for value in sorted(caller_endpoints.get(caller, set())):
                for permission in permissions:
                    edges.append(_make_edge(
                        "endpoint->permission",
                        endpoint_node(value),
                        permission_node(permission),
                        _string_cite(
                            value, caller, caller_class, site.get("offset")
                        ),
                        _permission_cite(
                            permission,
                            api_method,
                            api_owner,
                            permissions,
                            requested_permissions,
                            manifest_relative,
                            tree_root,
                        ),
                    ))
    return edges


def _method_native_edges(
    surface_result: dict[str, Any],
    methods: dict[str, dict[str, Any]],
    *,
    tree_root: str,
    diagnostics: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    """JNI-to-Java mapping is produced once, in native.py; consume those facts.

    ``_map_jni_symbol`` (native.py) writes one ``native_jni_entry`` fact per
    mapped export, citing the .so byte offset *and* the smali declaration. This
    reader reuses that mapping — it never re-demangles or re-matches symbols.
    """
    edges: list[dict[str, Any]] = []
    for fact in _list(surface_result.get("facts")):
        if not isinstance(fact, dict) or fact.get("kind") != "native_jni_entry":
            continue
        library = str(fact.get("library") or "")
        symbol = str(fact.get("symbol") or "")
        java_class = str(fact.get("java_class") or "")
        java_method = str(fact.get("java_method") or "")
        java_signature = str(fact.get("java_signature") or "")
        if not (library and symbol and java_class and java_method):
            continue
        full_name = f"{java_class} {java_method} {java_signature}".strip()
        if full_name not in methods:
            _record(
                diagnostics,
                "link_method_native_unresolved",
                f"{library}::{symbol}: {full_name} not in method_model",
            )
            continue
        offset: Any = None
        smali_cite: EvidenceLocation | None = None
        for item in _list(fact.get("evidence")):
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if path == library and isinstance(item.get("offset"), int):
                offset = item["offset"]
            if path and path != library and isinstance(item.get("line"), int):
                smali_cite = EvidenceLocation(
                    evidence_kind="smali_declaration",
                    source_path=_cite_path(path, tree_root),
                    line_start=item["line"],
                )
        if smali_cite is not None:
            method_cite = smali_cite
        else:
            method_cite = _method_cite(
                full_name, java_class, descriptor=java_signature or None
            )
        edges.append(_make_edge(
            "method->native",
            method_node(full_name),
            native_node(library, symbol),
            method_cite,
            EvidenceLocation(
                evidence_kind="native_symbol",
                source_path=_cite_path(library, tree_root),
                byte_offset_start=offset,
                extractor_coordinate={
                    "symbol": symbol,
                    "java_class": java_class,
                    "java_method": java_method,
                    "mapping_confidence": fact.get("mapping_confidence"),
                },
            ),
        ))
    return edges


def _finding_path_line(finding: dict[str, Any]) -> tuple[str, int | None]:
    """Same coordinate trufflehog.py reads: SourceMetadata.Data.Filesystem."""
    source = finding.get("SourceMetadata")
    if not isinstance(source, dict):
        return "", None
    data = source.get("Data")
    if not isinstance(data, dict):
        return "", None
    filesystem = data.get("Filesystem") or data.get("filesystem")
    if not isinstance(filesystem, dict):
        return "", None
    path = str(filesystem.get("file") or filesystem.get("File") or "")
    raw_line = filesystem.get("line") or filesystem.get("Line")
    try:
        line = int(raw_line) if raw_line is not None else None
    except (TypeError, ValueError):
        line = None
    return path, line


def _match_library(
    finding_path: str, libraries: list[str]
) -> str | None:
    """Longest modelled .so whose path is a path-suffix of the finding's path."""
    matches = [
        library for library in libraries
        if finding_path == library or finding_path.endswith("/" + library)
    ]
    if not matches:
        return None
    return max(matches, key=len)


def _native_secret_edges(
    surface_result: dict[str, Any],
    trufflehog_findings: list[dict[str, Any]] | None,
    *,
    tree_root: str,
    diagnostics: list[dict[str, str]] | None,
) -> list[dict[str, Any]]:
    libraries = [
        str(item) for item in _list(_inventory(surface_result).get("native_libraries"))
        if item
    ]
    if not libraries:
        _record(
            diagnostics,
            "link_native_secret_no_native_libraries",
            "no .so is modelled in native inventory: nothing to attach a secret to",
        )
        return []
    if not trufflehog_findings:
        _record(
            diagnostics,
            "link_native_secret_source_absent",
            (
                "no TruffleHog findings supplied: the secrets stage runs "
                "separately from the surface pass, so a secret inside a "
                "modelled .so cannot be cited from this pass"
            ),
        )
        return []
    edges: list[dict[str, Any]] = []
    for finding in trufflehog_findings:
        if not isinstance(finding, dict):
            continue
        path, line = _finding_path_line(finding)
        library = _match_library(path, libraries) if path else None
        if library is None:
            continue
        detector = str(
            finding.get("DetectorName") or finding.get("DetectorType") or "unknown"
        )
        verified = finding.get("Verified") is True
        edges.append(_make_edge(
            "native->secret",
            native_node(library, detector),
            secret_node(detector, _cite_path(path, tree_root), line),
            EvidenceLocation(
                evidence_kind="native_library",
                source_path=_cite_path(library, tree_root),
            ),
            EvidenceLocation(
                evidence_kind="trufflehog_finding",
                source_path=_cite_path(path, tree_root),
                line_start=line,
                extractor_coordinate={
                    "detector": detector,
                    "detector_type": finding.get("DetectorType"),
                    "decoder": finding.get("DecoderName"),
                    "verification": "verified" if verified else "unverified",
                },
            ),
        ))
    return edges


def build_link_graph(
    surface_result: dict[str, Any],
    dex_result: dict[str, Any] | None,
    *,
    trufflehog_findings: list[dict[str, Any]] | None = None,
    tree_root: str = "apktool/",
    manifest_relative: str = "AndroidManifest.xml",
    coverage: dict[str, str] | None = None,
    diagnostics: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Build every provable typed edge, sorted and de-duplicated.

    ``coverage``/``diagnostics`` are optional sinks (same convention as
    ``parse_manifest_v2``): when supplied they receive one coverage key per
    edge type plus every reason an edge type produced nothing.
    """
    surface_result = surface_result or {}
    dex_result = _dex(dex_result)
    classes, methods = _class_index(dex_result)
    requested_permissions = [
        str(name) for name in _list(_manifest(surface_result).get("permissions"))
    ]

    edges: list[dict[str, Any]] = []
    edges.extend(_component_edges(
        surface_result, classes,
        manifest_relative=manifest_relative, tree_root=tree_root,
        diagnostics=diagnostics,
    ))
    edges.extend(_class_method_edges(classes, methods, diagnostics=diagnostics))
    edges.extend(_method_method_edges(dex_result, classes))
    endpoint_edges, caller_endpoints = _endpoint_edges(
        dex_result, methods, classes, diagnostics=diagnostics
    )
    edges.extend(endpoint_edges)
    edges.extend(_endpoint_permission_edges(
        dex_result, caller_endpoints, methods, classes, requested_permissions,
        manifest_relative=manifest_relative, tree_root=tree_root,
        diagnostics=diagnostics,
    ))
    edges.extend(_method_native_edges(
        surface_result, methods, tree_root=tree_root, diagnostics=diagnostics
    ))
    edges.extend(_native_secret_edges(
        surface_result, trufflehog_findings,
        tree_root=tree_root, diagnostics=diagnostics,
    ))

    # asset->reader has no provable source yet. classify.py exposes the asset
    # entries but no code path joins an asset path to the call that opens it:
    # the open is usually a stream Read over a resource id or a String that
    # only exists at runtime. Rather than guess, the type is declared
    # not_applicable with the reason.
    _record(
        diagnostics,
        "link_asset_reader_not_derivable",
        (
            "no provable source: the decoded tree names its asset files, but "
            "nothing in P0-P3 joins an asset path to the code that opens it "
            "(the open argument is a resource id or a runtime-built string)"
        ),
    )

    unique: dict[str, dict[str, Any]] = {}
    for edge in edges:
        key = json.dumps(edge, ensure_ascii=False, sort_keys=True)
        unique.setdefault(key, edge)
    ordered = [unique[key] for key in sorted(unique)]

    produced = {edge["edge_type"] for edge in ordered}
    for edge_type in EDGE_TYPES:
        _mark(coverage, edge_type, "success" if edge_type in produced else "not_applicable")
    return ordered


# ---- entry points ----------------------------------------------------------
def _reachability(
    component: dict[str, Any], exported: bool | None,
    actions: list[str], categories: list[str], links: list[dict[str, Any]],
    authorities: list[str],
) -> list[str]:
    reasons: list[str] = []
    if exported is True:
        reasons.append("exported")
    if exported is None and component.get("has_intent_filter"):
        # Platform default: an intent filter makes a component exported unless
        # android:exported says otherwise (targetSdk-dependent pre-31).
        reasons.append("export_default_with_intent_filter")
    if LAUNCHER_ACTION in actions and LAUNCHER_CATEGORY in categories:
        reasons.append("launcher_activity")
    if links:
        reasons.append("deep_link")
    if BROWSABLE_CATEGORY in categories:
        reasons.append("browsable")
    if authorities:
        reasons.append("provider_authority")
    return reasons


def _entry_point_record(
    component_type: str,
    name: str,
    descriptor: str | None,
    exported: bool | None,
    reasons: list[str],
    *,
    declared_permission: str | None,
    requested_permissions: list[str],
    actions: list[str],
    categories: list[str],
    links: list[dict[str, Any]],
    authorities: list[str],
    citations: tuple[EvidenceLocation, EvidenceLocation | None],
    manifest_relative: str,
    tree_root: str,
) -> dict[str, Any]:
    component_cite, class_cite = citations
    return {
        "schema_version": LINKS_SCHEMA,
        "entry_point": f"{component_type}:{name}",
        "component_type": component_type,
        "name": name,
        "class_descriptor": descriptor,
        "class_in_dex": class_cite is not None,
        "exported": exported,
        "externally_reachable": bool(reasons),
        "reachability": reasons,
        "declared_permission": declared_permission,
        "declared_permission_requested": (
            None if declared_permission is None
            else declared_permission in requested_permissions
        ),
        "intent_actions": actions,
        "intent_categories": categories,
        "deep_links": links,
        "provider_authorities": authorities,
        "citation": citation_to_dict(component_cite),
        "class_citation": (
            citation_to_dict(class_cite) if class_cite is not None else None
        ),
        "manifest_path": _cite_path(manifest_relative, tree_root),
    }


def build_entry_points(
    surface_result: dict[str, Any],
    dex_result: dict[str, Any] | None,
    *,
    tree_root: str = "apktool/",
    manifest_relative: str = "AndroidManifest.xml",
) -> list[dict[str, Any]]:
    """Every externally reachable manifest component + the Application class."""
    surface_result = surface_result or {}
    manifest = _manifest(surface_result)
    classes, _methods = _class_index(_dex(dex_result))
    requested_permissions = [
        str(item) for item in _list(manifest.get("permissions"))
    ]
    package = manifest.get("package")
    entries: list[dict[str, Any]] = []

    for component in _list(manifest.get("components")):
        if not isinstance(component, dict):
            continue
        component_type = str(component.get("type") or "")
        name = str(component.get("name") or "")
        descriptor = _descriptor(name, package)
        if not component_type or not descriptor:
            continue
        raw_exported = component.get("exported")
        exported = (
            True if raw_exported == "true"
            else False if raw_exported == "false"
            else None
        )
        filters = [
            item for item in _list(component.get("intent_filters"))
            if isinstance(item, dict)
        ]
        actions = sorted({
            str(action)
            for item in filters for action in _list(item.get("actions"))
        })
        categories = sorted({
            str(category)
            for item in filters for category in _list(item.get("categories"))
        })
        links = deep_link_targets(filters) if filters else []
        provider = component.get("provider")
        authorities = (
            [str(item) for item in _list(provider.get("authorities"))]
            if isinstance(provider, dict) else []
        )
        reasons = _reachability(
            component, exported, actions, categories, links, authorities
        )
        if not reasons:
            continue
        class_entry = classes.get(descriptor)
        entries.append(_entry_point_record(
            component_type, name, descriptor, exported, reasons,
            declared_permission=component.get("permission"),
            requested_permissions=requested_permissions,
            actions=actions,
            categories=categories,
            links=links,
            authorities=authorities,
            citations=(
                _component_cite(
                    component_type, name, manifest_relative, tree_root
                ),
                _class_cite(class_entry) if class_entry is not None else None,
            ),
            manifest_relative=manifest_relative,
            tree_root=tree_root,
        ))

    application = manifest.get("application")
    app_name = (
        str(application.get("name") or "")
        if isinstance(application, dict) else ""
    )
    app_descriptor = _descriptor(app_name, package)
    if app_descriptor:
        class_entry = classes.get(app_descriptor)
        entries.append(_entry_point_record(
            "application", app_name, app_descriptor, None,
            ["application_class"],
            declared_permission=None,
            requested_permissions=requested_permissions,
            actions=[], categories=[], links=[], authorities=[],
            citations=(
                EvidenceLocation(
                    evidence_kind="manifest_application",
                    source_path=_cite_path(manifest_relative, tree_root),
                    manifest_xpath="/manifest/application",
                    extractor_coordinate={"android:name": app_name},
                ),
                _class_cite(class_entry) if class_entry is not None else None,
            ),
            manifest_relative=manifest_relative,
            tree_root=tree_root,
        ))

    entries.sort(key=lambda item: (item["component_type"], item["name"]))
    return entries


# ---- writers ---------------------------------------------------------------
def _atomic_write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    """Temp + fsync + replace, the same pattern resources.jsonl uses."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            for record in records:
                handle.write(
                    json.dumps(
                        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ) + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def write_links(
    directory: str | Path,
    edges: list[dict[str, Any]],
    entry_points: list[dict[str, Any]],
) -> dict[str, Path]:
    """Write ``links.jsonl`` + ``entry_points.jsonl`` into ``directory``."""
    target = Path(directory)
    return {
        "links": _atomic_write_jsonl(target / LINKS_FILENAME, edges),
        "entry_points": _atomic_write_jsonl(
            target / ENTRY_POINTS_FILENAME, entry_points
        ),
    }
