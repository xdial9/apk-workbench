"""Single-pass decode-tree classifier + original-APK zip inventory (plan v2 S2).

Doctrine notes:
- One os.walk, one routing decision per file, zero re-reads downstream.
- NOTHING is silently skipped: every non-scanned file class is named and
  counted (binary containers, unknown binary, undecodable, symlink).
- Magic-byte sniffing is data, not guessing: routing keys on observed bytes.
"""
from __future__ import annotations

import hashlib
import os
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Text routing whitelist (moved here so the classifier owns routing; the
# analyzer imports this name to preserve the established constant).
TEXT_SUFFIXES = {
    ".smali", ".xml", ".json", ".properties", ".yml", ".yaml", ".txt",
    ".js", ".html", ".htm", ".css", ".cfg", ".conf", ".ini", ".gradle",
    ".kt", ".java", ".md", ".plist", ".csv",
}

# Magic-byte table: prefix bytes -> content kind (observed data, not names).
MAGIC_TABLE: tuple[tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip_empty"),
    (b"\x1f\x8b", "gzip"),
    (b"\x7fELF", "elf"),
    (b"dex\n", "dex"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"\xca\xfe\xba\xbe", "java_class"),
)

ARCHIVE_KINDS = frozenset({"zip", "zip_empty", "gzip", "dex", "java_class"})

SNIFF_BYTES = 8


def sniff_magic(head: bytes) -> str | None:
    """Classify raw leading bytes against the observed-magic table."""
    for prefix, kind in MAGIC_TABLE:
        if head.startswith(prefix):
            return kind
    return None


def sniff_file_magic(path: Path) -> str | None:
    """Read only the first SNIFF_BYTES of a file; never load the whole file."""
    try:
        with path.open("rb") as handle:
            head = handle.read(SNIFF_BYTES)
    except OSError:
        return "unreadable"
    if not head:
        return "empty"
    return sniff_magic(head)


@dataclass(frozen=True)
class ClassifiedFile:
    path: Path
    relative: str
    suffix: str
    size_bytes: int
    content_kind: str | None   # sniff result: zip/dex/elf/... or None for text
    is_text_candidate: bool


@dataclass
class DecodedTree:
    root: Path
    files: list[Path] = field(default_factory=list)            # compat surface
    entries: list[ClassifiedFile] = field(default_factory=list)
    extension_counts: dict[str, int] = field(default_factory=dict)
    symlink_count: int = 0
    unreadable_count: int = 0
    class_counts: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "file_count": len(self.files),
            "symlink_entries_skipped": self.symlink_count,
            "unreadable_entries": self.unreadable_count,
            "extension_counts": dict(sorted(self.extension_counts.items())),
            "content_class_counts": dict(sorted(self.class_counts.items())),
        }


def classify_decoded_tree(root: Path) -> DecodedTree:
    """Single-pass classification of an apktool decode tree (S2)."""
    tree = DecodedTree(root=root)
    extensions: Counter[str] = Counter()
    classes: Counter[str] = Counter()
    for current, directories, names in os.walk(root):
        base = Path(current)
        kept_dirs = []
        for name in directories:
            candidate = base / name
            if candidate.is_symlink():
                tree.symlink_count += 1
            else:
                kept_dirs.append(name)
        directories[:] = kept_dirs
        for name in names:
            candidate = base / name
            if candidate.is_symlink():
                tree.symlink_count += 1
                continue
            if not candidate.is_file():
                tree.unreadable_count += 1
                continue
            suffix = candidate.suffix.lower()
            kind = sniff_file_magic(candidate)
            if kind == "unreadable":
                tree.unreadable_count += 1
            try:
                size_bytes = candidate.stat().st_size
            except OSError:
                size_bytes = 0
            is_text = kind in (None, "empty") and (
                suffix in TEXT_SUFFIXES or kind == "empty"
            )
            entry = ClassifiedFile(
                path=candidate,
                relative=candidate.relative_to(root).as_posix(),
                suffix=suffix,
                size_bytes=size_bytes,
                content_kind=kind,
                is_text_candidate=is_text,
            )
            tree.files.append(candidate)
            tree.entries.append(entry)
            extensions[suffix or "(no extension)"] += 1
            classes[
                kind if kind else ("text" if is_text else "unknown_binary")
            ] += 1
    tree.files.sort()
    tree.entries.sort(key=lambda entry: entry.path)
    tree.extension_counts = dict(extensions)
    tree.class_counts = dict(classes)
    return tree


def inventory_apk_zip(apk_path: Path) -> dict[str, Any]:
    """Full member inventory of the ORIGINAL APK (input-policy Appendix C).

    Every member is listed with size + sha256 (computed by streaming), and
    any member whose content is itself a container (zip/jar/dex/gzip) is
    recorded as a nested-archive fact. Nothing here is optional: undecoded
    members are mapped even when no decoder touches them.
    """
    members: list[dict[str, Any]] = []
    nested: list[str] = []
    total_uncompressed = 0
    with zipfile.ZipFile(apk_path) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            digest_obj = hashlib.sha256()
            head = b""
            size = 0
            error: str | None = None
            try:
                with archive.open(info) as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        digest_obj.update(chunk)
                        if len(head) < SNIFF_BYTES:
                            head += chunk[: SNIFF_BYTES - len(head)]
            except RuntimeError as exc:  # encrypted members (zipfile contract)
                error = f"encrypted: {type(exc).__name__}"
            except (OSError, zipfile.BadZipFile) as exc:
                error = f"{type(exc).__name__}"
            digest = digest_obj.hexdigest() if not error else None
            kind = sniff_magic(head) if head else ("empty" if size == 0 else None)
            suffix = Path(info.filename).suffix.lower()
            root_dex = (
                suffix == ".dex"
                and "/" not in info.filename
                and info.filename.rsplit(".", 1)[0].count(".") == 0
                and info.filename == "classes.dex"
            ) or (
                suffix == ".dex" and "/" not in info.filename
                and info.filename.startswith("classes")
            )
            if not root_dex and (
                kind in ARCHIVE_KINDS
                or suffix in {".zip", ".jar", ".apk", ".dex"}
            ):
                nested.append(info.filename)
            total_uncompressed += size
            members.append({
                "name": info.filename,
                "size": size,
                "compressed_size": info.compress_size,
                "sha256": digest,
                "content_kind": kind,
                "error": error,
            })
    members.sort(key=lambda member: member["name"])
    nested.sort()
    return {
        "source_path": os.fspath(apk_path),
        "file_count": len(members),
        "total_uncompressed_bytes": total_uncompressed,
        "members": members,
        "nested_archives": nested,
    }