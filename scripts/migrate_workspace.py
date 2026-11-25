#!/usr/bin/env python3
"""Copy legacy APK-Workbench workspace bundles into the single-folder `~/APK-Workbench/runs/` layout."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apkworkbench.core.layout import migrate_legacy_workspace


def _build_parser() -> argparse.ArgumentParser:
    home = Path.home()
    parser = argparse.ArgumentParser(
        description=(
            "Migrate legacy APK-Workbench results/<pkg>/<ver>/<digest> bundles into "
            "the consolidated single-folder <target>/runs/ layout (copy-only; never deletes source)."
        )
    )
    parser.add_argument(
        "--source",
        type=Path,
        default=home / "APK-Workbench" / "workspace",
        help="Path to the legacy workspace directory containing results/ and downloads/.",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=home / "APK-Workbench",
        help="Path to the consolidated APK-Workbench home folder.",
    )
    parser.add_argument(
        "--legacy-config",
        type=Path,
        default=home / ".config" / "apkworkbench" / "config.yaml",
        help="Optional legacy config.yaml path to copy into <target>/config.yaml if absent.",
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Preview what would be migrated without modifying any files (default).",
    )
    mode_group.add_argument(
        "--apply",
        action="store_true",
        help="Actually copy bundles and update <target>/runs_index.json.",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print the full migration report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    dry_run = not args.apply

    report = migrate_legacy_workspace(
        args.source,
        args.target,
        dry_run=dry_run,
        legacy_config_path=args.legacy_config,
    )

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    mode = "DRY RUN" if report["dry_run"] else "APPLIED"
    print(f"APK-Workbench Workspace Migration ({mode})")
    print(f"  Source:           {report['source_workspace']}")
    print(f"  Target:           {report['target_home']}")
    print(f"  Bundles found:    {report['bundles_found']}")
    print(f"  Bundles migrated: {report['bundles_migrated']}")
    print(f"  Bundles skipped:  {report['bundles_skipped']}")
    print(
        f"  Dossiers:         {report['dossiers_verified']}/{report['dossiers_found']} verified"
        if not report["dry_run"]
        else f"  Dossiers found:   {report['dossiers_found']}"
    )
    print(
        f"  Lead ledgers:     {report['lead_ledgers_verified']}/{report['lead_ledgers_found']} verified"
        if not report["dry_run"]
        else f"  Lead ledgers:     {report['lead_ledgers_found']}"
    )
    cfg = report["legacy_config"]
    if cfg["source"]:
        cfg_state = "copied" if cfg["copied"] else ("would copy" if cfg["would_copy"] else "already present")
        print(f"  Legacy config:    {cfg['source']} -> {cfg['target']} ({cfg_state})")
    else:
        print("  Legacy config:    none found")

    if report["items"]:
        print("\nBundles:")
        for item in report["items"]:
            flags: list[str] = []
            if item["has_dossier"]:
                flags.append("dossier" + (":verified" if item["dossier_verified"] else ""))
            if item["has_lead_ledger"]:
                flags.append("lead_ledger" + (":verified" if item["lead_ledger_verified"] else ""))
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"  - {item['action']:16s} {item['folder']}{flag_str}")

    if report["dry_run"]:
        print("\nRe-run with --apply to copy bundles into the consolidated home folder.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
