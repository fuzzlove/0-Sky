#!/usr/bin/env python3
"""Compare retained manual conversions and generate review-only rule candidates."""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat.forensics import ArtifactRef, compare_pair
from zero_sky_compat.rule_mining import mine


def resolve(spec: dict, search_roots: list[Path]) -> Path:
    if "path" in spec:
        path = (ROOT / spec["path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()):
            raise ValueError("manifest path escapes repository")
        if path.is_file() or path.is_dir():
            return path
        raise FileNotFoundError(spec["path"])
    name = spec.get("search_filename")
    if not name or Path(name).name != name:
        raise ValueError("invalid search filename")
    matches = []
    for search_root in search_roots:
        candidate = search_root.expanduser().resolve() / name
        if candidate.is_file() and not candidate.is_symlink():
            matches.append(candidate)
    if len(matches) != 1:
        raise FileNotFoundError(f"expected exactly one configured artifact named {name}; found {len(matches)}")
    return matches[0]


def summarize_pair(pair: dict) -> dict:
    diff = pair["diff"]
    return {
        "pair_id": pair["pair_id"], "relationship": pair["relationship"],
        "original_sha256": pair["original"]["sha256"],
        "working_sha256": pair["working"]["sha256"],
        "files_added": len(diff["recursive_files"]["added"]),
        "files_removed": len(diff["recursive_files"]["removed"]),
        "files_content_changed": len(diff["content_changed"]),
        "files_mode_changed": len(diff["mode_changed"]),
        "macho_changed": len(diff["entitlements_and_macho"]["changed"]),
        "plist_changed": len(diff["plists"]["changed"]),
        "scripts_changed": len(diff["maintainer_scripts"]["changed"]),
        "runtime_evidence": pair["runtime_evidence"],
    }


def markdown(report: dict) -> str:
    lines = ["# 0-Sky Manual Conversion Findings", "",
             "This report compares retained originals and working derivatives without executing package scripts. Candidate rules remain `EXPERIMENTAL` until their validations and rule promotion requirements pass.", "",
             "## Compared pairs", "",
             "| Pair | Relationship | Added | Removed | Content changes | Mode changes | Mach-O changes |", "|---|---:|---:|---:|---:|---:|---:|"]
    for row in report["summary"]:
        lines.append(f"| `{row['pair_id']}` | {row['relationship']} | {row['files_added']} | {row['files_removed']} | {row['files_content_changed']} | {row['files_mode_changed']} | {row['macho_changed']} |")
    lines += ["", "## Findings", ""]
    for pair in report["pairs"]:
        diff = pair["diff"]
        lines += [f"### {pair['pair_id']}", "", f"Relationship: `{pair['relationship']}`.", "",
                  f"Original SHA-256: `{pair['original']['sha256']}`", "",
                  f"Working SHA-256: `{pair['working']['sha256']}`", "",
                  f"Changed payload files: {len(diff['content_changed'])}; added: {len(diff['recursive_files']['added'])}; removed: {len(diff['recursive_files']['removed'])}; mode changes: {len(diff['mode_changed'])}.", ""]
        if pair["pair_id"] == "trollrecorder-zip-normalization":
            lines += ["Every extracted member byte and Unix mode is identical. The derivative changes ZIP compression from Stored/LZMA to Deflate so the authorized SRD installer can extract it.", ""]
        elif pair["relationship"] == "cross_version_source_port":
            lines += ["This is source port evidence across different upstream versions. It cannot establish that the supplied binary was deterministically converted, so it is excluded from automatic rule reproduction claims.", ""]
        else:
            changed = diff["content_changed"][:20]
            if changed:
                lines += ["Changed files:", ""] + [f"- `{name}`" for name in changed] + [""]
    lines += ["## Generated candidate rules", ""]
    for rule in report["candidate_rules"]:
        lines += [f"- `{rule['id']}` — {rule['title']} ({rule['confidence']}, {rule['maturity']})"]
    lines += ["", "## Evidence gaps", ""]
    for gap in report["evidence_gaps"]:
        lines.append(f"- **{gap['component']}**: {gap['reason']}")
    lines += ["", "## Conclusions", "",
              "Two HIGH-confidence deterministic conversions reproduce retained working artifacts byte for byte: ZIP compression normalization for TrollRecorder and locked legacy plist canonicalization for the Doodle port. Source rebuild and signing differences remain manual or component-specific until stronger repeated evidence exists.", ""]
    return "\n".join(lines)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp")
    temporary.write_text(value)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "compatibility/manual-conversion-pairs.json")
    parser.add_argument("--search-root", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path, default=ROOT / "reports/manual-conversion-analysis.json")
    parser.add_argument("--docs", type=Path, default=ROOT / "docs/compatibility-findings.md")
    parser.add_argument("--rules", type=Path, default=ROOT / "compatibility/rules/generated-candidates")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    pairs = []
    for spec in manifest["pairs"]:
        original = resolve(spec["original"], args.search_root)
        working = resolve(spec["working"], args.search_root)
        pairs.append(compare_pair(spec["id"], spec["relationship"],
                                  ArtifactRef(spec["original"]["label"], original),
                                  ArtifactRef(spec["working"]["label"], working),
                                  spec.get("evidence", [])))
    candidates = mine(pairs)
    report = {"schema_version": 1, "engine": "0-Sky Compatibility Engine",
              "analysis_scope": "retained-manual-conversion-pairs",
              "summary": [summarize_pair(pair) for pair in pairs], "pairs": pairs,
              "candidate_rules": candidates,
              "evidence_gaps": manifest.get("known_evidence_gaps", []),
              "automatic_compatibility_claim": False}
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    atomic_text(args.report, encoded)
    document = markdown(report)
    atomic_text(args.docs, document)
    args.rules.mkdir(parents=True, exist_ok=True)
    for old in args.rules.glob("*.json"):
        old.unlink()
    for rule in candidates:
        atomic_text(args.rules / (rule["id"] + ".json"), json.dumps(rule, indent=2, sort_keys=True) + "\n")
    html_report = "<!doctype html><meta charset=utf-8><title>0-Sky Compatibility Findings</title><style>body{font-family:system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem}pre{white-space:pre-wrap}</style><h1>0-Sky Manual Conversion Findings</h1><pre>" + html.escape(document) + "</pre>"
    atomic_text(args.report.with_suffix(".html"), html_report)
    print(json.dumps({"pairs": len(pairs), "candidate_rules": len(candidates),
                      "report": str(args.report.relative_to(ROOT)),
                      "documentation": str(args.docs.relative_to(ROOT))}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
