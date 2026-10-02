"""Mine reviewable compatibility rules from forensic artifact differences."""
from __future__ import annotations

import hashlib
import json


def _rule(rule_id: str, title: str, confidence: str, matches: list[str],
          preconditions: list[str], transformation: dict, validation: list[str],
          pairs: list[str]) -> dict:
    value = {
        "schema_version": 1, "id": rule_id, "version": 1, "maturity": "EXPERIMENTAL",
        "title": title, "confidence": confidence, "derived_from": sorted(set(pairs)),
        "match": matches, "preconditions": preconditions, "transformation": transformation,
        "rollback": "discard derivative workspace and preserve original artifact",
        "validation": validation,
        "production_eligible": False,
    }
    value["evidence_fingerprint"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return value


def mine(pairs: list[dict]) -> list[dict]:
    rules = []
    compression_pairs = []
    resign_pairs = []
    plist_pairs = []
    for pair in pairs:
        before = pair["original"]["archive"]
        after = pair["working"]["archive"]
        if before.get("format") == after.get("format") == "zip":
            b_members, a_members = before.get("members", {}), after.get("members", {})
            same_names = b_members.keys() == a_members.keys()
            payload_same = not pair["diff"]["content_changed"] and not pair["diff"]["mode_changed"]
            compression_changed = any(
                b_members[name].get("compression") != a_members[name].get("compression")
                for name in b_members.keys() & a_members.keys())
            if same_names and payload_same and compression_changed:
                compression_pairs.append(pair["pair_id"])
        changed = set(pair["diff"]["content_changed"])
        if (pair["relationship"] == "iterative_adapted_package" and
                pair["diff"]["package_metadata"]["changed"] == ["Version"] and
                len(pair["diff"]["plists"]["changed"]) == 1 and
                changed == {"DEBIAN/control", pair["diff"]["plists"]["changed"][0]}):
            plist_pairs.append(pair["pair_id"])
        if changed and all(name.endswith("/_CodeSignature/CodeResources") or
                           name.rsplit("/", 1)[-1] in ("SRDZsh", "srdzsh-rootd")
                           for name in changed):
            resign_pairs.append(pair["pair_id"])
    if compression_pairs:
        rules.append(_rule(
            "zip-compression-normalization-v1",
            "Normalize unsupported IPA/TIPA ZIP compression",
            "HIGH", ["zip member compression is BZIP2 or LZMA"],
            ["archive passes bounded structural validation", "all member paths are safe",
             "member expansion is within configured limits"],
            {"type": "archive_repackage", "target_compression": "DEFLATE",
             "preserve": ["member bytes", "names", "timestamps", "comments", "Unix modes"]},
            ["member names unchanged", "member SHA-256 unchanged", "member modes unchanged",
             "archive CRC passes", "SRD installer extraction succeeds"], compression_pairs))
    if resign_pairs:
        rules.append(_rule(
            "authorized-resign-after-source-build-v1",
            "Refresh authorized signatures after a controlled source build",
            "MANUAL", ["Mach-O and CodeResources are the only changed payload files"],
            ["source provenance is pinned", "entitlement contract is reviewed",
             "configured SRD signing mechanism is available"],
            {"type": "source_build_signing", "automatic_binary_rewrite": False},
            ["Mach-O dependency graph unchanged", "required entitlements preserved",
             "strict signature verification", "install, launch, functional and rollback UAT"],
            resign_pairs))
    if plist_pairs:
        rules.append(_rule(
            "legacy-plist-canonicalization-v1",
            "Canonicalize a parseable legacy tweak filter plist",
            "HIGH", ["declared tweak filter is parseable by platform plutil but not strict plistlib"],
            ["package identity and input version match conversion lock",
             "semantic plist value is preserved", "filter scope is not widened"],
            {"type": "deb_plist_canonicalization", "format": "XML1",
             "version_change": "must be declared in conversion lock"},
            ["strict plist parser succeeds", "semantic value unchanged",
             "all unrelated payload hashes and modes unchanged", "runtime tweak and filter UAT pass"],
            plist_pairs))
    return rules
