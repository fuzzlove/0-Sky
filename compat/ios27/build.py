"""Pinned source recipe runner for reviewed iOS 27 ports.

Unknown source and recipes are rejected. Build output is compared across two
fresh workspaces; this does not grant device or repository admission.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ALLOWED_EXECUTABLES = {"/usr/bin/make", "/usr/bin/xcrun", "/usr/bin/python3", "/bin/cp"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    count = size = 0
    for path in sorted(root.rglob("*")):
        count += 1
        if count > 100000:
            raise ValueError("reviewed source exceeds file limit")
        if path.is_symlink():
            raise ValueError("reviewed build source contains a symbolic link")
        if path.is_file():
            size += path.stat().st_size
            if size > 4 * 1024 ** 3:
                raise ValueError("reviewed source exceeds size limit")
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0")
        digest.update(b"D" if path.is_dir() else sha256(path).encode())
    return digest.hexdigest()


def safe_relative(value: object) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("invalid recipe path")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("recipe path escapes its workspace")
    return path


def load_recipe(path: Path, reviews: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError("recipe is missing or unsafe")
    if reviews.is_symlink() or not reviews.is_file() or reviews.stat().st_size > 65536:
        raise ValueError("reviewed recipe registry is absent or unsafe")
    approved = json.loads(reviews.read_text())
    digest = sha256(path)
    if approved.get("schema") != 1 or approved.get("recipes", {}).get(path.name) != digest:
        raise ValueError("recipe hash has not been reviewed")
    recipe = json.loads(path.read_text())
    if (recipe.get("schema") != 1 or not isinstance(recipe.get("component_id"), str) or
            not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,99}", recipe["component_id"]) or
            not isinstance(recipe.get("source_tree_sha256"), str) or
            not re.fullmatch(r"[a-f0-9]{64}", recipe["source_tree_sha256"]) or
            (recipe.get("expected_output_sha256") is not None and
             not re.fullmatch(r"[a-f0-9]{64}", recipe["expected_output_sha256"]))):
        raise ValueError("recipe schema or source pin is invalid")
    safe_relative(recipe.get("source_rel"))
    safe_relative(recipe.get("output_rel"))
    if not isinstance(recipe.get("steps"), list) or not recipe["steps"] or len(recipe["steps"]) > 24:
        raise ValueError("recipe has no bounded build steps")
    for step in recipe["steps"]:
        argv = step.get("argv") if isinstance(step, dict) else None
        if (not isinstance(argv, list) or not argv or len(argv) > 48 or
                argv[0] not in ALLOWED_EXECUTABLES or
                any(not isinstance(arg, str) or not arg or "\0" in arg or
                    arg.startswith(("/Users/", "/Volumes/")) for arg in argv) or
                not isinstance(step.get("timeout"), int) or not 1 <= step["timeout"] <= 1200):
            raise ValueError("recipe contains an unreviewed command")
    return recipe


def run_reviewed_recipe(root: Path, recipe_path: Path, reviews: Path, output: Path) -> dict:
    recipe = load_recipe(recipe_path, reviews)
    root = root.resolve(strict=True)
    raw_source = root / safe_relative(recipe["source_rel"])
    source = raw_source.resolve(strict=True)
    if not source.is_relative_to(root) or not source.is_dir() or raw_source.is_symlink():
        raise ValueError("recipe source is outside reviewed root")
    if tree_hash(source) != recipe["source_tree_sha256"]:
        raise ValueError("source tree differs from pinned recipe")
    output_rel = safe_relative(recipe["output_rel"])
    hashes = []
    selected = None
    with tempfile.TemporaryDirectory(prefix="0sky-ios27-build-") as temporary:
        for attempt in (1, 2):
            work = Path(temporary) / ("build-" + str(attempt))
            shutil.copytree(source, work, symlinks=False)
            env = {key: os.environ[key] for key in ("PATH", "DEVELOPER_DIR", "SDKROOT") if key in os.environ}
            env.update(HOME=str(work), TMPDIR=str(work), ZERO_SKY_BUILD_ROOT=str(work))
            for step in recipe["steps"]:
                result = subprocess.run(step["argv"], cwd=work, env=env,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, timeout=step["timeout"], check=False)
                if result.returncode:
                    raise RuntimeError("reviewed build step failed: " + Path(step["argv"][0]).name +
                                       " exit " + str(result.returncode))
            raw_artifact = work / output_rel
            artifact = raw_artifact.resolve(strict=True)
            if not artifact.is_relative_to(work.resolve()) or not artifact.is_file() or raw_artifact.is_symlink():
                raise ValueError("build output is missing or outside workspace")
            hashes.append(sha256(artifact))
            if attempt == 2:
                selected = artifact
        if hashes[0] != hashes[1]:
            raise RuntimeError("two clean builds produced different bytes")
        expected = recipe.get("expected_output_sha256")
        if expected is not None and expected != hashes[0]:
            raise RuntimeError("built artifact differs from reviewed output hash")
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise FileExistsError("refusing to replace prior build artifact")
        staging = output.with_name(output.name + ".pending")
        shutil.copy2(selected, staging)
        if sha256(staging) != hashes[0]:
            raise RuntimeError("artifact changed while staging")
        staging.replace(output)
    return {"component_id": recipe["component_id"], "source_tree_sha256":
            recipe["source_tree_sha256"], "recipe_sha256": sha256(recipe_path),
            "artifact_sha256": hashes[0], "reproducible": True,
            "status": "BUILD_VERIFIED" if recipe.get("expected_output_sha256") else
                      "BUILD_OUTPUT_HASH_UNREVIEWED", "repo_admission": "BLOCKED"}
