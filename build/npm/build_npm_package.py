#!/usr/bin/env python3
"""
build_npm_package.py

Stage the npm package and invoke `npm pack`.

Usage:
    uv run build/npm/build_npm_package.py --version 1.2.3 --vendor dist/npm/vendor
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


DEFAULT_PACKAGE_ROOT = Path("npm/leash")
DEFAULT_LICENSE = Path("LICENSE")
STAGING_DEFAULT = Path("dist/npm/stage")
PACK_DEST_DEFAULT = Path("dist/npm")


class PackageBuildError(RuntimeError):
    """Raised when the npm package cannot be produced."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the leash npm package.")
    parser.add_argument(
        "--version", required=True, help="Semantic version to embed in package.json."
    )
    parser.add_argument(
        "--vendor",
        type=Path,
        required=True,
        help="Path to the collected vendor tree (output of collect_vendor_from_dist.py).",
    )
    parser.add_argument(
        "--package-root",
        type=Path,
        default=DEFAULT_PACKAGE_ROOT,
        help="Directory containing package scaffolding (README, bin, package.json template).",
    )
    parser.add_argument(
        "--license",
        type=Path,
        default=DEFAULT_LICENSE,
        help="License file to include in the package.",
    )
    parser.add_argument(
        "--stage",
        type=Path,
        default=None,
        help="Optional staging directory. If omitted, a temporary directory is used.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=PACK_DEST_DEFAULT,
        help="Destination directory for npm pack output (tarball).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite staging and output directories if they already exist.",
    )
    parser.add_argument(
        "--npm-bin",
        default="npm",
        help="npm executable to invoke (default: npm from PATH).",
    )
    return parser.parse_args()


def load_package_template(package_root: Path) -> dict[str, Any]:
    package_json_path = package_root / "package.json"
    if not package_json_path.exists():
        raise PackageBuildError(f"Missing package.json template at {package_json_path}")
    with package_json_path.open("r", encoding="utf-8") as handle:
        template = json.load(handle)
    if "version" in template:
        # The stage builder owns the version field; surface unexpected template versions.
        raise PackageBuildError(
            f"package.json template should not define 'version' (found in {package_json_path})"
        )
    return template


def ensure_directory(path: Path, *, allow_existing: bool) -> None:
    if path.exists():
        if not allow_existing:
            raise PackageBuildError(
                f"Directory {path} already exists. Use --force to overwrite."
            )
        if path.is_file():
            raise PackageBuildError(f"{path} exists and is a file, expected directory.")
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_scaffold(package_root: Path, staging_dir: Path) -> None:
    bin_src = package_root / "bin"
    if not bin_src.exists():
        raise PackageBuildError(f"Missing bin directory at {bin_src}")
    shutil.copytree(bin_src, staging_dir / "bin", dirs_exist_ok=True)

    readme_src = package_root / "README.md"
    if not readme_src.exists():
        raise PackageBuildError(f"Missing README at {readme_src}")
    shutil.copy2(readme_src, staging_dir / "README.md")


def copy_vendor_tree(vendor_src: Path, staging_dir: Path) -> None:
    if not vendor_src.exists():
        raise PackageBuildError(f"Vendor directory {vendor_src} does not exist.")
    shutil.copytree(vendor_src, staging_dir / "vendor", dirs_exist_ok=True)


def copy_license(license_src: Path, staging_dir: Path) -> None:
    if not license_src.exists():
        raise PackageBuildError(f"License file {license_src} does not exist.")
    shutil.copy2(license_src, staging_dir / "LICENSE")


def write_package_json(
    template: dict[str, Any], version: str, staging_dir: Path
) -> None:
    package_json_path = staging_dir / "package.json"
    package = dict(template)
    package["version"] = version
    with package_json_path.open("w", encoding="utf-8") as handle:
        json.dump(package, handle, indent=2)
        handle.write("\n")


def run_npm_pack(staging_dir: Path, out_dir: Path, npm_bin: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [
        npm_bin,
        "pack",
        "--json",
        "--pack-destination",
        str(out_dir),
        str(staging_dir),
    ]
    result = subprocess.run(
        command,
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise PackageBuildError(
            f"npm pack failed with exit code {result.returncode}: {result.stderr.strip()}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PackageBuildError(f"Failed to parse npm pack output: {exc}") from exc
    if not isinstance(data, list) or not data:
        raise PackageBuildError(f"Unexpected npm pack output: {data!r}")
    entry = data[0]
    filename = entry.get("filename")
    if not filename:
        raise PackageBuildError(f"npm pack output missing filename: {entry!r}")
    return out_dir / filename


def build_package(args: argparse.Namespace) -> Path:
    package_root: Path = args.package_root
    vendor_src: Path = args.vendor
    license_src: Path = args.license
    out_dir: Path = args.out
    version: str = args.version

    template = load_package_template(package_root)

    if args.stage is None:
        with tempfile.TemporaryDirectory(prefix="leash-npm-stage-") as tmpdir:
            staging_dir = Path(tmpdir)
            copy_scaffold(package_root, staging_dir)
            copy_vendor_tree(vendor_src, staging_dir)
            copy_license(license_src, staging_dir)
            write_package_json(template, version, staging_dir)
            return run_npm_pack(staging_dir, out_dir, args.npm_bin)

    staging_dir = args.stage
    ensure_directory(staging_dir, allow_existing=args.force)
    copy_scaffold(package_root, staging_dir)
    copy_vendor_tree(vendor_src, staging_dir)
    copy_license(license_src, staging_dir)
    write_package_json(template, version, staging_dir)
    return run_npm_pack(staging_dir, out_dir, args.npm_bin)


def main() -> None:
    args = parse_args()

    try:
        tarball = build_package(args)
    except PackageBuildError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"npm package created: {tarball}")


if __name__ == "__main__":
    main()
