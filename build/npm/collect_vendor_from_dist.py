#!/usr/bin/env python3
"""
collect_vendor_from_dist.py

Extract Goreleaser archives into the npm vendor layout.

Usage:
    uv run build/npm/collect_vendor_from_dist.py --dist dist --out dist/npm/vendor
"""

from __future__ import annotations

import argparse
import shutil
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path


# Mapping of GOOS/GOARCH pairs to npm triples.
GO_TARGETS = {
    ("darwin", "amd64"): "darwin-amd64",
    ("darwin", "arm64"): "darwin-arm64",
    ("linux", "amd64"): "linux-amd64",
    ("linux", "arm64"): "linux-arm64",
}


@dataclass(frozen=True)
class ArchiveTarget:
    goos: str
    goarch: str
    npm_triple: str

    @property
    def archive_glob(self) -> str:
        return f"leash_*_{self.goos}_{self.goarch}.tar.gz"

    @property
    def vendor_binary(self) -> str:
        suffix = ".exe" if self.goos == "windows" else ""
        return f"{self.npm_triple}/leash{suffix}"


REQUIRED_TARGETS: tuple[ArchiveTarget, ...] = tuple(
    ArchiveTarget(goos, goarch, npm_triple)
    for (goos, goarch), npm_triple in GO_TARGETS.items()
)


class VendorCollectionError(RuntimeError):
    """Raised when the vendor tree cannot be produced."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract Goreleaser archives into vendor layout."
    )
    parser.add_argument(
        "--dist",
        type=Path,
        required=True,
        help="Directory containing Goreleaser output archives.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Directory that will receive the vendor tree.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Remove any existing vendor directory before extraction.",
    )
    return parser.parse_args()


def ensure_clean_output(out_dir: Path, force: bool) -> None:
    if out_dir.exists():
        if not force:
            raise VendorCollectionError(
                f"Output directory {out_dir} already exists. Use --force to overwrite."
            )
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)


def find_archive(dist_dir: Path, target: ArchiveTarget) -> Path:
    matches = sorted(dist_dir.glob(target.archive_glob))
    if not matches:
        raise VendorCollectionError(
            f"No archive found for {target.goos}/{target.goarch} "
            f"matching pattern {target.archive_glob}."
        )
    if len(matches) > 1:
        raise VendorCollectionError(
            f"Multiple archives found for {target.goos}/{target.goarch}: {matches}"
        )
    return matches[0]


def safe_extract_binary(
    archive_path: Path, target: ArchiveTarget, dest_dir: Path
) -> None:
    with tarfile.open(archive_path, "r:gz") as tar:
        binary_members = [
            member
            for member in tar.getmembers()
            if member.name.split("/")[-1] in {"leash", "leash.exe"}
        ]
        if not binary_members:
            raise VendorCollectionError(
                f"Archive {archive_path} does not contain a leash binary."
            )
        if len(binary_members) > 1:
            raise VendorCollectionError(
                f"Archive {archive_path} contains multiple potential leash binaries: "
                f"{[member.name for member in binary_members]}"
            )
        member = binary_members[0]
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise VendorCollectionError(
                f"Archive {archive_path} contains unsafe path {member.name}."
            )
        extraction_dir = dest_dir / target.npm_triple
        extraction_dir.mkdir(parents=True, exist_ok=True)
        tar.extractall(path=extraction_dir, members=[member], filter="data")

        extracted_path = extraction_dir / member_path
        if extracted_path.is_dir():
            # Binaries should be files; surface a meaningful failure.
            raise VendorCollectionError(
                f"Expected {extracted_path} to be a file, found directory."
            )

        final_path = extraction_dir / (
            "leash.exe" if extracted_path.name.endswith(".exe") else "leash"
        )
        if extracted_path != final_path:
            shutil.move(str(extracted_path), final_path)
            prune_empty_directories(extracted_path.parent, extraction_dir)
        else:
            final_path = extracted_path

        final_path.chmod(
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IXUSR
            | stat.S_IRGRP
            | stat.S_IXGRP
            | stat.S_IROTH
            | stat.S_IXOTH
        )


def collect_vendor(dist_dir: Path, out_dir: Path) -> None:
    for target in REQUIRED_TARGETS:
        archive = find_archive(dist_dir, target)
        safe_extract_binary(archive, target, out_dir)


def prune_empty_directories(path: Path, stop_dir: Path) -> None:
    current = path
    while current != stop_dir and current.exists():
        try:
            current.rmdir()
        except OSError:
            break
        current = current.parent


def main() -> None:
    args = parse_args()
    dist_dir: Path = args.dist
    out_dir: Path = args.out

    if not dist_dir.exists():
        raise VendorCollectionError(f"Dist directory {dist_dir} does not exist.")

    ensure_clean_output(out_dir, force=args.force)
    collect_vendor(dist_dir, out_dir)


if __name__ == "__main__":
    try:
        main()
    except VendorCollectionError as exc:
        raise SystemExit(str(exc))
