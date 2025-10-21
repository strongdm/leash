#!/usr/bin/env python3
"""
versionator.py

Usage:
  ./build/versionator.py bin
  ./build/versionator.py docker
  ./build/versionator.py major
  ./build/versionator.py minor
  ./build/versionator.py patch
  ./build/versionator.py tag

Resolves the current project version based on (in priority order):
  1. A git tag matching vX.Y.Z on the current commit.
  2. Fallback to a dev snapshot string (dev-<shortSHA>[-dirty]).

Outputs the requested string for the caller.
"""
from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass

SEMVER_RE = re.compile(r"^v?(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)$")


class VersionError(RuntimeError):
    """Raised when a version cannot be resolved."""


@dataclass
class Version:
    major: int
    minor: int
    patch: int
    tag: str

    @property
    def bin(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def docker(self) -> str:
        return self.bin

    @property
    def tag_with_prefix(self) -> str:
        return self.tag

    def part(self, name: str) -> str:
        if name == "major":
            return str(self.major)
        if name == "minor":
            return str(self.minor)
        if name == "patch":
            return str(self.patch)
        raise ValueError(f"unknown part {name}")


def run_git_command(args: list[str]) -> str:
    return subprocess.check_output(["git"] + args, stderr=subprocess.STDOUT).decode().strip()


def current_git_tag() -> str | None:
    try:
        tag = run_git_command(["describe", "--tags", "--exact-match"])
        if SEMVER_RE.match(tag):
            return tag
        raise VersionError(f"current git tag '{tag}' does not match vX.Y.Z")
    except (subprocess.CalledProcessError, VersionError):
        return None


def snapshot_suffix() -> str:
    try:
        short_sha = run_git_command(["rev-parse", "--short=7", "HEAD"])
    except subprocess.CalledProcessError:
        short_sha = "unknown"

    dirty = ""
    try:
        subprocess.check_call(
            ["git", "diff", "--quiet", "HEAD", "--"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        dirty = "-dirty"

    return f"dev-{short_sha}{dirty}"


def snapshot_version() -> Version:
    suffix = snapshot_suffix()
    return Version(0, 0, 0, suffix)


def resolve_version() -> Version:
    tag = current_git_tag()
    if tag:
        match = SEMVER_RE.match(tag)
        assert match is not None
        return Version(int(match.group("major")), int(match.group("minor")), int(match.group("patch")), tag)
    return snapshot_version()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 1

    try:
        version = resolve_version()
    except VersionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    command = argv[1]

    if command == "bin":
        print(version.bin)
    elif command == "docker":
        print(version.docker)
    elif command == "tag":
        print(version.tag_with_prefix)
    elif command in {"major", "minor", "patch"}:
        print(version.part(command))
    else:
        print(f"Error: unknown command '{command}'", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
