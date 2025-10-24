#!/usr/bin/env python3
"""
docker_tags.py

Compute the set of Docker tags and related metadata for a project image.

Example:
    ./build/docker_tags.py \
        --image ghcr.io/strongdm/leash:latest \
        --version v1.2.3

The script prints shell-ready variable assignments that can be `eval`'d:
    CHANNEL_NAME='main'
    COMMIT='abc1234'
    TAG_LIST='repo:tag1 repo:tag2'
    TAG_ARGS='-t repo:tag1 -t repo:tag2'
"""
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable


class TagError(RuntimeError):
    """Raised when tagging metadata cannot be produced."""


@dataclass
class TagConfig:
    image: str
    version: str
    extra_tags: tuple[str, ...] = ()


@dataclass
class GitState:
    branch: str
    short_sha: str
    dirty: bool

    @property
    def commit(self) -> str:
        suffix = "-dirty" if self.dirty else ""
        return f"{self.short_sha}{suffix}"

    @property
    def dev_tag_base(self) -> str:
        return f"dev-{self.commit}"


def run_git(args: Iterable[str]) -> str:
    try:
        out = subprocess.check_output(["git", *args], stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover - keep shell compatible fallback
        raise TagError(f"git {' '.join(args)} failed: {exc}") from exc
    return out.decode().strip()


def current_git_branch() -> str:
    try:
        branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"])
    except TagError:
        return "main"

    branch = branch.strip()
    if branch in ("HEAD", ""):
        return "main"

    branch = branch.lower()
    branch = re.sub(r"[^a-z0-9._-]", "-", branch)
    branch = re.sub(r"-{2,}", "-", branch)
    branch = branch.strip("-")
    return branch or "main"


def current_git_state() -> GitState:
    try:
        short_sha = run_git(["rev-parse", "--short=7", "HEAD"])
    except TagError:
        short_sha = "dev"

    try:
        status_output = subprocess.check_output(
            ["git", "status", "--porcelain"],
            stderr=subprocess.STDOUT,
        )
        dirty = bool(status_output.strip())
    except (OSError, subprocess.CalledProcessError):
        dirty = False

    return GitState(branch=current_git_branch(), short_sha=short_sha, dirty=dirty)


def parse_image(image: str) -> tuple[str, str]:
    if not image:
        raise TagError("image value is required")

    # Handle digests ("repo@sha256:...") by splitting before @.
    if "@" in image:
        repo, _, digest = image.partition("@")
        if not repo:
            raise TagError(f"unable to determine image repository for {image!r}")
        return repo, image  # default tag is the full digest reference

    repo, sep, tag = image.rpartition(":")
    if sep and repo:
        return repo, image
    return image, image  # no explicit tag provided


def shell_assign(name: str, value: str) -> str:
    return f"{name}={shlex.quote(value)}"


def unique_append(accum: list[str], candidate: str | None) -> None:
    if candidate and candidate not in accum:
        accum.append(candidate)


def compute_tags(cfg: TagConfig, state: GitState) -> dict[str, str]:
    repo, default_tag = parse_image(cfg.image)

    channel = state.branch if state.branch else "main"
    dev_tag_base = state.dev_tag_base
    dev_tag = f"{repo}:{dev_tag_base}"
    branch_tag = ""
    if channel != "main":
        branch_tag = f"{repo}:{dev_tag_base}-{channel}"

    include_default = default_tag != f"{repo}:main"

    version_tag = ""
    if cfg.version:
        version_tag = f"{repo}:{cfg.version}"

    tags: list[str] = []
    unique_append(tags, version_tag)
    unique_append(tags, dev_tag)
    unique_append(tags, branch_tag)
    if include_default:
        unique_append(tags, default_tag)

    for extra in cfg.extra_tags:
        unique_append(tags, extra)

    tag_args = " ".join(f"-t {tag}" for tag in tags)
    tag_list = " ".join(tags)

    return {
        "CHANNEL_NAME": channel,
        "COMMIT": state.commit,
        "DEV_TAG": dev_tag,
        "BRANCH_TAG": branch_tag,
        "DEFAULT_TAG": default_tag,
        "TAG_LIST": tag_list,
        "TAG_ARGS": tag_args,
        "VERSION_TAG_FULL": version_tag,
    }


def parse_args(argv: list[str]) -> TagConfig:
    parser = argparse.ArgumentParser(description="Generate Docker tagging metadata.")
    parser.add_argument("--image", required=True, help="Base image reference, e.g. ghcr.io/org/app:latest")
    parser.add_argument("--version", default="", help="Version label to attach as a tag (e.g. v1.2.3 or dev-abc123)")
    parser.add_argument(
        "--extra-tag",
        action="append",
        default=[],
        help="Additional tag reference to include verbatim (repeatable).",
    )
    args = parser.parse_args(argv)
    extra_tags = tuple(tag.strip() for tag in args.extra_tag if tag and tag.strip())
    return TagConfig(image=args.image, version=args.version, extra_tags=extra_tags)


def main(argv: list[str]) -> int:
    try:
        cfg = parse_args(argv[1:])
        git_state = current_git_state()
        data = compute_tags(cfg, git_state)
    except TagError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    for key, value in data.items():
        print(shell_assign(key, value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
