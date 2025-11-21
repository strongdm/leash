#!/usr/bin/env python3
"""Aggregate latest release data for bundled coder CLIs."""

from __future__ import annotations

import gzip
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

CLI_SOURCES: List[Dict[str, Optional[str]]] = [
    {"key": "@openai/codex", "npm": "@openai/codex", "github": "openai/codex"},
    {"key": "@anthropic-ai/claude-code", "npm": "@anthropic-ai/claude-code", "github": "anthropics/claude-code"},
    {"key": "@google/gemini-cli", "npm": "@google/gemini-cli", "github": "google-gemini/gemini-cli"},
    {"key": "@qwen-code/qwen-code", "npm": "@qwen-code/qwen-code", "github": "QwenLM/qwen-code"},
    {"key": "opencode-ai@latest", "npm": "opencode-ai", "github": "sst/opencode"},
]

NPM_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "leash-coder-cli-releases/1.0 (+https://github.com/strongdm/leash)",
}
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "leash-coder-cli-releases/1.0 (+https://github.com/strongdm/leash)",
}
HTTP_TIMEOUT = 30


def main() -> None:
    cli_results: Dict[str, Dict[str, Any]] = {}
    summary_candidates: List[Tuple[datetime, str]] = []

    for source in CLI_SOURCES:
        result, error = collect_cli_release(source)
        entry: Dict[str, Any] = {"Error": error}
        if result is not None:
            entry.update(result)
            published_at = extract_publish_time(result)
            if published_at is not None:
                summary_candidates.append((published_at, source["key"]))
        cli_results[source["key"]] = entry

    summary = build_summary(summary_candidates)
    output = {"Summary": summary, "CoderCLIs": cli_results}
    print(json.dumps(output, indent=2))


def collect_cli_release(source: Dict[str, Optional[str]]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    entry: Dict[str, Any] = {"GitHub": None, "NPM": None}
    errors: List[str] = []

    npm_package = source.get("npm")
    if npm_package:
        npm_data, npm_error = fetch_npm_metadata(npm_package)
        if npm_error:
            errors.append(f"npm: {npm_error}")
        else:
            entry["NPM"] = npm_data
    else:
        errors.append("npm: package not specified")

    github_repo = source.get("github")
    if github_repo:
        github_data, github_error = fetch_github_release(github_repo)
        if github_error:
            errors.append(f"github: {github_error}")
        else:
            entry["GitHub"] = github_data

    error_msg = "; ".join(errors) if errors else None
    return entry, error_msg


def fetch_npm_metadata(package: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    encoded = urlparse.quote(package, safe="@")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        data = http_get_json(url, NPM_HEADERS)
    except RuntimeError as exc:
        return None, truncate_error(str(exc))

    dist_tags = data.get("dist-tags") or {}
    versions = data.get("versions") or {}
    latest = dist_tags.get("latest")
    if not latest:
        return None, "missing dist-tags.latest"

    version_data = versions.get(latest, {})
    tarball = (version_data.get("dist") or {}).get("tarball")
    integrity = (version_data.get("dist") or {}).get("integrity")
    published_at = (data.get("time") or {}).get(latest)

    npm_info = {
        "Package": package,
        "LatestVersion": latest,
        "PublishedAt": published_at,
        "Tarball": tarball,
        "Integrity": integrity,
        "DistTags": dist_tags,
    }
    return npm_info, None


def fetch_github_release(repo: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    headers = dict(GITHUB_HEADERS)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("CODER_RELEASES_GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        data = http_get_json(url, headers)
    except RuntimeError as exc:
        return None, truncate_error(str(exc))

    github_info = {
        "Repo": repo,
        "TagName": data.get("tag_name"),
        "Name": data.get("name"),
        "PublishedAt": data.get("published_at"),
        "URL": data.get("html_url"),
        "Draft": data.get("draft"),
        "Prerelease": data.get("prerelease"),
    }
    return github_info, None


def http_get_json(url: str, headers: Dict[str, str]) -> Any:
    request = urlrequest.Request(url, headers=headers)
    try:
        with urlrequest.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read()
            if response.headers.get("Content-Encoding", "").lower() == "gzip":
                body = gzip.decompress(body)
            charset = response.headers.get_content_charset("utf-8")
            return json.loads(body.decode(charset))
    except urlerror.HTTPError as exc:
        detail = exc.read()
        try:
            detail_text = detail.decode("utf-8")
        except UnicodeDecodeError:
            detail_text = detail.decode("latin-1", errors="ignore")
        message = detail_text.strip() or exc.reason
        raise RuntimeError(f"{url}: {exc.code} {exc.reason}: {message}") from exc
    except urlerror.URLError as exc:
        raise RuntimeError(f"{url}: {exc.reason}") from exc


def truncate_error(message: str, limit: int = 512) -> str:
    text = message.strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit-3]}..."


def extract_publish_time(result: Dict[str, Any]) -> Optional[datetime]:
    npm = result.get("NPM") or {}
    published = npm.get("PublishedAt")
    if not isinstance(published, str) or not published:
        return None
    try:
        return parse_iso8601(published)
    except ValueError:
        return None


def build_summary(candidates: List[Tuple[datetime, str]]) -> Optional[Dict[str, str]]:
    if not candidates:
        return None
    published_at, package = max(candidates, key=lambda item: item[0])
    return {"MostRecentPublishedAt": format_iso8601(published_at), "Package": package}


def parse_iso8601(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_iso8601(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
