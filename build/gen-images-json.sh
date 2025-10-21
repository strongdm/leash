#!/usr/bin/env bash

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION_SCRIPT="${REPO_ROOT}/build/versionator.py"

log() {
    local level="$1"
    shift
    local caller="${FUNCNAME[1]:-main}"
    local line="${BASH_LINENO[0]:-0}"
    printf '%s\n' "${level}: ${SCRIPT_NAME}:${caller}:${line}: $*" 1>&2
}

log_info() {
    log "INFO" "$@"
}

log_error() {
    log "ERROR" "$@"
}

die() {
    log_error "$@"
    exit 1
}

require_cmd() {
    local missing=0
    local cmd
    for cmd in "$@"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_error "required command not found: ${cmd}"
            missing=1
        fi
    done
    if ((missing)); then
        exit 1
    fi
}

sanitize_tag() {
    local tag="$1"
    tag=$(printf '%s' "$tag" | tr '[:upper:]' '[:lower:]')
    tag=$(printf '%s' "$tag" | tr -c 'a-z0-9._-' '-')
    tag=$(printf '%s' "$tag" | sed 's/--*/-/g')
    while [[ "$tag" == -* ]]; do tag="${tag#-}"; done
    while [[ "$tag" == *- ]]; do tag="${tag%-}"; done
    if [ -z "$tag" ]; then
        die "sanitized tag is empty"
    fi
    printf '%s' "$tag"
}

extract_digest_from_json() {
    local json="$1"
    if [ -z "${json}" ]; then
        return 0
    fi

    MANIFEST_JSON="${json}" python3 - <<'PY'
import json
import os
import sys

raw = os.environ.get("MANIFEST_JSON", "")
if not raw.strip():
    raise SystemExit(0)

try:
    data = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(0)

digest = ""
if isinstance(data, dict):
    digest = data.get("digest") or ""
    if not digest:
        config = data.get("config", {})
        if isinstance(config, dict):
            digest = config.get("digest") or ""

if digest:
    print(digest, end="")
PY
}

inspect_manifest_digest() {
    local ref="$1"
    local retries="${MANIFEST_RETRIES:-120}"
    local delay="${MANIFEST_RETRY_DELAY:-5}"
    local attempt=1
    while (( attempt <= retries )); do
        local digest=""
        local buildx_json=""
        buildx_json="$(docker buildx imagetools inspect "${ref}" --format '{{json .Manifest}}' 2>/dev/null || true)"
        digest="$(extract_digest_from_json "${buildx_json}")"
        if [ -z "${digest}" ]; then
            local manifest_json=""
            manifest_json="$(docker manifest inspect "${ref}" 2>/dev/null || true)"
            digest="$(extract_digest_from_json "${manifest_json}")"
        fi
        if [ -n "${digest}" ]; then
            printf '%s' "${digest}"
            return 0
        fi
        if (( attempt < retries )); then
            log_info "manifest for ${ref} not yet available (attempt ${attempt}/${retries}); retrying in ${delay}s..."
            sleep "${delay}"
        fi
        (( attempt++ ))
    done
    return 1
}

main() {
    require_cmd docker python3

    local version="${1:-${VERSION:-}}"
    if [ -z "${version}" ]; then
        if ! version="$("${VERSION_SCRIPT}" tag)"; then
            die "failed to resolve version via ${VERSION_SCRIPT}"
        fi
    fi
    if [ -z "${version}" ]; then
        die "version argument or VERSION env var is required"
    fi

    version="$(sanitize_tag "${version}")"

    local dist_dir="${DIST_DIR:-dist}"
    mkdir -p "${dist_dir}"

    local leash_repo="ghcr.io/strongdm/leash"
    local coder_repo="ghcr.io/strongdm/coder"

    local leash_tags=(
        "${leash_repo}:${version}"
        "${leash_repo}:latest"
    )
    local coder_tags=(
        "${coder_repo}:${version}"
        "${coder_repo}:latest"
    )

    local leash_digest
    if ! leash_digest="$(inspect_manifest_digest "${leash_repo}:${version}")"; then
        local leash_source="${LEASH_SOURCE_IMAGE:-}"
        if [ -n "${leash_source}" ]; then
            log_info "primary manifest missing; falling back to source ${leash_source}"
            if ! leash_digest="$(inspect_manifest_digest "${leash_source}")"; then
                die "failed to resolve manifest digest for ${leash_repo}:${version} (fallback ${leash_source} also unavailable)"
            fi
        else
            die "failed to resolve manifest digest for ${leash_repo}:${version}"
        fi
    fi

    local coder_digest
    if ! coder_digest="$(inspect_manifest_digest "${coder_repo}:${version}")"; then
        local coder_source="${CODER_SOURCE_IMAGE:-}"
        if [ -n "${coder_source}" ]; then
            log_info "primary manifest missing; falling back to source ${coder_source}"
            if ! coder_digest="$(inspect_manifest_digest "${coder_source}")"; then
                die "failed to resolve manifest digest for ${coder_repo}:${version} (fallback ${coder_source} also unavailable)"
            fi
        else
            die "failed to resolve manifest digest for ${coder_repo}:${version}"
        fi
    fi

    local leash_tags_joined
    leash_tags_joined="$(printf '%s\n' "${leash_tags[@]}" | paste -sd' ' -)"
    local coder_tags_joined
    coder_tags_joined="$(printf '%s\n' "${coder_tags[@]}" | paste -sd' ' -)"

    LEASH_REPO="${leash_repo}" CODER_REPO="${coder_repo}" \
    LEASH_DIGEST="${leash_digest}" CODER_DIGEST="${coder_digest}" \
    LEASH_TAGS="${leash_tags_joined}" CODER_TAGS="${coder_tags_joined}" \
    VERSION="${version}" DIST_DIR="${dist_dir}" \
    python3 - <<'PY'
import json
import os

def payload(name):
    return {
        "version": os.environ["VERSION"],
        "repo": os.environ[f"{name}_REPO"],
        "digest": os.environ[f"{name}_DIGEST"],
        "tags": os.environ[f"{name}_TAGS"].split(),
    }

data = {
    "leash": payload("LEASH"),
    "coder": payload("CODER"),
}

dist_dir = os.environ["DIST_DIR"]
os.makedirs(dist_dir, exist_ok=True)
output_path = os.path.join(dist_dir, "images.json")
with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
PY

    log_info "Wrote ${dist_dir}/images.json for ${version}"
}
export -f main

if [ "${BASH_SOURCE[0]}" = "${0}" ] || [ "${BASH_SOURCE[0]}" = '--' ]; then
    set -o errexit
    set -o pipefail
    set -o nounset

    if [ "${1:-}" = '-v' ]; then
        printf '%s\n' "INFO: $(basename "$0")::${LINENO}: Verbose output enabled" 1>&2
        shift
        set -o xtrace
    fi

    main "$@"
fi
