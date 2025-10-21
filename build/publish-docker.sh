#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_NAME="$(basename "$0")"
VERSION_SCRIPT="${REPO_ROOT}/build/versionator.py"

log() {
    local level="$1"
    shift
    local caller="${FUNCNAME[1]:-main}"
    local line="${BASH_LINENO[0]:-0}"
    printf '%s\n' "${level}: ${SCRIPT_NAME}:${caller}:${line}: $*" 1>&2
}

log_info() { log "INFO" "$@"; }
log_error() { log "ERROR" "$@"; }
die() { log_error "$@"; exit 1; }

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
        tag="dev-$(git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)"
    fi
    printf '%s' "$tag"
}

docker_build_push() {
    local image="$1"
    local version="$2"
    shift 2
    local args=("$@")

    log_info "Building ${image}:${version} (multi-arch)"
    DOCKER_BUILDKIT=1 docker buildx build \
        --platform linux/amd64,linux/arm64 \
        -t "${image}:${version}" \
        -t "${image}:latest" \
        "${args[@]}" \
        --push \
        .
}

promote_image() {
    local source_ref="$1"
    local image="$2"
    local version="$3"

    log_info "Promoting ${source_ref} -> ${image}:${version} (multi-arch)"
    docker buildx imagetools create \
        --tag "${image}:${version}" \
        --tag "${image}:latest" \
        "${source_ref}"
}

main() {
    cd "${REPO_ROOT}"

    require_cmd docker git python3

    local version="${1:-${VERSION:-}}"
    if [ -z "${version}" ]; then
        if ! version="$("${VERSION_SCRIPT}" tag)"; then
            die "failed to resolve version via ${VERSION_SCRIPT}"
        fi
    fi
    if [ -z "${version}" ]; then
        die "version argument or VERSION env var is required"
    fi

    local original_version="${version}"
    version="$(sanitize_tag "${version}")"

    local leash_image="${LEASH_IMAGE:-ghcr.io/strongdm/leash}"
    local target_image="${TARGET_IMAGE:-ghcr.io/strongdm/coder}"

    local commit
    commit="$(git rev-parse --short=7 HEAD)"
    local build_date
    build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local channel="${RELEASE_CHANNEL:-release}"
    local git_url
    git_url="$(git config --get remote.origin.url 2>/dev/null || echo unknown)"

    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf 'sanitized_version=%s\n' "${version}" >> "${GITHUB_OUTPUT}"
    fi

    local leash_source="${LEASH_SOURCE_IMAGE:-}"
    if [ -n "${leash_source}" ]; then
        if ! promote_image "${leash_source}" "${leash_image}" "${version}"; then
            log_error "promotion failed; rebuilding ${leash_image}:${version}"
            leash_source=""
        fi
    fi
    if [ -z "${leash_source}" ]; then
        docker_build_push "${leash_image}" "${version}" \
            --file Dockerfile.leash \
            --target final-prebuilt \
            --build-arg UI_SOURCE=ui-prebuilt \
            --build-arg COMMIT="${commit}" \
            --build-arg BUILD_DATE="${build_date}" \
            --build-arg VERSION="${version#v}" \
            --build-arg CHANNEL="${channel}" \
            --build-arg GIT_REMOTE_URL="${git_url}"
    fi

    local target_source="${TARGET_SOURCE_IMAGE:-}"
    if [ -n "${target_source}" ]; then
        if ! promote_image "${target_source}" "${target_image}" "${version}"; then
            log_error "promotion failed; rebuilding ${target_image}:${version}"
            target_source=""
        fi
    fi
    if [ -z "${target_source}" ]; then
        docker_build_push "${target_image}" "${version}" \
            --file Dockerfile.coder \
            --build-arg COMMIT="${commit}" \
            --build-arg BUILD_DATE="${build_date}" \
            --build-arg VERSION="${version#v}" \
            --build-arg CHANNEL="${channel}" \
            --build-arg GIT_REMOTE_URL="${git_url}"
    fi

    log_info "Docker tags created for original input '${original_version}' as '${version}'"
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
