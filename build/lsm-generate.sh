#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRIPT_NAME="$(basename "$0")"

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

main() {
    cd "${REPO_ROOT}"

    local make_bin="${MAKE:-make}"
    local mode="${LSM_GENERATE_MODE:-docker}"

    case "${mode}" in
        native)
            log_info "Running ${make_bin} lsm-generate (native mode)"
            require_cmd "${make_bin}" go
            "${make_bin}" lsm-generate
            ;;
        docker)
            log_info "Running ${make_bin} lsm-generate-docker"
            require_cmd "${make_bin}" docker
            "${make_bin}" lsm-generate-docker
            ;;
        skip)
            log_info "Skipping LSM generation (LSM_GENERATE_MODE=skip)"
            ;;
        *)
            die "unknown LSM_GENERATE_MODE=${mode}; expected 'docker' or 'native'"
            ;;
    esac
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
