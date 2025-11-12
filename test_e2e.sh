#!/usr/bin/env bash

set -o errexit
set -o pipefail
set -o nounset

##
# NOTE: Maybe put in:
#
#     echo 'curl -vL -H'User-Agent: None' https://www.google.com/' | ./run-coder.sh -I -c bash dnup
#
# with the appropriate profile (and a negative test case?) later.

FLAGS=()
case "${VERBOSE:-}" in
  1|true|True|TRUE|yes|Yes|YES|on|On|ON)
    FLAGS+=("-v")
    ;;
  *)
    ;;
esac

GOFLAGS_VALUE="${GOFLAGS:-}"
if [[ -z "${GOFLAGS_VALUE}" ]]; then
  GOFLAGS_VALUE="-vet=off"
fi
GOFLAGS_VALUE="${GOFLAGS_VALUE} -tags=e2e"

if (( ${#FLAGS[@]} )); then
  LEASH_E2E=1 GOFLAGS="${GOFLAGS_VALUE}" go test -count=1 "${FLAGS[@]}" "$@" ./e2e/...
else
  LEASH_E2E=1 GOFLAGS="${GOFLAGS_VALUE}" go test -count=1 "$@" ./e2e/...
fi
