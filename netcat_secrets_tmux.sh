#!/usr/bin/env bash
# Automates secrets placeholder end-to-end verification using tmux.

set -euo pipefail

SESSION_APP="secrets_proxy_app"
SESSION_NETCAT="secrets_proxy_netcat"
SECRET_ID="${SECRET_ID:-something}"
SECRET_VALUE="${SECRET_VALUE:-12345678901234567890}"
PROXY_PORT="${PROXY_PORT:-6666}"
HOST_IP="${HOST_IP:-}"
API_BASE_OVERRIDE="${API_BASE:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"
MAKE_TIMEOUT="${MAKE_TIMEOUT:-60}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

detect_host_ip() {
  if [[ -n "${HOST_IP}" ]]; then
    echo "${HOST_IP}"
    return 0
  fi
  if command -v ipconfig >/dev/null 2>&1; then
    for iface in en0 en1 en2; do
      if ip=$(ipconfig getifaddr "$iface" 2>/dev/null); then
        if [[ -n "${ip}" ]]; then
          echo "${ip}"
          return 0
        fi
      fi
    done
  fi
  if command -v ip >/dev/null 2>&1; then
    ip -4 addr show scope global | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1
    return 0
  fi
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig | awk '/inet / && $2 != "127.0.0.1" {print $2; exit}'
    return 0
  fi
  return 1
}

require_cmd git
require_cmd tmux
if command -v nc >/dev/null 2>&1; then
  NETCAT_BIN="nc"
elif command -v netcat >/dev/null 2>&1; then
  NETCAT_BIN="netcat"
else
  echo "netcat (nc) is required" >&2
  exit 1
fi
require_cmd timeout
require_cmd curl

REPO_ROOT="$(git rev-parse --show-toplevel)"
if [[ -z "${REPO_ROOT}" ]]; then
  echo "failed to detect repository root" >&2
  exit 1
fi

HOST_ADDR="$(detect_host_ip || true)"
if [[ -z "${HOST_ADDR}" ]]; then
  echo "unable to determine host IP; set HOST_IP env var" >&2
  exit 1
fi

echo "Using host IP: ${HOST_ADDR}"

cleanup() {
  tmux kill-session -t "${SESSION_APP}" >/dev/null 2>&1 || true
  tmux kill-session -t "${SESSION_NETCAT}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if tmux has-session -t "${SESSION_APP}" >/dev/null 2>&1; then
  tmux kill-session -t "${SESSION_APP}"
fi
if [[ "${SKIP_NETCAT:-0}" != "1" ]]; then
  if tmux has-session -t "${SESSION_NETCAT}" >/dev/null 2>&1; then
    tmux kill-session -t "${SESSION_NETCAT}"
  fi
  if "${NETCAT_BIN}" -h 2>&1 | grep -q -- '-k'; then
    LISTEN_CMD="${NETCAT_BIN} -v -k -l 0.0.0.0 ${PROXY_PORT}"
  else
    LISTEN_CMD="while true; do timeout 60 ${NETCAT_BIN} -v -l 0.0.0.0 ${PROXY_PORT}; done"
  fi
  tmux new-session -d -s "${SESSION_NETCAT}" "cd ${REPO_ROOT}; ${LISTEN_CMD}"
else
  echo "NOTE: skipping netcat tmux session (SKIP_NETCAT=1)"
fi

if [[ "${SKIP_BUILD}" == "1" ]]; then
  build_cmd="./bin/leash -o bash"
else
  build_cmd="timeout ${MAKE_TIMEOUT} make -j10 default && ./bin/leash -o bash"
fi

#tmux new-session -d -s "${SESSION_APP}" "cd ${REPO_ROOT}; ${build_cmd}"
tmux new-session -d -s "${SESSION_APP}" "cd ${REPO_ROOT}; ./bin/leash -o bash"

wait_for_prompt() {
  local attempt=0
  while (( attempt < 120 )); do
    if tmux capture-pane -pt "${SESSION_APP}" | grep -q "\\[leash\\].*>"; then
      return 0
    fi
    sleep 1
    ((attempt++))
  done
  return 1
}

if ! wait_for_prompt; then
  echo "leash shell did not become ready within timeout" >&2
  exit 1
fi

control_port="$(tmux capture-pane -pt "${SESSION_APP}" | sed -n 's/.*Leash UI (Control UI): http:\/\/[^:]*:\([0-9][0-9]*\)\/.*/\1/p' | tail -n1)"
if [[ -n "${API_BASE_OVERRIDE}" ]]; then
  API_BASE="${API_BASE_OVERRIDE}"
elif [[ -n "${control_port}" ]]; then
  API_BASE="http://127.0.0.1:${control_port}"
else
  API_BASE="http://127.0.0.1:18080"
fi

echo "Using API base: ${API_BASE}"

send_app() {
  tmux send-keys -t "${SESSION_APP}" "$1" C-m
}

send_app "export HOST_IP=${HOST_ADDR} PROXY_PORT=${PROXY_PORT} SECRET_ID=${SECRET_ID} SECRET_VALUE='${SECRET_VALUE}' API_BASE='${API_BASE}'"
send_app "API_BASE=\"\${LEASH_API_BASE:-\${API_BASE}}\""
send_app "timeout 60 bash -c 'until curl -sf \"${API_BASE}/api/secrets\" >/dev/null; do sleep 1; done'"
send_app "payload=\$(printf '{\"id\":\"%s\",\"value\":\"%s\"}' \"\${SECRET_ID}\" \"\${SECRET_VALUE}\")"
send_app "placeholder=\$(timeout 60 curl -sS -X POST -H 'Content-Type: application/json' -d \"\${payload}\" \"${API_BASE}/api/secrets/\${SECRET_ID}\" | sed -n 's/.*\"placeholder\":\"\\([^\\\"]*\\)\".*/\\1/p')"
send_app "printf '__PLACEHOLDER__:%s\n' \"\${placeholder}\""

placeholder=""
for _ in $(seq 1 60); do
  placeholder_line="$(tmux capture-pane -pt "${SESSION_APP}" | awk '/^__PLACEHOLDER__:/ {line=$0} END {print line}')"
  if [[ -n "${placeholder_line}" ]]; then
    placeholder="${placeholder_line#__PLACEHOLDER__:}"
    placeholder="$(echo "${placeholder}" | tr -d '[:space:]')"
    if [[ -n "${placeholder}" ]]; then
      break
    fi
  fi
  sleep 1
done

if [[ -z "${placeholder}" ]]; then
  echo "failed to capture placeholder from leash session" >&2
  tmux capture-pane -pt "${SESSION_APP}"
  exit 1
fi

echo "Placeholder: ${placeholder}"

send_app "timeout 60 curl -sv http://\${HOST_IP}:${PROXY_PORT}/${placeholder} -H \"Authorization: ${placeholder}\""

sleep 5

app_log="$(tmux capture-pane -pt "${SESSION_APP}")"
netcat_log=""
if [[ "${SKIP_NETCAT:-0}" != "1" ]]; then
  netcat_log="$(tmux capture-pane -pt "${SESSION_NETCAT}")"
fi

echo "----- leash session output -----"
echo "${app_log}"
echo "--------------------------------"
echo "----- netcat session output -----"
if [[ "${SKIP_NETCAT:-0}" != "1" ]]; then
  echo "${netcat_log}"
  echo "--------------------------------"
  if echo "${netcat_log}" | grep -q "${SECRET_VALUE}"; then
    echo "SUCCESS: secret value observed in netcat output."
  else
    echo "WARNING: secret value not observed in netcat output."
  fi
else
  echo "(skipped; external listener expected to record payload)"
  echo "--------------------------------"
  echo "NOTE: netcat verification skipped."
fi
