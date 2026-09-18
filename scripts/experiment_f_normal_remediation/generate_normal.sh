#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

[[ $# -eq 2 ]] || { echo "usage: $0 SESSION_ID GENERATOR_EVIDENCE_ROOT" >&2; exit 2; }
readonly SESSION_ID="$1" EVIDENCE_ROOT="$2"
require_session "$SESSION_ID"
command -v curl >/dev/null || { echo 'ABORT: curl unavailable' >&2; exit 1; }
command -v timeout >/dev/null || { echo 'ABORT: GNU timeout unavailable' >&2; exit 1; }
require_generator_route
readonly SESSION_DIR="$(create_new_session_dir "$EVIDENCE_ROOT" "$SESSION_ID")"

printf '%s\n' 'F-A1-NORMAL-A2-PROFILE-01' > "$SESSION_DIR/profile_id.txt"
printf '%s\n' "$TARGET_URL" > "$SESSION_DIR/target_url.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/generator_started_utc.txt"
export TARGET_URL SESSION_DIR
set +e
timeout --signal=TERM 180s bash -c '
  for request_number in $(seq 1 100); do
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    curl --http1.1 --max-time 10 --request GET \
      --user-agent "RF-NIDS-Experiment-F-Normal-Remediation/1.0" \
      --silent --show-error --output /dev/null \
      --write-out "%{http_code},%{time_total}" "$TARGET_URL" \
      > "$SESSION_DIR/request_${request_number}.result" \
      2> "$SESSION_DIR/request_${request_number}.stderr"
    status=$?
    printf "%s,%s,%s\n" "$request_number" "$started" "$status" >> "$SESSION_DIR/requests.csv"
    [[ $status -eq 0 ]] || exit "$status"
    [[ $request_number -eq 100 ]] || sleep 1
  done
'
readonly STATUS=$?
set -e
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/generator_ended_utc.txt"
printf '%s\n' "$STATUS" > "$SESSION_DIR/generator_exit_status.txt"
exit "$STATUS"
