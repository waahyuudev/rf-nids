#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

for script in "$SCRIPT_DIR"/*.sh; do
  bash -n "$script"
done

readonly TEST_PARENT="$(mktemp -d /tmp/rf-nids-f-a3-repair.XXXXXX)"
trap 'rm -rf "$TEST_PARENT"' EXIT
readonly TEST_ROOT="$TEST_PARENT/test-root"
readonly EXPECTED="$TEST_ROOT/TEST-ID"
readonly CREATED="$(create_new_session_dir "$TEST_ROOT" TEST-ID)"
[[ "$CREATED" == "$EXPECTED" ]]
[[ -d "$EXPECTED" ]]

if (create_new_session_dir "$TEST_ROOT" TEST-ID) >/dev/null 2>&1; then
  echo 'FAIL: second create unexpectedly succeeded' >&2
  exit 1
fi

for session_id in \
  F-A1-NORMAL-V-01 F-A1-NORMAL-V-01-R1 F-A1-NORMAL-V-02 F-A1-NORMAL-V-03 \
  F-A1-DDOSLIKE-V-01 F-A1-DDOSLIKE-V-02 F-A1-DDOSLIKE-V-03 \
  F-A1-PORTSCAN-V-01 F-A1-PORTSCAN-V-02 F-A1-PORTSCAN-V-03; do
  require_session "$session_id" "$VALIDATION_SESSION_PATTERN"
done
require_session F-A1-NORMAL-V-01-R1 "$NORMAL_SESSION_PATTERN"

for invalid_id in F-A1-NORMAL-V-01-R2 F-A1-NORMAL-V-04 F-A1-DDOSLIKE-V-01-R1 INVALID; do
  if (require_session "$invalid_id" "$VALIDATION_SESSION_PATTERN") >/dev/null 2>&1; then
    printf 'FAIL: invalid session unexpectedly passed: %s\n' "$invalid_id" >&2
    exit 1
  fi
done

readonly HISTORICAL_ROOT="$TEST_PARENT/historical"
mkdir -p "$HISTORICAL_ROOT/F-A1-NORMAL-V-01"
require_session F-A1-NORMAL-V-01 "$NORMAL_SESSION_PATTERN"
if (create_new_session_dir "$HISTORICAL_ROOT" F-A1-NORMAL-V-01) >/dev/null 2>&1; then
  echo 'FAIL: historical V-01 evidence directory was reusable' >&2
  exit 1
fi

if (require_session INVALID "$VALIDATION_SESSION_PATTERN") >/dev/null 2>&1; then
  echo 'FAIL: invalid session unexpectedly passed' >&2
  exit 1
fi

[[ "$TARGET_URL" == 'http://10.10.20.2:8080/' ]]
[[ "$TARGET_IP" == '10.10.20.2' ]]
grep -Fq 'ip link show enp0s3' "$SCRIPT_DIR/capture_session.sh"
grep -Fq -- '--request GET' "$SCRIPT_DIR/generate_normal.sh"
grep -Fq 'for request_number in $(seq 1 30)' "$SCRIPT_DIR/generate_normal.sh"
grep -Fq -- '--max-time 10' "$SCRIPT_DIR/generate_normal.sh"
grep -Fq -- '--users 8 --spawn-rate 2 --run-time 90s' "$SCRIPT_DIR/generate_ddoslike.sh"
grep -Fq -- '-sS -Pn -n -T3 --max-retries 1 --host-timeout 120s -p 1-1000' "$SCRIPT_DIR/generate_portscan.sh"

for generator in generate_normal.sh generate_ddoslike.sh generate_portscan.sh; do
  grep -Fq '[[ $# -eq 2 ]]' "$SCRIPT_DIR/$generator"
done

printf 'PASS: non-traffic operator-script tests\n'
