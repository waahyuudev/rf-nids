#!/usr/bin/env bash
set -euo pipefail

readonly TARGET_IP="10.10.20.2"
readonly TARGET_URL="http://10.10.20.2:8080/"
readonly EXPECTED_GATEWAY="10.10.10.1"
readonly VALIDATION_SESSION_PATTERN='^F-A1-(NORMAL-V-(0[1-3]|01-R1)|DDOSLIKE-V-0[1-3]|PORTSCAN-V-0[1-3])$'
readonly NORMAL_SESSION_PATTERN='^F-A1-NORMAL-V-(0[1-3]|01-R1)$'

require_generator_route() {
  local route
  route="$(ip route get "$TARGET_IP")"
  [[ "$route" == *"via $EXPECTED_GATEWAY"* ]] || {
    printf 'ABORT: route must use gateway %s: %s\n' "$EXPECTED_GATEWAY" "$route" >&2
    exit 1
  }
}

create_new_session_dir() {
  local root="$1"
  local session_id="$2"
  local destination="$root/$session_id"
  [[ ! -e "$destination" ]] || { printf 'ABORT: evidence exists: %s\n' "$destination" >&2; exit 1; }
  mkdir -p "$root"
  mkdir -m 0750 "$destination"
  printf '%s\n' "$destination"
}

require_session() {
  local supplied="$1" pattern="$2"
  [[ "$supplied" =~ $pattern ]] || { printf 'ABORT: session is not allowlisted: %s\n' "$supplied" >&2; exit 1; }
}
