#!/usr/bin/env bash
set -euo pipefail

readonly TARGET_IP="10.10.20.2"
readonly TARGET_URL="http://10.10.20.2:8080/"
readonly EXPECTED_GATEWAY="10.10.10.1"
readonly SESSION_PATTERN='^F-A1-NORMAL-A2-0[1-3]$'

require_session() {
  local supplied="$1"
  [[ "$supplied" =~ $SESSION_PATTERN ]] || {
    printf 'ABORT: session is not allowlisted: %s\n' "$supplied" >&2
    exit 1
  }
}

require_generator_route() {
  local route
  route="$(ip route get "$TARGET_IP")"
  [[ "$route" == *"via $EXPECTED_GATEWAY"* ]] || {
    printf 'ABORT: route must use gateway %s: %s\n' "$EXPECTED_GATEWAY" "$route" >&2
    exit 1
  }
}

create_new_session_dir() {
  local root="$1" session_id="$2" destination
  destination="$root/$session_id"
  [[ ! -e "$destination" ]] || {
    printf 'ABORT: evidence exists: %s\n' "$destination" >&2
    exit 1
  }
  mkdir -p "$root"
  mkdir -m 0750 "$destination"
  printf '%s\n' "$destination"
}
