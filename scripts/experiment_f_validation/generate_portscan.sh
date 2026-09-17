#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
[[ $# -eq 2 ]] || { echo "usage: $0 SESSION_ID GENERATOR_EVIDENCE_ROOT" >&2; exit 2; }
readonly SESSION_ID="$1" EVIDENCE_ROOT="$2"
require_session "$SESSION_ID" '^F-A1-PORTSCAN-V-0[1-3]$'
command -v nmap >/dev/null || { echo 'ABORT: nmap unavailable' >&2; exit 1; }
require_generator_route
readonly SESSION_DIR="$(create_new_session_dir "$EVIDENCE_ROOT" "$SESSION_ID")"
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/generator_started_utc.txt"
set +e
sudo nmap -sS -Pn -n -T3 --max-retries 1 --host-timeout 120s -p 1-1000 -oA "$SESSION_DIR/nmap" 10.10.20.2 > "$SESSION_DIR/nmap.stdout.log" 2> "$SESSION_DIR/nmap.stderr.log"
readonly STATUS=$?
set -e
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/generator_ended_utc.txt"
printf '%s\n' "$STATUS" > "$SESSION_DIR/generator_exit_status.txt"
exit "$STATUS"
