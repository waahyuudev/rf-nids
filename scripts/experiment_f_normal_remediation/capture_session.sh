#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

[[ $# -eq 2 ]] || { echo "usage: $0 SESSION_ID OBSERVER_EVIDENCE_ROOT" >&2; exit 2; }
readonly SESSION_ID="$1" EVIDENCE_ROOT="$2"
require_session "$SESSION_ID"
command -v tcpdump >/dev/null || { echo 'ABORT: tcpdump unavailable' >&2; exit 1; }
ip link show enp0s3 >/dev/null 2>&1 || { echo 'ABORT: enp0s3 unavailable' >&2; exit 1; }
readonly SESSION_DIR="$(create_new_session_dir "$EVIDENCE_ROOT" "$SESSION_ID")"

printf '%s\n' 'enp0s3' > "$SESSION_DIR/capture_interface.txt"
printf '%s\n' 'host 10.10.20.2 and tcp port 8080' > "$SESSION_DIR/capture_filter.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/capture_started_utc.txt"
printf 'Session %s: capturing on enp0s3. Stop with Ctrl-C immediately after generation ends.\n' "$SESSION_ID"
set +e
sudo tcpdump -i enp0s3 -nn -U -w "$SESSION_DIR/$SESSION_ID.pcap" host 10.10.20.2 and tcp port 8080 2> "$SESSION_DIR/tcpdump.stderr.log"
readonly STATUS=$?
set -e
date -u +%Y-%m-%dT%H:%M:%SZ > "$SESSION_DIR/capture_ended_utc.txt"
printf '%s\n' "$STATUS" > "$SESSION_DIR/tcpdump_exit_status.txt"
sha256sum "$SESSION_DIR/$SESSION_ID.pcap" > "$SESSION_DIR/PCAP_SHA256SUM"
exit "$STATUS"
