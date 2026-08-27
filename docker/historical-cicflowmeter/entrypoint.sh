#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: historical-cicflowmeter <input.pcap> <output-directory>" >&2
  exit 64
fi

input=$1
output=$2

case "$input" in
  /input/*.pcap|/input/*.pcapng) ;;
  *) echo "input must be a PCAP directly under /input" >&2; exit 64 ;;
esac
case "$output" in
  /output|/output/) ;;
  *) echo "output directory must be /output" >&2; exit 64 ;;
esac

[ -f "$input" ] || { echo "input PCAP does not exist: $input" >&2; exit 66; }
[ -d "$output" ] || { echo "output directory does not exist: $output" >&2; exit 73; }
[ -w "$output" ] || { echo "output directory is not writable: $output" >&2; exit 73; }

# The upstream generated script uses a working-directory-relative native path.
# Containers run from /work, so make the same bundled library explicit.
JAVA_OPTS="${JAVA_OPTS:-} -Djava.library.path=/opt/CICFlowMeter/lib/native"
export JAVA_OPTS

exec /opt/CICFlowMeter/bin/cfm "$input" "$output"
