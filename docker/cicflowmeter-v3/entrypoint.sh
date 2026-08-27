#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: cicflowmeter-v3 <input.pcap> <output-directory>" >&2
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

mkdir -p /work/input
ln -s "$input" "/work/input/$(basename "$input")"

exec java \
  -Djava.library.path=/opt/CICFlowMeter/lib/native \
  -cp '/opt/CICFlowMeter/lib/*' \
  cic.cs.unb.ca.ifm.CICFlowMeter \
  /work/input/ \
  /output/
