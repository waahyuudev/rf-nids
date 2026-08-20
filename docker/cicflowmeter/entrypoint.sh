#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: <input.pcap> <output.csv>" >&2
  exit 64
fi

input=$1
output=$2

case "$input" in /input/*) ;; *) echo "input must be below /input" >&2; exit 64 ;; esac
case "$output" in /output/*) ;; *) echo "output must be below /output" >&2; exit 64 ;; esac
[ -f "$input" ] || { echo "input PCAP does not exist: $input" >&2; exit 66; }
mkdir -p "$(dirname "$output")"

exec cicflowmeter -f "$input" -c "$output"
