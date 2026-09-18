#!/usr/bin/env sh
set -eu
echo 'PREPARATION ONLY — no traffic, capture, or Locust invocation is performed.'
echo 'Session: F-A1-DDOSLIKE-A-02 | split: F-ADAPTATION'
echo 'Target: http://10.10.20.2:8080/ | endpoint: / | users: 4 | spawn: 1 user/s | duration: 60 s | timeout: 10 s | wait: 1-2 s'
echo 'Before separate explicit execution: use a unique A-02 workload, PCAP, Locust CSV directory, hashes, and create-new-only evidence paths. Do not reuse A-01 artifacts or capture windows.'
