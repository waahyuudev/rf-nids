#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for script in common.sh capture_session.sh generate_normal.sh; do
  bash -n "$SCRIPT_DIR/$script"
done

source "$SCRIPT_DIR/common.sh"
for session in F-A1-NORMAL-A2-01 F-A1-NORMAL-A2-02 F-A1-NORMAL-A2-03; do
  require_session "$session"
done
if (require_session F-A1-NORMAL-A2-04) 2>/dev/null; then
  echo 'FAIL: unregistered session accepted' >&2
  exit 1
fi
if (require_session F-A1-NORMAL-V-01-R1) 2>/dev/null; then
  echo 'FAIL: validation session accepted' >&2
  exit 1
fi

temporary_root="$(mktemp -d)"
trap 'rmdir "$temporary_root/F-A1-NORMAL-A2-01" "$temporary_root" 2>/dev/null || true' EXIT
created="$(create_new_session_dir "$temporary_root" F-A1-NORMAL-A2-01)"
[[ "$created" == "$temporary_root/F-A1-NORMAL-A2-01" ]]
if (create_new_session_dir "$temporary_root" F-A1-NORMAL-A2-01) 2>/dev/null; then
  echo 'FAIL: overwrite guard did not refuse existing evidence' >&2
  exit 1
fi
printf '%s\n' 'PASS: syntax, allowlist, validation exclusion, and create-new guard'
