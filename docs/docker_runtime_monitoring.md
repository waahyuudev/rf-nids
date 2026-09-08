# Dockerized runtime monitoring on Ubuntu NIDS

This is the current runtime deployment guide; it supersedes historical host-run
FastAPI instructions. FastAPI stays inside Compose, PostgreSQL keeps its existing
named volume, and Streamlit stays on the Ubuntu host.

## Deployment contract

Use rootful Docker Engine on Ubuntu, without user-namespace remapping. Docker
Desktop/macOS host networking does not expose macOS capture interfaces like Linux
host networking. An amd64 host is preferred: the unchanged pinned V3 image uses
`linux/amd64`; an ARM Ubuntu VM also requires working amd64 emulation.

The API shares the Linux host network namespace, so `socket.if_nameindex()` can
return `enp0s3`. It listens on host port 8000 with one Uvicorn process (no reload).
PostgreSQL publishes only `127.0.0.1:5432`; API uses that address, while migration
continues using `postgres:5432` on the Compose bridge. `/health` checks a database
query and model initialization. No new migration or volume is introduced.

API UID/GID 10001 is unchanged. The image includes tcpdump, libcap tools, and only
the Docker CLI copied from `docker:28-cli` (no nested Docker daemon). Compose drops
all capabilities except `NET_RAW`. File capability `cap_net_raw=ep` on tcpdump
makes this capability effective for the non-root executable. Capture and preflight
use `-p` (no promiscuous mode); routed packets destined to/from the NIDS interface
are visible without changing interface flags, so `NET_ADMIN` is unnecessary.
Do not add `no-new-privileges` to the API: it would prevent acquiring this file
capability. The offline extractor retains its existing hardening, including
`no-new-privileges`, no networking, and no capabilities.

Only the API mounts `/var/run/docker.sock`, and gets its numeric host group ID as
a supplemental group. **Docker socket access is effectively root-equivalent
control of the host**, despite the API's non-root UID and capture capability
limits. This is required by the existing `docker image inspect` / `docker run`
extractor architecture. Restrict access to the API and host to trusted lab users;
keep ADMIN authentication enabled. The socket is not mounted into migration,
PostgreSQL, Streamlit, or the extractor. Host networking makes API port 8000 a
host listener; apply the lab's host firewall/access policy accordingly.

`RUNTIME_MONITORING_HOST_ROOT` must be the absolute, canonical host directory
mounted at `/app/data/runtime/monitoring`. Both API and extractor run as UID 10001
and must be able to traverse/write their shared directory. The API maps resolved
artifact paths relative to its runtime root onto the host root before passing
both `--mount` sources to the daemon. Host paths are never resolved inside the
container. Escaping paths/symlinks and commas in bind sources are rejected.
Keep this mapping stable after deployment so prior artifact provenance remains
readable. Existing historical host-only artifact paths are not rewritten.

Without a host-root setting, Python development/tests use the same local paths
as before. Compose requires explicit host path and socket GID; it fails early
instead of creating an accidental root-owned bind directory.

Preflight checks executable/interface discovery, briefly starts tcpdump writing
to `/dev/null`, detects immediate failures, then sends SIGINT and reaps it without
waiting for packets. It escalates to SIGTERM/SIGKILL if needed and rejects abnormal
termination. The usual probe takes about one second. Errors retain tcpdump's
actual diagnostic, with Linux/macOS permission guidance. Image identity is still
checked against the unchanged pinned digest. Models, features, classes, prediction
rules, and runtime validation results are unchanged.

## One-time setup, after reviewing the diff

Run from the existing repository on **ubuntu-nids**. Do not rename the Compose
project or change its volume name. Never run `docker compose down -v` or reset DB.
Stop any active monitoring session through Streamlit before rebuilding the API.

```bash
cd /home/wahyudev/rf-nids  # substitute the actual repository location
export RUNTIME_MONITORING_HOST_ROOT="$(pwd -P)/data/runtime/monitoring"
export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
# Creates/sets ownership of this directory only; does not recurse or delete artifacts.
sudo install -d -o 10001 -g 10001 -m 0750 "$RUNTIME_MONITORING_HOST_ROOT"
printf 'RUNTIME_MONITORING_HOST_ROOT=%s\nDOCKER_SOCKET_GID=%s\n' \
  "$RUNTIME_MONITORING_HOST_ROOT" "$DOCKER_SOCKET_GID"
```

Put the two printed assignments into the existing `.env`, preserving other
settings. Future shells then need only the normal Compose build/up commands.
Do not source unrelated `.env` contents into the shell. The runtime root must
remain accessible to UID 10001; do not recursively change historical artifacts.
If old artifacts have incompatible permissions, inspect those separately.

```bash
docker compose config --quiet
docker image inspect rf-nids-cicflowmeter-v3:a26aae27 --format '{{.Id}}'
# Must match the existing pinned identity:
# sha256:0227c7280e586d54144b9bb11b2a6b5d4b1c4ba9bc7c44199fa312a6b829caab
docker compose build
docker compose up -d
docker compose ps -a
docker compose logs --tail=100 migration api
curl --fail --silent --show-error http://127.0.0.1:8000/health
# Expect healthy, database connected, model_loaded true.
docker compose exec postgres psql -U postgres -d rf_nids -c 'SELECT 1;'
docker compose exec api sh -c 'id; getcap "$(command -v tcpdump)"; docker version'
docker compose exec api python -c 'import socket; print(socket.if_nameindex())'
docker compose exec api sh -c 'test -w /app/data/runtime/monitoring && docker image inspect rf-nids-cicflowmeter-v3:a26aae27 --format "{{.Id}}"'
```

If the image is missing or mismatched, restore the already-approved pinned image
from the existing lab image archive; do not rebuild/re-tag a substitute or change
the expected digest. Do not infer runtime readiness from API health alone.

The following calls the real preflight **inside the API container**, without
creating a monitoring session, requiring traffic, or writing runtime artifacts:

```bash
docker compose exec -T api python - <<'PY'
from src.common.config import Settings
from src.api.runtime_monitoring import RuntimePipeline
s = Settings.from_env()
p = RuntimePipeline(root=s.runtime_monitoring_root,
    host_root=s.runtime_monitoring_host_root, image=s.cicflowmeter_v3_image,
    expected_image_digest=s.cicflowmeter_v3_image_digest,
    window_seconds=s.capture_window_seconds)
p.preflight('enp0s3')
print('Capture preflight and pinned image identity verified')
PY
```

## UI acceptance and real traffic

Keep the existing Streamlit host process, pointing to `http://127.0.0.1:8000`.
If it is not already running, start **only Streamlit** with the host's existing
installation (FastAPI is already in Docker):

```bash
FASTAPI_BASE_URL=http://127.0.0.1:8000 .venv/bin/streamlit run dashboard/app.py
```

Log in using an existing ADMIN account. Verify Monitoring lists `enp0s3`, choose
it and target `10.10.20.2`, then click **START MONITORING**. Expect RUNNING with
capture windows progressing. API `/api/monitoring/interfaces` returns the same
server-discovered list; it remains authenticated. `/docs` allows login through
`/api/auth/login` and Bearer authorization for endpoint inspection if needed.

Before generating traffic, select **Normal HTTP** and click **START VALIDATION**.
On **ubuntu-traffic**, verify the route uses NIDS 10.10.10.1, then request the
existing target HTTP service (adjust port only if the lab service uses another):

```bash
ip route get 10.10.20.2
for i in $(seq 1 30); do curl --max-time 2 http://10.10.20.2/; sleep 1; done
```

Allow at least a capture window plus extraction time. Confirm Predictions contain
this session's real rows. Click **COMPLETE FROM SERVER EVIDENCE**. Record the actual
pipeline and detection results, even if FAIL; traffic alone does not guarantee a
particular model label.

For the isolated authorized PortScan scenario, select **PortScan**, click
**START VALIDATION**, then on **ubuntu-traffic**:

```bash
nmap -sT -Pn -p 1-1024 10.10.20.2
```

Wait for committed predictions, complete validation from server evidence, and
inspect predictions/alerts. A PortScan alert is expected only if the unchanged
model and alert rules detect it. Do not change thresholds or fabricate a PASS.
Click **STOP MONITORING**, wait for STOPPED and finalized artifacts, and verify
counters stop changing. Repeat Start/Stop for the Stop / Restart scenario if
needed. Validation must begin before the traffic it is intended to measure.

Read-only evidence inspection on **ubuntu-nids**:

```bash
docker compose logs --tail=200 api
docker compose exec postgres psql -U postgres -d rf_nids -c \
  'SELECT id,status,target_ip,interface_name,flow_count,prediction_count,alert_count,last_error FROM monitoring_sessions ORDER BY id DESC LIMIT 5;'
docker compose exec postgres psql -U postgres -d rf_nids -c \
  'SELECT id,monitoring_session_id,state,pcap_relative_path,csv_relative_path,error_stage,error_message FROM runtime_capture_artifacts ORDER BY id DESC LIMIT 10;'
docker compose exec postgres psql -U postgres -d rf_nids -c \
  'SELECT monitoring_session_id,predicted_label,count(*) FROM predictions WHERE monitoring_session_id=(SELECT max(id) FROM monitoring_sessions) GROUP BY monitoring_session_id,predicted_label;'
docker compose exec postgres psql -U postgres -d rf_nids -c \
  'SELECT a.id,a.severity,a.status,p.predicted_label,p.monitoring_session_id FROM alerts a JOIN predictions p ON p.id=a.prediction_id WHERE p.monitoring_session_id=(SELECT max(id) FROM monitoring_sessions);'
docker compose exec postgres psql -U postgres -d rf_nids -c \
  'SELECT id,monitoring_session_id,status,pipeline_result,detection_result,evidence_json FROM runtime_validation_runs ORDER BY id DESC LIMIT 3;'
# Inspect the latest captured artifact without starting another capture:
docker compose exec -T api python - <<'PY'
import subprocess
from pathlib import Path
from src.common.config import Settings
files = list(Settings.from_env().runtime_monitoring_root.rglob('*.pcap'))
assert files, 'No runtime PCAP yet'
p = max(files, key=lambda path: path.stat().st_mtime_ns)
print(p, flush=True)
subprocess.run(['tcpdump', '-nn', '-r', str(p), '-c', '10', 'host', '10.10.20.2'], check=True)
PY
```

Check matching source/destination addresses in PCAP, committed CSV provenance,
session-linked predictions, conditional alerts, and server-derived validation
results together. An idle final PCAP may have no packets; inspect an earlier
window from the same session if needed. Stop does not delete runtime artifacts.

**Requires Ubuntu NIDS runtime validation.** macOS automated tests mock capture
and Docker subprocesses. They cannot establish real interface visibility,
capability enforcement, socket permissions, image execution/emulation, routed
packet capture, or live model detection on the Ubuntu lab.
