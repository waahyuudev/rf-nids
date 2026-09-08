# Phase 10 Runtime Capture Pipeline

The production monitoring controller now owns a daemon background thread per active
session. Start performs prerequisite checks, returns after worker initialization, and
the worker repeatedly executes bounded windows:

`tcpdump → PCAP → pinned CICFlowMeter V3 → audited V3 adapter → active RF → database`

## Capture and artifacts

The API resolves `tcpdump` once during preflight, verifies capture access using a
bounded, packet-free probe on the server-discovered interface, and then invokes that
same executable directly with an argument array and the filter `host <target>`.
This includes traffic where the configured private target is either source or
destination. Interfaces are selected from host discovery. Commands, output paths,
and model paths are never accepted from the browser. Each session writes generated
files below `data/runtime/monitoring/<session-id>-<uuid>/`, separated into PCAP and flow
window directories. Runtime artifacts are retained for audit and are not deleted
automatically. Operators may archive/delete stopped-session artifacts under their
own retention policy.

The extractor runs the pinned `rf-nids-cicflowmeter-v3:a26aae27` image with no
network, dropped capabilities, a read-only root, and explicit input/output mounts.
The audited `CICFlowMeterV3ModelAdapter` enforces the exact model-metadata order of
78 features. Empty packet windows and empty flow results are logged as no observed
traffic; capture, extractor, CSV, adapter, inference, or database errors instead
make the session `FAILED` and preserve `last_error`.

## Persistence and lifecycle

Each successfully classified flow creates the existing transactional traffic-flow,
prediction, and conditional alert records. Predictions retain the active model ID
and nullable `monitoring_session_id`. A server-generated key containing session,
non-overlapping window, PCAP hash, and row number is protected by the existing
unique provenance constraint. Counters are recalculated from committed predictions
and alerts, never from captured-row estimates.

Stop changes the session to `STOPPING`, signals the active tcpdump process group,
flushes the finalized PCAP through extraction, adaptation, inference, and commit, waits for
all owned processes to be reaped, freezes committed counters, and only then records `STOPPED`.
Capture and extraction failures retain the artifact and record the exact failed stage.
Unexpected failure records `FAILED`. Graceful API shutdown stops owned workers. On
unclean restart, database-active sessions are marked `FAILED`; stored PIDs are never
trusted or used to kill processes after restart.

Runtime endpoints remain ADMIN-protected. The session-specific predictions endpoint
is `GET /api/monitoring/sessions/{id}/predictions`.

The RF-NIDS dashboard controls the defensive monitoring pipeline. Attack traffic is generated externally from the isolated Kali Linux virtual machine.

This remains a bounded-window thesis prototype, not inline prevention. The Ubuntu
runtime deployment keeps FastAPI and PostgreSQL in Docker Compose and Streamlit
on the host. See [Docker runtime monitoring](docker_runtime_monitoring.md) for
networking, capabilities, shared artifact paths, setup, and validation commands.

The probe starts non-promiscuous tcpdump writing to `/dev/null`, waits at most one
second for immediate errors, then interrupts and reaps it. It never uses `-c 0`
and never requires a packet. Linux errors mention capture permissions; macOS
errors mention BPF device access. Historical macOS host development can still use
its configured BPF permissions, but Docker Desktop does not validate the Ubuntu
host-interface capture deployment.
