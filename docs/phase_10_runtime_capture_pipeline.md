# Phase 10 Runtime Capture Pipeline

The production monitoring controller now owns a daemon background thread per active
session. Start performs prerequisite checks, returns after worker initialization, and
the worker repeatedly executes bounded windows:

`tcpdump → PCAP → pinned CICFlowMeter V3 → audited V3 adapter → active RF → database`

## Capture and artifacts

`tcpdump` is invoked directly with an argument array and the filter `host <target>`.
This includes traffic where the configured private target is either source or
destination. Interfaces are selected from host discovery. Commands, output paths,
and model paths are never accepted from the browser. Each session writes generated
files below `data/runtime/monitoring/<session-id>/`, separated into PCAP and flow
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
waits for the daemon worker, freezes committed counters, and then records `STOPPED`.
Unexpected failure records `FAILED`. Graceful API shutdown stops owned workers. On
unclean restart, database-active sessions are marked `FAILED`; stored PIDs are never
trusted or used to kill processes after restart.

Runtime endpoints remain ADMIN-protected. The session-specific predictions endpoint
is `GET /api/monitoring/sessions/{id}/predictions`.

The RF-NIDS dashboard controls the defensive monitoring pipeline. Attack traffic is generated externally from the isolated Kali Linux virtual machine.

This remains a bounded-window thesis prototype, not inline prevention. Successful
operation requires capture permission, `tcpdump`, Docker, and the prebuilt pinned V3
image on the API host. No attacker automation, model retraining, threshold change,
or scientific evidence mutation is performed.
