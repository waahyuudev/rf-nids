# Phase 10 Runtime Capture Pipeline

The production monitoring controller now owns a daemon background thread per active
session. Start performs prerequisite checks, returns after worker initialization, and
the worker repeatedly executes bounded windows:

`tcpdump → PCAP → pinned CICFlowMeter V3 → audited V3 adapter → active RF → database`

## Capture and artifacts

The macOS host resolves `tcpdump` once during preflight, verifies that the unprivileged
FastAPI process can open BPF on the server-discovered interface, and then invokes that
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

This remains a bounded-window thesis prototype, not inline prevention. FastAPI runs
unprivileged on the macOS host and captures the verified UTM guest-to-guest path on
`vmenet3`; Ubuntu `enp0s2` is the target-side interface, not a dashboard capture choice.
The current Compose API service is not a capture deployment. Successful operation requires
BPF permission, `tcpdump`, Docker, and the prebuilt pinned V3 image on the API host. No attacker automation, model retraining, threshold change,
or scientific evidence mutation is performed.

## One-time macOS BPF permission

Do not run FastAPI as root and do not add `sudo` to the runtime command. From an official
Wireshark macOS disk image, open and install only `Install ChmodBPF.pkg`. This installs the
standard `org.wireshark.ChmodBPF` launch daemon, creates the scoped `access_bpf` group, adds
the installing user to that group, and grants that group access to the dynamically created
`/dev/bpf*` devices. Log out of macOS and back in after installation.

Verify the one-time configuration without capturing traffic:

```bash
id -Gn | tr ' ' '\n' | grep '^access_bpf$'
stat -f '%N %Su:%Sg %Sp' /dev/bpf0
/usr/sbin/tcpdump -i vmenet3 -c 0 -n
```

The first command must print `access_bpf`, the BPF device group must be `access_bpf`, and
the final command must exit without a BPF permission error. Dashboard Start repeats the
same zero-packet open check on the selected server-discovered interface before capture.
