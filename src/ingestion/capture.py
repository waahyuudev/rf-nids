"""Capture-source abstraction backed by a configurable CICFlowMeter executable."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class CaptureError(RuntimeError):
    pass


class CICFlowMeterCapture:
    """Convert PCAP/interface traffic to CSV using external CICFlowMeter.

    This wrapper deliberately does not claim an in-project extractor implementation.
    """

    def __init__(self, executable: str = "cicflowmeter") -> None:
        self.executable = executable

    def _check(self) -> None:
        if shutil.which(self.executable) is None:
            raise CaptureError(
                f"CICFlowMeter executable '{self.executable}' was not found; install a "
                "compatible extractor or pass --flow-csv with pre-extracted output"
            )

    def from_pcap(self, pcap: Path, output: Path | None = None) -> Path:
        self._check()
        if not pcap.is_file():
            raise CaptureError(f"PCAP file does not exist: {pcap}")
        destination = output or Path(tempfile.mkdtemp(prefix="rf-nids-flows-")) / "flows.csv"
        destination.parent.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            [self.executable, "-f", str(pcap), "-c", str(destination)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise CaptureError(f"CICFlowMeter failed ({completed.returncode}): {detail}")
        if not destination.is_file():
            raise CaptureError("CICFlowMeter completed without producing the expected CSV")
        return destination

    def from_interface(self, interface: str, output: Path | None = None) -> Path:
        self._check()
        destination = output or Path(tempfile.mkdtemp(prefix="rf-nids-live-")) / "flows.csv"
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            completed = subprocess.run(
                [self.executable, "-i", interface, "-c", str(destination)], check=False
            )
        except PermissionError as exc:
            raise CaptureError(
                f"Permission denied capturing interface '{interface}'; grant capture "
                "capabilities or run with appropriate lab privileges"
            ) from exc
        if completed.returncode not in (0, -2):
            raise CaptureError(f"Live CICFlowMeter exited with code {completed.returncode}")
        return destination
