# A-02/A-03 fast-track operator preparation

This directory contains **preparation-only** scripts. They never generate traffic, start capture, or invoke Locust. A human operator must separately provide the approved generator-side workload and explicitly execute an authorized run after confirming the target, capture, artifact paths, and create-new status.

Frozen parameters for both sessions: target `http://10.10.20.2:8080/`, endpoint `/`, maximum users `4`, spawn rate `1 user/s`, duration `60 seconds`, timeout `10 seconds`, wait time `1–2 seconds`, and split `F-ADAPTATION`.

Run the matching preparation script on the operator system before any separately authorized traffic action. It only prints the required immutable parameters and evidence separation requirements.
