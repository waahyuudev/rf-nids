# E13 operator plan — not yet executed

This is a preregistered example only. It is not authorization to run E13. Before any execution, an operator must pass the separate E13 gate, verify `enp0s3`, target `10.10.20.2:8080`, frozen hashes, and dedicated empty evidence directories.

Illustrative bounded D2 command shape (do **not** execute during preregistration):

```sh
# NOT-YET-EXECUTED: use a lab-approved finite HTTP runner only.
# Four logical source identities; <= 200 requests/source; <= 800 total;
# concurrency 32; timeout 10 seconds; maximum duration 300 seconds.
```

Use the same finite implementation with D1 capped at 100 requests/source, 400 total, and concurrency 8. No infinite loops, flood tools, SYN/UDP/raw-packet traffic, or targets outside the fixed lab scope are permitted.
