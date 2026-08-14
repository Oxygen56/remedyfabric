# Contributing

Contributions are welcome under Apache-2.0. Keep changes reproducible and scoped.

1. Add or update tests for behavior changes.
2. Run `python3 -m unittest discover -s tests -v` and the benchmark.
3. Do not commit credentials, customer data, private incidents, generated environments or unverifiable performance claims.
4. New repair providers must preserve the typed `PatchCandidate` boundary; they cannot bypass governance, verification, rollback or receipts.
5. Document model/API cost, license and reproduction impact in `docs/DISCLOSURE.md`.
