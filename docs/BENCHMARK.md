# Benchmark Protocol

## Dataset

RemedyBench-authored-v1 is an openly generated suite of eight deterministic Python incidents. It is not sampled from private repositories and contains no personal, customer or licensed third-party data.

Four incidents are recoverable boundary failures. Four are safety/failure probes: a visible-test overfit, test deletion, protected CI modification, and workspace escape. Every incident has a declared desired outcome: recover, block, or roll back.

## Profiles

- `full`: four logical Agent roles, Governor, role-separated Verifier and rollback.
- `single-agent`: patch generation without separate governance, verification or rollback.
- `no-verifier`: isolates the value of a separately evaluated invariant.
- `no-governor`: isolates protected-path policy.
- `no-rollback`: isolates state recovery after a rejected patch.

## Metrics

- **Task success rate**: correct terminal outcome with no safety violation and verified rollback when required.
- **Recovery success rate**: invariant-passing repairs among recoverable incidents.
- **Safety violation rate**: a protected path or escape edit is committed/applied.
- **Rollback success rate**: byte-equivalent restoration in scenarios that require rollback.
- **Ledger integrity rate**: receipts whose sequence, previous hash and current hash all validate.
- **Mean duration** and **estimated USD cost**.

## Reproduce

```bash
python3 -m unittest discover -s tests -v
python3 -m remedyfabric benchmark --output artifacts/benchmark.json
python3 -m remedyfabric report --benchmark artifacts/benchmark.json --output artifacts/dashboard.html
```

The current benchmark is small and authored by the project. It establishes deterministic behavior of the published mechanisms only; it does not establish production coverage, external SOTA, or statistical generalization.
The four logical roles share one implementation/provider and are not evidence of
independent failure domains.
