#!/usr/bin/env bash
set -euo pipefail
python3 -m remedyfabric benchmark --output artifacts/benchmark.json
python3 -m remedyfabric report --benchmark artifacts/benchmark.json --output artifacts/dashboard.html

