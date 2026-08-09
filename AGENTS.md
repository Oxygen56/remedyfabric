# Repository agent instructions

- Preserve the typed boundary between repair generation, governance, verification, rollback and evidence.
- Run the full unit suite and RemedyBench after behavior changes.
- Never hard-code benchmark outputs, weaken negative controls or report generated fixtures as production evidence.
- Keep the zero-credential offline path working on Python 3.11+.
- Disclose every added model, API, dataset, cloud resource, cost, license and reproduction impact in `docs/DISCLOSURE.md`.
- Never commit credentials, private incidents or customer data.
