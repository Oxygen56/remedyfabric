# RemedyFabric evidence dashboard

Judge-facing evidence index for the RemedyFabric GOAI 2026 Agent Infra entry. The page states
the bounded winning claim, champion thresholds, adversarial fault matrix, release separation,
and explicit non-claims. Live numbers are frozen only after the champion gate passes.

The site is a dependency-free static projection of `artifacts/dashboard.html`. The build performs
no network requests and includes no authentication, database, image proxy, tracking, third-party
script, or server runtime. `npm audit` therefore evaluates an empty dependency graph.
