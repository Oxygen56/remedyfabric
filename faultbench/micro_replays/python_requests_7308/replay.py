#!/usr/bin/env python3
r"""Standalone semantic replay of Requests PR 7308's `$` to `\Z` regex change."""

from __future__ import annotations

import json
import re


def main() -> None:
    before = re.compile(r"^\S[^\r\n]*$|^$")
    after = re.compile(r"^\S[^\r\n]*\Z|^\Z")
    invalid = "bar\n"
    before_incorrectly_accepts = before.match(invalid) is not None
    after_rejects = after.match(invalid) is None
    valid_still_accepts = after.match("bar") is not None
    assert before_incorrectly_accepts
    assert after_rejects
    assert valid_still_accepts
    print(
        json.dumps(
            {
                "case_id": "requests-7308",
                "language": "Python",
                "before_defect_observed": before_incorrectly_accepts,
                "after_expectation_passed": after_rejects and valid_still_accepts,
                "scope": "standalone semantic micro-replay; not the Requests test suite",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
