"""Scale Hypothesis ``max_examples`` when ``SUBSTRATE_FUZZ_MULTIPLIER`` is set (e.g. CI heavy job)."""

from __future__ import annotations

import os

# Hard cap so accidental env typos cannot explode CI minutes.
_MAX_CAP = 600


def fuzz_max_examples(base: int) -> int:
    """Return ``base * multiplier``, capped (multiplier from env, default 1)."""
    try:
        m = int(os.environ.get("SUBSTRATE_FUZZ_MULTIPLIER", "1"))
    except ValueError:
        m = 1
    m = max(1, min(m, 10))
    return min(_MAX_CAP, max(1, base * m))
