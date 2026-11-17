"""Planted insecure-deserialization helper (regression fixture).

Deserializes an attacker-supplied blob with pickle, which executes arbitrary
code during unpickling.
"""

import pickle
from typing import Any


def load_profile(payload: str) -> dict[str, str]:
    obj: Any = pickle.loads(bytes.fromhex(payload))  # noqa: S301
    return {"profile": str(obj)}
