"""Planted weak-crypto helper (regression fixture).

Passwords are hashed with MD5 and no salt: a fast, collision-prone digest that
lets an attacker brute-force a leaked password table cheaply.
"""

import hashlib


def hash_password(value: str) -> str:
    return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()
