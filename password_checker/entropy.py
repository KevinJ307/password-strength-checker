"""Estimate the entropy (in bits) of a password.

Entropy is a measure of how unpredictable a password is. The idea:
if a password is drawn randomly from a pool of N possible characters
and is L characters long, there are N**L possible passwords, and the
entropy in bits is log2(N**L) = L * log2(N).
"""

import math
import string

# Each tuple is (set of characters, size of that character class).
CHAR_CLASSES = [
    (set(string.ascii_lowercase), 26),
    (set(string.ascii_uppercase), 26),
    (set(string.digits), 10),
    (set(string.punctuation), len(string.punctuation)),
    (set(" "), 1), # space
]


def estimate_pool_size(password: str) -> int:
    # Return the size of the character pool the password draws from.
    pool = 0
    remaining = set(password)
    for chars, size in CHAR_CLASSES:
        if remaining & chars:
            pool += size
            remaining -= chars    # remove counted chars so we don't double-count
    # Anything left over is counted individually.
    pool += len(remaining)
    return pool


def shannon_entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    pool = estimate_pool_size(password)
    if pool <= 1:
        return 0.0
    return len(password) * math.log2(pool)
