"""Check whether a password has appeared in known data breaches, using the
Have I Been Pwned (HIBP) Pwned Passwords API.

Privacy note:
Never sends the password or its full hash anywhere. We use "k-anonymity":
"""

import hashlib

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:  # requests is optional
    _HAS_REQUESTS = False

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


def sha1_hash(password: str) -> str:
    """Return the uppercase hex SHA-1 hash of the password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_breach_count(password: str, timeout: float = 5.0) -> int:
    """Return how many times this password appears in known breaches.

    Returns 0 if the password was not found in any breach.
    Raises RuntimeError if `requests` is unavailable or the request fails,
    so the caller can decide whether to warn or continue offline.
    """
    if not _HAS_REQUESTS:
        raise RuntimeError(
            "The 'requests' library is required for breach checking. "
            "Install it with: pip install requests"
        )

    full_hash = sha1_hash(password)
    prefix, suffix = full_hash[:5], full_hash[5:]

    try:
        response = requests.get(HIBP_RANGE_URL + prefix, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Breach check failed: {exc}") from exc

    for line in response.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
            return int(count)
    return 0
