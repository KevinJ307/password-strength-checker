"""Detect predictable patterns that make a password weaker than its raw
entropy suggests.
"""

import re

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "12345678", "111111", "1234567", "sunshine", "iloveyou", "admin",
    "welcome", "monkey", "letmein", "dragon", "football", "master",
    "qwertyuiop", "123123", "000000", "1234567890", "secret", "login",
}

KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890",
]


def is_common_password(password: str) -> bool:
    """True if the password is a known extremely-common password."""
    return password.lower() in COMMON_PASSWORDS


def has_repeated_chars(password: str, run_length: int = 3) -> bool:
    # True if a single character repeats run_length or more times in a row.
    pattern = r"(.)\1{" + str(run_length - 1) + r",}"
    return re.search(pattern, password) is not None


def has_sequential_chars(password: str, run_length: int = 4) -> bool:
    # True if the password contains an ascending OR descending run of 
    # consecutive characters of length run_length or more.

    if len(password) < run_length:
        return False
    lowered = password.lower()
    asc = desc = 1
    for i in range(1, len(lowered)):
        delta = ord(lowered[i]) - ord(lowered[i - 1])
        if delta == 1:
            asc += 1
            desc = 1
        elif delta == -1:
            desc += 1
            asc = 1
        else:
            asc = desc = 1
        if asc >= run_length or desc >= run_length:
            return True
    return False


def has_keyboard_pattern(password: str, run_length: int = 4) -> bool:
    """True if the password contains a straight keyboard run like 'qwer'."""
    lowered = password.lower()
    for row in KEYBOARD_PATTERNS:
        for seq in (row, row[::-1]):
            for start in range(len(seq) - run_length + 1):
                if seq[start:start + run_length] in lowered:
                    return True
    return False


def find_weaknesses(password: str) -> list[str]:
    """Return a list of human-readable weakness descriptions found."""
    issues = []
    if is_common_password(password):
        issues.append("This is one of the most commonly used passwords.")
    if has_repeated_chars(password):
        issues.append("Contains a character repeated several times in a row.")
    if has_sequential_chars(password):
        issues.append("Contains a sequential run like 'abcd' or '1234'.")
    if has_keyboard_pattern(password):
        issues.append("Contains a straight keyboard pattern like 'qwer'.")
    return issues
