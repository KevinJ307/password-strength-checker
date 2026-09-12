"""Combine entropy and pattern analysis into a single strength verdict."""

from dataclasses import dataclass, field

from .entropy import shannon_entropy_bits
from .patterns import find_weaknesses, is_common_password

STRENGTH_LEVELS = [
    (0, "Very Weak"),
    (28, "Weak"),
    (36, "Fair"),
    (60, "Strong"),
    (128, "Very Strong"),
]


@dataclass
class StrengthResult:
    password_length: int
    raw_entropy_bits: float
    effective_entropy_bits: float
    label: str
    weaknesses: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def _label_for_bits(bits: float) -> str:
    label = STRENGTH_LEVELS[0][1]
    for threshold, name in STRENGTH_LEVELS:
        if bits >= threshold:
            label = name
    return label


def _build_suggestions(password: str, weaknesses: list[str]) -> list[str]:
    suggestions = []
    if len(password) < 12:
        suggestions.append("Make it longer — aim for at least 12-16 characters.")
    classes_used = sum([
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ])
    if classes_used < 3:
        suggestions.append("Mix in uppercase, digits, and symbols.")
    if weaknesses:
        suggestions.append("Avoid common words, sequences, and keyboard runs.")
    if not suggestions:
        suggestions.append("Consider a passphrase of several random words for even more strength.")
    return suggestions


def evaluate(password: str) -> StrengthResult:
    """Evaluate a password and return a full StrengthResult."""
    raw_bits = shannon_entropy_bits(password)
    weaknesses = find_weaknesses(password)

    # Penalize predictable patterns. Each detected weakness knocks the
    # effective entropy down
    effective_bits = raw_bits
    if is_common_password(password):
        effective_bits = min(effective_bits, 8.0)
    else:
        effective_bits -= 12.0 * len(weaknesses)
    effective_bits = max(effective_bits, 0.0)

    label = _label_for_bits(effective_bits)
    suggestions = _build_suggestions(password, weaknesses)

    return StrengthResult(
        password_length=len(password),
        raw_entropy_bits=round(raw_bits, 1),
        effective_entropy_bits=round(effective_bits, 1),
        label=label,
        weaknesses=weaknesses,
        suggestions=suggestions,
    )
