"""A password strength checker with entropy scoring, pattern detection,
and optional breach checking via Have I Been Pwned."""

from .strength import evaluate, StrengthResult

__all__ = ["evaluate", "StrengthResult"]
__version__ = "1.0.0"
