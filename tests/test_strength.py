"""Tests for the password strength checker.

Run with:  pytest
"""

from password_checker.entropy import estimate_pool_size, shannon_entropy_bits
from password_checker.patterns import (
    is_common_password,
    has_repeated_chars,
    has_sequential_chars,
    has_keyboard_pattern,
)
from password_checker.strength import evaluate


# --- entropy ---------------------------------------------------------------

def test_pool_size_lowercase_only():
    assert estimate_pool_size("abcdef") == 26


def test_pool_size_mixed_classes():
    # lowercase (26) + uppercase (26) + digits (10) + symbol (32) = 94
    assert estimate_pool_size("aB3!") == 94


def test_entropy_empty_is_zero():
    assert shannon_entropy_bits("") == 0.0


def test_longer_password_has_more_entropy():
    assert shannon_entropy_bits("aaaaaaaa") < shannon_entropy_bits("aaaaaaaaaaaa")


# --- patterns --------------------------------------------------------------

def test_common_password_detected():
    assert is_common_password("password")
    assert is_common_password("PASSWORD")  # case-insensitive
    assert not is_common_password("k9#mQ2wL")


def test_repeated_chars():
    assert has_repeated_chars("aaab")
    assert not has_repeated_chars("aab")


def test_sequential_chars():
    assert has_sequential_chars("abcd1234")
    assert has_sequential_chars("4321")     # descending
    assert not has_sequential_chars("acbd")


def test_keyboard_pattern():
    assert has_keyboard_pattern("qwer")
    assert not has_keyboard_pattern("aeiou")


# --- end-to-end evaluation -------------------------------------------------

def test_common_password_scores_very_weak():
    result = evaluate("password")
    assert result.label == "Very Weak"
    assert result.weaknesses


def test_strong_password_scores_well():
    result = evaluate("7kQ!vR2m@Xz9Lp#W")
    assert result.label in ("Strong", "Very Strong")
    assert result.weaknesses == []


def test_sequential_password_penalized():
    weak = evaluate("abcdefghabcdefgh")
    # Pattern penalty should drag effective below raw entropy.
    assert weak.effective_entropy_bits < weak.raw_entropy_bits


def test_result_has_suggestions():
    result = evaluate("abc")
    assert result.suggestions
