# Password Strength Checker

A command-line tool that evaluates password strength using **entropy estimation**,
**pattern detection**, and an optional **breach check** against the
[Have I Been Pwned](https://haveibeenpwned.com/) database.

Unlike simple checkers that just count "does it have a number and a symbol?",
this tool estimates how *unpredictable* a password actually is and penalizes
common weak patterns like sequences (`abcd`), repeats (`aaaa`), and keyboard
runs (`qwer`).

## Features

- **Entropy scoring** — estimates password entropy in bits from character
  pool size and length.
- **Pattern detection** — flags common passwords, repeated characters,
  sequential runs, and keyboard patterns, then reduces the effective score.
- **Breach checking** (optional) — checks whether a password appears in known
  data breaches using the HIBP API and **k-anonymity**, so the password is
  never sent over the network.
- **Secure input** — prompts with `getpass` so the password isn't echoed to
  the screen or saved in shell history.
- **Tested** — includes a `pytest` suite covering the core logic.

## Installation

```bash
git clone https://github.com/<your-username>/password-strength-checker.git
cd password-strength-checker
pip install -r requirements.txt   # only needed for the --breach feature
```

The core checker uses only the Python standard library, so it runs with no
dependencies unless you use `--breach`.

## Usage

Prompt securely (recommended):

```bash
python -m password_checker
```

Also check against known breaches:

```bash
python -m password_checker --breach
```

Pass a password directly (convenient for testing, but visible in shell
history — avoid for real passwords):

```bash
python -m password_checker --password "example123"
```

### Example output

```
  Length:            8 characters
  Raw entropy:       37.6 bits
  Effective entropy: 8.0 bits
  Strength:          Very Weak

  Weaknesses found:
    - This is one of the most commonly used passwords.

  Suggestions:
    - Make it longer — aim for at least 12-16 characters.
    - Mix in uppercase, digits, and symbols.
    - Avoid common words, sequences, and keyboard runs.
```

## How it works

### Entropy

Entropy measures unpredictability. If a password of length `L` is drawn
randomly from a pool of `N` possible characters, there are `N**L` possibilities,
and the entropy is `L * log2(N)` bits. More bits means harder to brute-force.

This is only an estimate — it assumes randomness. Human passwords rarely are,
which is why pattern detection matters.

### k-anonymity breach check

To check a breach database without leaking your password:

1. SHA-1 hash the password locally.
2. Send only the **first 5 characters** of that hash to the API.
3. The API returns every known hash suffix sharing that prefix.
4. Search that list locally for your full hash.

The server never learns which password you checked.

## Running the tests

```bash
pip install pytest
pytest
```

## Possible extensions

Ideas for taking this further (good for interviews to talk about):

- Load a large real-world wordlist (e.g. `rockyou.txt` from
  [SecLists](https://github.com/danielmiessler/SecLists)) for common-password
  detection instead of the small built-in set.
- Add [zxcvbn](https://github.com/dropbox/zxcvbn)-style pattern matching
  (dates, leetspeak substitutions, l33t decoding).
- Estimate real-world crack time under different attacker speeds.
- Build a small web UI or REST API wrapper.
