"""Command-line interface for the password strength checker.
"""

import argparse
import getpass
import sys

from .strength import evaluate
from .breach import check_breach_count


def _print_report(password: str, check_breach: bool) -> None:
    result = evaluate(password)

    print()
    print(f"  Length:            {result.password_length} characters")
    print(f"  Raw entropy:       {result.raw_entropy_bits} bits")
    print(f"  Effective entropy: {result.effective_entropy_bits} bits")
    print(f"  Strength:          {result.label}")

    if result.weaknesses:
        print("\n  Weaknesses found:")
        for issue in result.weaknesses:
            print(f"    - {issue}")

    if result.suggestions:
        print("\n  Suggestions:")
        for tip in result.suggestions:
            print(f"    - {tip}")

    if check_breach:
        print("\n  Breach check (Have I Been Pwned):")
        try:
            count = check_breach_count(password)
        except RuntimeError as exc:
            print(f"    Could not check: {exc}")
        else:
            if count > 0:
                print(f"    WARNING: seen {count:,} times in known breaches. Do not use it.")
            else:
                print("    Not found in known breaches.")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the strength of a password."
    )
    parser.add_argument(
        "--breach", action="store_true",
        help="also check the password against Have I Been Pwned (needs internet)",
    )
    parser.add_argument(
        "--password",
        help="password to check (NOT recommended: visible in shell history). "
             "Omit this to be prompted securely.",
    )
    args = parser.parse_args(argv)

    if args.password is not None:
        password = args.password
    else:
        password = getpass.getpass("Enter password to check: ")

    if not password:
        print("No password entered.", file=sys.stderr)
        return 1

    _print_report(password, check_breach=args.breach)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
