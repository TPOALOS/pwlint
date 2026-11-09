#!/usr/bin/env python3
"""pwlint - judge a password honestly, and generate strong ones. Offline.

`pwlint check` estimates how many guesses an attacker would need, spotting what really makes passwords weak:
common passwords, a word plus a number, keyboard walks (qwerty), sequences (abcd, 1234), repeats, years. It
never prints the password and never sends it anywhere; it reads it from a hidden prompt or from stdin, not from
the command line (where it would stay in your shell history).
`pwlint gen` makes random passwords or PINs with Python's cryptographic random generator.
Standard library only. Exit codes: check = 0 strong enough, 1 weaker than --min-bits; 2 = usage error.
"""
import argparse
import getpass
import json
import math
import re
import secrets
import string
import sys

__version__ = "1.0.0"

# A few hundred of the most common passwords (lower case). Real attackers use millions; this list is enough to catch
# the lazy ones and to explain WHY a password is weak.
COMMON = """123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 football
monkey letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 superman 1qaz2wsx 7777777
121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh hunter buster soccer harley batman andrew tigger
sunshine iloveyou 2000 charlie robert thomas hockey ranger daniel starwars klaster 112233 george computer michelle jessica
pepper 1111 zxcvbn 555555 11111111 131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua cheese amanda
summer love ashley nicole chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor matrix mobilemail
mom monitor monitoring montana moon moscow welcome admin login passw0rd p@ssw0rd password1 password123 admin123 root toor
test guest changeme default secret qwerty123 qwerty1 letmein1 welcome1 iloveu abcd1234 1q2w3e4r 1q2w3e q1w2e3r4 zaq12wsx
internet service canada hello hello123 whatever liverpool arsenal chelsea1 manchester barcelona fenerbahce galatasaray
besiktas trabzonspor istanbul ankara turkiye sifre parola merhaba 123456a a123456 asd123 qweasd qweasdzxc pokemon naruto
minecraft google facebook samsung apple1 iphone ford pass1234 master123 shadow1 sunshine1 princess1 football1 baseball1
dragon1 monkey1 lovely flower flower1 cookie cookie1 secret1 super123 batman1 spiderman superman1 hannah jessica1 nothing
password! password. 1234qwer qwer1234 zxcv1234 asdf1234 asdfghjkl 0987654321 987654 12341234 11223344 123654 147258 147258369
951753 741852 963852 1234321 1357924680 abcdef abcdefg abc12345 qwert qwertz azerty""".split()
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i", "|": "l", "+": "t"})
KEYBOARD_ROWS = ("1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "qazwsxedcrfvtgbyhnujmikolp", "1qaz2wsx3edc4rfv5tgb")  # secretscan:ignore
DICTIONARY_RANK = {w: i + 1 for i, w in enumerate(COMMON)}
GUESSES_PER_SECOND = 1e10  # offline attack on a fast hash with a few GPUs
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


def human_duration(seconds):
    if seconds < 1:
        return "instantly"
    for limit, unit in ((60, "second"), (3600, "minute"), (86400, "hour"), (86400 * 365, "day"), (86400 * 365 * 100, "year")):
        if seconds < limit:
            divisor = {"second": 1, "minute": 60, "hour": 3600, "day": 86400, "year": 86400 * 365}[unit]
            n = seconds / divisor
            return "%d %s%s" % (n, unit, "" if int(n) == 1 else "s")
    if seconds < 86400 * 365 * 1e6:
        return "%d centuries" % (seconds / (86400 * 365 * 100))
    return "longer than the age of recorded history"


def charset_bits(text):
    size = 0
    if any(c.islower() for c in text):
        size += 26
    if any(c.isupper() for c in text):
        size += 26
    if any(c.isdigit() for c in text):
        size += 10
    if any(c in string.punctuation for c in text):
        size += 33
    if any(ord(c) > 127 or c == " " for c in text):
        size += 32
    return math.log2(size) if size else 0.0


def _run(text, i, step_ok):
    """Length of the run starting at i for which step_ok(prev, cur) keeps holding."""
    j = i + 1
    while j < len(text) and step_ok(text[j - 1], text[j]):
        j += 1
    return j - i


def _find_patterns(text):
    """Greedy left-to-right segmentation. Yields (start, end, kind, bits)."""
    low = text.lower()
    deleet = low.translate(LEET)
    i, n = 0, len(text)
    per_char = charset_bits(text)
    while i < n:
        best = None
        # common password or common word, with look-alike substitutions undone
        for j in range(n, i + 3, -1):
            for form, rank_source in ((low[i:j], "plain"), (deleet[i:j], "leet")):
                rank = DICTIONARY_RANK.get(form)
                if rank:
                    bits = math.log2(rank + 1) + (1.5 if rank_source == "leet" else 0) + sum(1 for c in text[i:j] if c.isupper()) * 0.5
                    best = (i, j, "common-password" if j - i == n else "common-word", bits)
                    break
            if best:
                break
        if best is None:
            run = _run(low, i, lambda a, b: a == b)
            if run >= 4:
                best = (i, i + run, "repeat", math.log2(per_char or 1) + math.log2(run) + 1)
        if best is None:
            for step in (1, -1):
                run = _run(low, i, lambda a, b, s=step: (a.isalnum() and b.isalnum() and ord(b) - ord(a) == s))
                if run >= 4:
                    best = (i, i + run, "sequence", math.log2(per_char or 1) + math.log2(run) + 1)
                    break
        if best is None:
            for row in KEYBOARD_ROWS:
                for chunk in range(min(n - i, len(row)), 3, -1):
                    piece = low[i:i + chunk]
                    if piece in row or piece[::-1] in row:
                        best = (i, i + chunk, "keyboard-walk", math.log2(per_char or 1) + math.log2(chunk) + 2)
                        break
                if best:
                    break
        if best is None:
            m = re.match(r"(19|20)\d\d", text[i:])
            if m and not text[i + 4:i + 5].isdigit():
                best = (i, i + 4, "year", 6.5)
        if best is None:
            best = (i, i + 1, "random", per_char)
        yield best
        i = best[1]


def analyze(password):
    """Estimate strength. -> dict with bits, guesses, crack time, score 0-4, patterns, advice."""
    if not password:
        return {"length": 0, "bits": 0.0, "score": 0, "label": "empty", "patterns": [], "advice": ["enter a password"],
                "crack_time": "instantly"}
    segments = list(_find_patterns(password))
    bits = sum(s[3] for s in segments)
    bits = min(bits, len(password) * charset_bits(password))  # never claim more than brute force would need
    kinds = sorted({s[2] for s in segments if s[2] != "random"})
    seconds = (2 ** min(bits, 1000)) / 2 / GUESSES_PER_SECOND
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 60 else 3 if bits < 80 else 4
    advice = []
    if "common-password" in kinds:
        advice.append("this is (a variant of) one of the most common passwords; attackers try it first")
    if "common-word" in kinds:
        advice.append("it contains a common word or password; adding digits or a capital at the end barely helps")
    if "keyboard-walk" in kinds:
        advice.append("keyboard patterns like qwerty or 1qaz2wsx are in every attacker's list")
    if "sequence" in kinds:
        advice.append("sequences such as abcd or 1234 are guessed early")
    if "repeat" in kinds:
        advice.append("repeated characters add almost nothing")
    if "year" in kinds:
        advice.append("years and dates are easy to guess")
    if len(password) < 12:
        advice.append("longer is stronger: aim for 14 or more characters")
    if score <= 2:
        advice.append("use a password manager and let it generate a random one (pwlint gen does too)")
    return {"length": len(password), "bits": round(bits, 1), "score": score,
            "label": ("very weak", "weak", "fair", "good", "strong")[score], "patterns": kinds,
            "crack_time": human_duration(seconds), "advice": advice}


# ---------------------------------------------------------------- generator

def generate(length=20, symbols=True, ambiguous=True, digits=True, upper=True, lower=True):
    """A random password with at least one character from every selected class (secrets, not random)."""
    classes = []
    if lower:
        classes.append(string.ascii_lowercase)
    if upper:
        classes.append(string.ascii_uppercase)
    if digits:
        classes.append(string.digits)
    if symbols:
        classes.append(SYMBOLS)
    if not classes:
        raise ValueError("select at least one kind of character")
    if not ambiguous:
        classes = ["".join(c for c in cls if c not in AMBIGUOUS) for cls in classes]
    if length < len(classes):
        raise ValueError("length must be at least %d for the selected character kinds" % len(classes))
    if length > 4096:
        raise ValueError("length is capped at 4096")
    alphabet = "".join(classes)
    chars = [secrets.choice(cls) for cls in classes]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_pin(digits=6):
    if not 4 <= digits <= 32:
        raise ValueError("a PIN needs 4 to 32 digits")
    return "".join(secrets.choice(string.digits) for _ in range(digits))


# --------------------------------------------------------------------- CLI

def read_password(use_stdin, prompt=getpass.getpass, stdin=None):
    stdin = stdin or sys.stdin
    if use_stdin:
        line = stdin.readline()
        return line.rstrip("\r\n")
    return prompt("Password to check (typing is hidden): ")


def main(argv=None, prompt=getpass.getpass, stdin=None):
    ap = argparse.ArgumentParser(description="Judge passwords offline and generate strong ones.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="estimate the strength of a password (read from a hidden prompt or stdin)")
    c.add_argument("--stdin", action="store_true", help="read the password from the first line of stdin")
    c.add_argument("--min-bits", type=float, default=60, help="exit 1 below this many bits (default 60)")
    c.add_argument("--json", action="store_true")
    g = sub.add_parser("gen", help="generate random passwords")
    g.add_argument("-n", "--length", type=int, default=20, help="characters per password (default 20)")
    g.add_argument("-c", "--count", type=int, default=1, help="how many (default 1)")
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--no-ambiguous", action="store_true", help="avoid look-alike characters (I l 1 O 0 o)")
    g.add_argument("--no-digits", action="store_true")
    g.add_argument("--pin", type=int, metavar="DIGITS", help="generate numeric PINs instead")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "gen":
            if not 1 <= args.count <= 1000:
                raise ValueError("count must be between 1 and 1000")
            for _ in range(args.count):
                print(generate_pin(args.pin) if args.pin else
                      generate(args.length, not args.no_symbols, not args.no_ambiguous, not args.no_digits))
            return 0
        password = read_password(args.stdin, prompt, stdin)
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        print("pwlint: %s" % (exc or "cancelled"), file=sys.stderr)
        return 2
    result = analyze(password)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("%s: about %.0f bits, %d characters; an offline attacker needs roughly %s" % (
            result["label"].upper(), result["bits"], result["length"], result["crack_time"]))
        if result["patterns"]:
            print("patterns found: %s" % ", ".join(result["patterns"]))
        for line in result["advice"]:
            print("- %s" % line)
        print("(an estimate at %.0e guesses per second; the password was not stored or sent anywhere)" % GUESSES_PER_SECOND,
              file=sys.stderr)
    return 0 if result["bits"] >= args.min_bits else 1


if __name__ == "__main__":
    sys.exit(main())
