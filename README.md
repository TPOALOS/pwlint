# pwlint

**Judge a password honestly, and generate strong ones. Offline.** `pwlint check` estimates how many guesses an attacker would
need and says *why* a password is weak. `pwlint gen` makes random passwords and PINs with Python's cryptographic random
generator.

The password is **never printed and never sent anywhere**. It is read from a hidden prompt (or stdin), not from the command
line, where it would stay in your shell history. One file, standard library only.

```
$ pwlint check
Password to check (typing is hidden):
VERY WEAK: about 20 bits, 11 characters; an offline attacker needs roughly instantly
patterns found: common-word, year
- it contains a common word or password; adding digits or a capital at the end barely helps
- years and dates are easy to guess
- longer is stronger: aim for 14 or more characters
- use a password manager and let it generate a random one (pwlint gen does too)

$ pwlint gen -n 18
-m9Q0eZ+1g$1,&j7ju
$ pwlint gen -n 18 | pwlint check --stdin
STRONG: about 118 bits, 18 characters; an offline attacker needs roughly longer than the age of recorded history
```

## Install and use

```bash
pip install git+https://github.com/TPOALOS/pwlint          # or copy pwlint.py
pwlint check                         # hidden prompt
pwlint check --stdin < file          # first line of stdin
pwlint check --min-bits 80           # exit 1 if weaker (for scripts)
pwlint gen                           # one 20-character password
pwlint gen -n 24 -c 5 --no-symbols --no-ambiguous     # five, letters and digits only, no look-alikes (I l 1 O 0 o)
pwlint gen --pin 8                   # numeric PINs
```

## How it estimates

The password is cut into pieces and each piece is priced the way an attacker would guess it:

| Pattern | Examples | Cost |
|---|---|---|
| common password or word (with `0 1 3 4 5 7 @ $` look-alike swaps undone) | `password`, `P@ssw0rd`, `sunshine` | the entry's rank in the list, about 2 to 10 bits |
| keyboard walk | `qwerty`, `1qaz2wsx` | a few bits |
| sequence | `abcd`, `4321`, `mnopqr` | a few bits |
| repeats | `zzzzzzzz` | a few bits |
| year | `1999`, `2024` | 6.5 bits |
| anything else | random characters | log2 of the character set per character |

The total is capped at what brute force would need, then turned into a crack time at 10 billion guesses per second (an
offline attack on a fast hash). Scores: under 28 bits very weak, 40 weak, 60 fair, 80 good, above strong.

Exit codes: `check` `0` at or above `--min-bits` (default 60), `1` below; `2` usage error or cancelled prompt.

## Limits

An estimate, not a proof. The built-in list holds a few hundred of the most common passwords; real attackers use millions
and also your name, birthday and leaked passwords from other sites. pwlint cannot know whether *your* password appeared in a
breach (that needs a network lookup, which this tool deliberately never does). Use a password manager, a unique password per
site, and two-factor authentication.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [exifstrip](https://github.com/TPOALOS/exifstrip) · [secretscan](https://github.com/TPOALOS/secretscan) · [githook-guard](https://github.com/TPOALOS/githook-guard) · [all 51 tools](https://tpoalos.github.io)
