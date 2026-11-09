import contextlib
import io
import json
import string
import unittest

import pwlint as pw


def bits(password):
    return pw.analyze(password)["bits"]


class AnalyzeTests(unittest.TestCase):
    def test_common_passwords_are_very_weak(self):
        for p in ("password", "123456", "qwerty", "letmein", "iloveyou", "admin", "Password1", "P@ssw0rd", "PASSWORD", "dragon"):
            r = pw.analyze(p)
            self.assertLess(r["bits"], 28, p)
            self.assertEqual(r["score"], 0, p)

    def test_word_plus_digits_is_still_weak(self):
        r = pw.analyze("sunshine2024")
        self.assertLess(r["bits"], 40)
        self.assertIn("common-word", r["patterns"])
        self.assertIn("year", r["patterns"])

    def test_leet_speak_does_not_help(self):
        self.assertLess(bits("p4ssw0rd"), 28)
        self.assertLess(bits("m0nk3y"), 28)

    def test_keyboard_walks_and_sequences_and_repeats(self):
        self.assertIn("keyboard-walk", pw.analyze("zxcvbnmasdf")["patterns"])
        self.assertIn("keyboard-walk", pw.analyze("1qaz2wsx3edc")["patterns"])
        self.assertIn("sequence", pw.analyze("mnopqrst")["patterns"])
        self.assertIn("sequence", pw.analyze("tsrqponm")["patterns"])
        self.assertIn("repeat", pw.analyze("zzzzzzzzzzzz")["patterns"])
        for p in ("mnopqrstuvwx", "zzzzzzzzzzzz", "qwertyuiop"):
            self.assertLess(bits(p), 40, p)

    def test_random_passwords_are_strong(self):
        for _ in range(20):
            r = pw.analyze(pw.generate(20))
            self.assertGreaterEqual(r["score"], 3)

    def test_length_beats_complexity(self):
        self.assertGreater(bits("correct horse battery staple window"), bits("Tr0ub4dor&3"))

    def test_more_length_means_more_bits(self):
        a, b, c = pw.generate(8), pw.generate(16), pw.generate(32)
        self.assertLess(bits(a), bits(b))
        self.assertLess(bits(b), bits(c))

    def test_never_more_than_brute_force(self):
        for p in ("a1", "Zx9!", "hello world"):
            self.assertLessEqual(bits(p), len(p) * pw.charset_bits(p) + 0.06)  # bits are rounded to 0.1

    def test_empty_password(self):
        r = pw.analyze("")
        self.assertEqual((r["bits"], r["score"], r["label"]), (0.0, 0, "empty"))

    def test_unicode_and_spaces(self):
        r = pw.analyze("Güneş doğarken çay içtim 42")
        self.assertGreater(r["bits"], 60)

    def test_very_long_input_is_fast_and_sane(self):
        r = pw.analyze("x" * 5000)
        self.assertIn("repeat", r["patterns"])
        r = pw.analyze(pw.generate(2000))
        self.assertGreater(r["bits"], 1000)

    def test_scores_are_monotonic_with_bits(self):
        order = [pw.analyze(p) for p in ("password", "sunshine2024", "Tr0ub4dor&3", pw.generate(14), pw.generate(30))]
        self.assertEqual([r["score"] for r in order], sorted(r["score"] for r in order))

    def test_advice_matches_the_problem(self):
        advice = " ".join(pw.analyze("qwerty").get("advice"))
        self.assertIn("common", advice)
        self.assertIn("password manager", advice)
        self.assertNotIn("common", " ".join(pw.analyze(pw.generate(24))["advice"]))

    def test_short_coincidences_in_random_text_are_not_flagged(self):
        for p in ("xq7abcM!z2", "Kd9aaB#v1w", "p3qweL!z9T"):
            self.assertEqual(pw.analyze(p)["patterns"], [], p)

    def test_year_detection_does_not_fire_inside_longer_numbers(self):
        self.assertNotIn("year", pw.analyze("x19999y")["patterns"])
        self.assertIn("year", pw.analyze("x1999y")["patterns"])

    def test_analysis_never_contains_the_password(self):
        secret = "Zq7!pLm2#vK9wXr4"  # secretscan:ignore
        self.assertNotIn(secret, json.dumps(pw.analyze(secret)))


class DurationTests(unittest.TestCase):
    def test_human_duration(self):
        cases = [(0.2, "instantly"), (5, "5 seconds"), (60, "1 minute"), (7200, "2 hours"), (86400 * 3, "3 days"),
                 (86400 * 365 * 5, "5 years"), (86400 * 365 * 500, "5 centuries")]
        for seconds, text in cases:
            self.assertEqual(pw.human_duration(seconds), text)
        self.assertIn("history", pw.human_duration(1e30))


class GenerateTests(unittest.TestCase):
    def test_length_and_classes(self):
        for _ in range(50):
            p = pw.generate(16)
            self.assertEqual(len(p), 16)
            self.assertTrue(any(c.islower() for c in p) and any(c.isupper() for c in p))
            self.assertTrue(any(c.isdigit() for c in p) and any(c in pw.SYMBOLS for c in p))

    def test_options(self):
        p = pw.generate(40, symbols=False, digits=False)
        self.assertTrue(all(c in string.ascii_letters for c in p))
        q = pw.generate(200, ambiguous=False)
        self.assertFalse(set(q) & pw.AMBIGUOUS)

    def test_minimum_length_still_has_every_class(self):
        for _ in range(30):
            p = pw.generate(4)
            self.assertEqual(sum(1 for cls in (string.ascii_lowercase, string.ascii_uppercase, string.digits, pw.SYMBOLS)
                                 if any(c in cls for c in p)), 4)

    def test_validation(self):
        for kw in ({"length": 3}, {"length": 5000}, {"symbols": False, "digits": False, "upper": False, "lower": False}):
            with self.assertRaises(ValueError):
                pw.generate(**kw)

    def test_values_differ(self):
        self.assertEqual(len({pw.generate(20) for _ in range(200)}), 200)

    def test_distribution_is_not_obviously_biased(self):
        counts = {}
        for _ in range(500):
            for c in pw.generate(20, symbols=False):
                counts[c] = counts.get(c, 0) + 1
        self.assertGreater(min(counts.values()), 0)
        self.assertEqual(set(counts), set(string.ascii_letters + string.digits))
        self.assertLess(max(counts.values()) / (sum(counts.values()) / len(counts)), 1.5)

    def test_uses_a_cryptographic_source(self):
        import inspect
        source = inspect.getsource(pw.generate) + inspect.getsource(pw.generate_pin)
        self.assertNotIn("random.choice", source.replace("secrets.choice", ""))
        self.assertIn("secrets.", source)

    def test_pins(self):
        for n in (4, 6, 12):
            p = pw.generate_pin(n)
            self.assertEqual((len(p), p.isdigit()), (n, True))
        for bad in (3, 33):
            with self.assertRaises(ValueError):
                pw.generate_pin(bad)


def run_main(*argv, stdin_text=None, prompt_value="prompted-secret"):
    out, err = io.StringIO(), io.StringIO()
    calls = []

    def prompt(text):
        calls.append(text)
        return prompt_value
    stdin = io.StringIO(stdin_text) if stdin_text is not None else None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = pw.main(list(argv), prompt=prompt, stdin=stdin)
    return code, out.getvalue(), err.getvalue(), calls


class CliTests(unittest.TestCase):
    def test_weak_password_exits_one(self):
        code, out, _, _ = run_main("check", "--stdin", stdin_text="password\n")
        self.assertEqual(code, 1)
        self.assertTrue(out.startswith("VERY WEAK"))
        self.assertIn("common", out)

    def test_strong_password_exits_zero(self):
        code, out, _, _ = run_main("check", "--stdin", stdin_text=pw.generate(24) + "\n")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(("GOOD", "STRONG")))

    def test_password_is_never_echoed(self):
        secret = "Zq7!pLm2#vK9wXr4"  # secretscan:ignore
        for extra in ([], ["--json"]):
            code, out, err, _ = run_main("check", "--stdin", *extra, stdin_text=secret + "\n")
            self.assertNotIn(secret, out + err)

    def test_prompt_is_used_when_not_reading_stdin(self):
        code, out, _, calls = run_main("check", prompt_value="hunter2")
        self.assertEqual(len(calls), 1)
        self.assertIn("hidden", calls[0])
        self.assertEqual(code, 1)

    def test_password_is_not_accepted_as_an_argument(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                pw.main(["check", "mypassword"])

    def test_min_bits_threshold(self):
        p = pw.generate(10)
        self.assertEqual(run_main("check", "--stdin", "--min-bits", "10", stdin_text=p)[0], 0)
        self.assertEqual(run_main("check", "--stdin", "--min-bits", "500", stdin_text=p)[0], 1)

    def test_json(self):
        _, out, _, _ = run_main("check", "--stdin", "--json", stdin_text="qwerty123\n")
        data = json.loads(out)
        self.assertEqual(set(data), {"length", "bits", "score", "label", "patterns", "advice", "crack_time"})
        self.assertEqual(data["length"], 9)

    def test_trailing_newline_is_not_part_of_the_password(self):
        a = run_main("check", "--stdin", "--json", stdin_text="abcXYZ123\n")[1]
        b = run_main("check", "--stdin", "--json", stdin_text="abcXYZ123\r\n")[1]
        self.assertEqual(json.loads(a)["length"], json.loads(b)["length"])
        self.assertEqual(json.loads(a)["length"], 9)

    def test_empty_stdin(self):
        code, out, _, _ = run_main("check", "--stdin", stdin_text="")
        self.assertEqual(code, 1)

    def test_gen_default(self):
        code, out, _, _ = run_main("gen")
        self.assertEqual((code, len(out.strip())), (0, 20))

    def test_gen_options(self):
        code, out, _, _ = run_main("gen", "-n", "12", "-c", "5", "--no-symbols", "--no-ambiguous")
        lines = out.strip().splitlines()
        self.assertEqual((code, len(lines), {len(l) for l in lines}), (0, 5, {12}))
        self.assertTrue(all(set(l) <= set(string.ascii_letters + string.digits) - pw.AMBIGUOUS for l in lines))

    def test_gen_pin(self):
        code, out, _, _ = run_main("gen", "--pin", "8", "-c", "3")
        lines = out.strip().splitlines()
        self.assertEqual((code, len(lines)), (0, 3))
        self.assertTrue(all(l.isdigit() and len(l) == 8 for l in lines))

    def test_gen_errors(self):
        for argv in (["gen", "-n", "2"], ["gen", "-c", "0"], ["gen", "-c", "5000"], ["gen", "--pin", "2"]):
            self.assertEqual(run_main(*argv)[0], 2, argv)

    def test_cancelled_prompt(self):
        def prompt(_):
            raise KeyboardInterrupt
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = pw.main(["check"], prompt=prompt)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
