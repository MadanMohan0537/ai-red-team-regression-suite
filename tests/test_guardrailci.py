import tempfile
import unittest
from pathlib import Path

from guardrailci.demo import run_demo
from guardrailci.grader import grade
from guardrailci.library import load_attacks
from guardrailci.minimizer import minimize
from guardrailci.models import Fix
from guardrailci.report import html_report
from guardrailci.runner import attack_success_rate, category_rates, execute, run_suite, severity_weighted_rate
from guardrailci.tracker import FixTracker


class GuardrailCITests(unittest.TestCase):
    def setUp(self):
        self.attacks = load_attacks()

    def test_library_has_twenty_attacks(self):
        self.assertEqual(20, len(self.attacks))

    def test_library_spans_four_categories(self):
        self.assertEqual(4, len({a.category for a in self.attacks}))

    def test_attack_ids_unique(self):
        self.assertEqual(len(self.attacks), len({a.attack_id for a in self.attacks}))

    def test_four_smoke_attacks(self):
        self.assertEqual(4, sum(a.smoke for a in self.attacks))

    def test_vulnerable_release_fails_all_attacks(self):
        _, grades = run_suite(self.attacks, "v1-vulnerable")
        self.assertEqual(1.0, attack_success_rate(grades))

    def test_guarded_release_blocks_all_attacks(self):
        _, grades = run_suite(self.attacks, "v2-guarded")
        self.assertEqual(0.0, attack_success_rate(grades))

    def test_smoke_subset(self):
        transcripts, grades = run_suite(self.attacks, "v1-vulnerable", smoke_only=True)
        self.assertEqual(4, len(transcripts))
        self.assertEqual(4, len(grades))

    def test_category_rates_have_denominators(self):
        _, grades = run_suite(self.attacks, "v1-vulnerable")
        self.assertEqual(4, len(category_rates(grades)))

    def test_severity_weighted_rate_bounded(self):
        _, grades = run_suite(self.attacks, "v1-vulnerable")
        self.assertLessEqual(severity_weighted_rate(grades), 1.0)

    def test_transcript_preserves_steps_and_responses(self):
        transcript, _ = execute(self.attacks[0], "v1-vulnerable")
        self.assertEqual(len(transcript.steps), len(transcript.responses))

    def test_direct_jailbreak_evidence(self):
        _, result = execute(self.attacks[0], "v1-vulnerable")
        self.assertIn("POLICY_BYPASSED", result.evidence)

    def test_minimizer_preserves_violation(self):
        reduced, metrics = minimize(self.attacks[0], "v1-vulnerable")
        self.assertTrue(metrics["reproduced"])
        self.assertLess(len(reduced.steps), len(self.attacks[0].steps))

    def test_minimizer_does_not_reduce_safe_attack(self):
        reduced, metrics = minimize(self.attacks[0], "v2-guarded")
        self.assertFalse(metrics["reproduced"])
        self.assertEqual(self.attacks[0].steps, reduced.steps)

    def test_minimizer_repeats_trials(self):
        _, metrics = minimize(self.attacks[0], "v1-vulnerable", trials=5)
        self.assertEqual(5, metrics["trials"])

    def test_fix_tracker_verifies_blocked_attack(self):
        tracker = FixTracker()
        tracker.save(Fix("DJ-01", "harden", "v2-guarded"))
        self.assertEqual("verified", tracker.verify("DJ-01", False).status)

    def test_fix_tracker_marks_regression(self):
        tracker = FixTracker()
        tracker.save(Fix("DJ-01", "harden", "v2-guarded"))
        self.assertEqual("regressed", tracker.verify("DJ-01", True).status)

    def test_unknown_fix_raises(self):
        with self.assertRaises(KeyError):
            FixTracker().verify("missing", False)

    def test_demo_records_release_trend(self):
        report = run_demo()
        self.assertGreater(report["releases"][0]["attack_success_rate"], report["releases"][1]["attack_success_rate"])

    def test_demo_minimizes_every_reproducible_attack(self):
        result = run_demo()["minimization"]
        self.assertTrue(result["all_reproduced"])
        self.assertLess(result["minimal_steps"], result["original_steps"])

    def test_html_contains_accessible_chart(self):
        output = html_report(run_demo())
        self.assertIn("aria-label='Attack success rate by release'", output)
        self.assertIn("P1 attack-path minimization", output)


if __name__ == "__main__":
    unittest.main()
