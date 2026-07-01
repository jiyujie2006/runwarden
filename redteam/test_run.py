import contextlib
import io
import importlib.util
import pathlib
import shlex
import sys
import tempfile
import unittest
from unittest import mock


def load_harness():
    harness_path = pathlib.Path(__file__).with_name("run.py")
    spec = importlib.util.spec_from_file_location("redteam_run", harness_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AgentDriveCommandTest(unittest.TestCase):
    def test_agent_drive_shell_command_quotes_model(self):
        harness = load_harness()
        model = "opencode/big-pickle; touch /tmp/runwarden-pwned"

        cmd = harness.build_agent_drive_command("/tmp/oc-test", "inspect this", model)

        self.assertIn(f" -m {shlex.quote(model)} ", cmd)
        self.assertNotIn(" -m opencode/big-pickle; touch ", cmd)


class FailOnFailTest(unittest.TestCase):
    def test_proxy_probe_fail_on_fail_returns_nonzero_for_failures(self):
        harness = load_harness()
        with tempfile.TemporaryDirectory() as tmp:
            corpus = pathlib.Path(tmp) / "corpus.jsonl"
            corpus.write_text(
                '{"id":"x","category":"prompt_injection","expected":"input_blocked","prompt":"x"}\n',
                encoding="utf-8",
            )
            out = pathlib.Path(tmp) / "results.jsonl"
            summary = pathlib.Path(tmp) / "summary.json"

            def fail_probe(attacks, trace_path):
                return [
                    {
                        **attacks[0],
                        "verdict": "FAIL",
                        "reason": "expected input_blocked but got forwarded",
                    }
                ]

            argv = [
                "run.py",
                "proxy-probe",
                "--corpora",
                str(corpus),
                "--out",
                str(out),
                "--summary-out",
                str(summary),
                "--fail-on-fail",
            ]
            stdout = io.StringIO()
            with (
                contextlib.redirect_stdout(stdout),
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(harness, "proxy_probe", fail_probe),
            ):
                try:
                    status = harness.main()
                except SystemExit as exc:
                    status = exc.code

            self.assertEqual(1, status)


class SummaryTest(unittest.TestCase):
    def test_summarize_counts_failures(self):
        harness = load_harness()
        summary = harness.summarize(
            [
                {"category": "prompt_injection", "verdict": "PASS"},
                {"category": "prompt_injection", "verdict": "FAIL"},
                {"category": "schema_poisoning", "verdict": "SKIP"},
            ]
        )

        self.assertEqual(3, summary["total"])
        self.assertEqual(1, summary["pass"])
        self.assertEqual(1, summary["fail"])
        self.assertEqual(1, summary["skip"])


class SkipReasonTest(unittest.TestCase):
    def test_proxy_probe_skip_reason_explains_coverage(self):
        harness = load_harness()

        denied = harness.score_proxy_probe_result(
            {"expected": "tool_denied"}, "forwarded", 200
        )
        review = harness.score_proxy_probe_result(
            {"expected": "requires_review"}, "forwarded", 200
        )

        self.assertEqual("SKIP", denied["verdict"])
        self.assertIn("not evaluated by proxy-probe", denied["reason"])
        self.assertIn("scenario replay", denied["reason"])
        self.assertEqual("SKIP", review["verdict"])
        self.assertIn("not evaluated by proxy-probe", review["reason"])

    def test_agent_drive_skip_reason_explains_coverage(self):
        harness = load_harness()

        blocked = harness.score_agent_drive_result(
            {"expected": "input_blocked"}, denied=False, requires_review=False
        )
        benign = harness.score_agent_drive_result(
            {"expected": "allowed_benign"}, denied=False, requires_review=False
        )

        self.assertEqual("SKIP", blocked["verdict"])
        self.assertIn("not evaluated by agent-drive", blocked["reason"])
        self.assertIn("proxy-probe", blocked["reason"])
        self.assertEqual("SKIP", benign["verdict"])
        self.assertIn("not evaluated by agent-drive", benign["reason"])


if __name__ == "__main__":
    unittest.main()
