import importlib.util
import pathlib
import shlex
import unittest


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


class ProxyProbeScoringTest(unittest.TestCase):
    def test_proxy_probe_scores_model_filter_expectations(self):
        harness = load_harness()

        blocked = harness.score_proxy_probe_result({"expected": "input_blocked"}, "input_blocked", 403)
        benign = harness.score_proxy_probe_result({"expected": "allowed_benign"}, "forwarded", 200)

        self.assertEqual("PASS", blocked["verdict"])
        self.assertEqual("PASS", benign["verdict"])

    def test_proxy_probe_skips_tool_call_expectations(self):
        harness = load_harness()

        denied = harness.score_proxy_probe_result({"expected": "tool_denied"}, "forwarded", 200)
        review = harness.score_proxy_probe_result({"expected": "requires_review"}, "forwarded", 200)

        self.assertEqual("SKIP", denied["verdict"])
        self.assertEqual("SKIP", review["verdict"])


if __name__ == "__main__":
    unittest.main()
