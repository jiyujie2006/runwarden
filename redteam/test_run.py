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


if __name__ == "__main__":
    unittest.main()
