"""Fail closed if the real Factory revision differs across PRE and MakeAppx gates."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrismRevisionPinConsistencyTests(unittest.TestCase):
    def test_real_factory_binding_matches_both_workflows(self):
        pre = (ROOT / ".github/workflows/prism-revision-provisioner.yml").read_text(encoding="utf-8")
        makeappx = (ROOT / "tests/prism_revision_makeappx.py").read_text(encoding="utf-8")

        def required(pattern):
            match = re.search(pattern, makeappx, flags=re.MULTILINE)
            self.assertIsNotNone(match, pattern)
            return match.group(1)

        source = required(r'^SOURCE = "([a-f0-9]{40})"$')
        request = required(r'^REQUEST = "(3d-prism-route-3d-[a-f0-9]{12})"$')
        run = required(r'^RUN = ([0-9]+)$')
        artifact = required(r'^ARTIFACT = ([0-9]+)$')
        self.assertEqual(request, "3d-prism-route-3d-" + source[:12])
        self.assertIn("sha='" + source + "'", pre)
        self.assertIn("actions/runs/" + run, pre)
        self.assertIn("actions/artifacts/" + artifact, pre)
        self.assertIn("--factory-run-id " + run, pre)
        self.assertIn("--factory-artifact-id " + artifact, pre)
        self.assertIn("factory_run_id=" + run, pre)
        self.assertIn("factory_artifact_id=" + artifact, pre)
        self.assertIn("HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING", makeappx)
        self.assertIn("HOLD_PENDING_OFFICIAL_CAS_AND_NEW_SOURCE_BINDING", pre)
        self.assertIn("signed_msix_verified=False", pre)
        self.assertIn("windows_all_auto_intake_verified=False", pre)

    def test_previous_source_is_provenance_only(self):
        pre = (ROOT / ".github/workflows/prism-revision-provisioner.yml").read_text(encoding="utf-8")
        makeappx = (ROOT / "tests/prism_revision_makeappx.py").read_text(encoding="utf-8")
        previous = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
        self.assertIn(previous, pre)
        self.assertIn(previous, makeappx)
        self.assertNotIn('SOURCE = "' + previous + '"', makeappx)


if __name__ == "__main__":
    unittest.main()
