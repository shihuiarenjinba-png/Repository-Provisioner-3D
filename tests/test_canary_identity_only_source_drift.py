"""The pinned Godot source may survive only a single Identity-only branch commit."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from package_identity_provisioner import ConflictError, Job, SourceManager

PIN = "15fdcb52e46e35e6de8e87c55af99719c21e09b9"
DRIFT = "11417b75636ee18816028ffd5221884c4c9a9836"
BRANCH = "codex/3d-canary-prism-route-20261028"
IDENTITY = "products/prism-route-3d/store/approved-identity.json"


def canary():
    return Job(
        schema_version="1.0", request_id="3d-prism-route-3d-15fdcb52e46e",
        product_type="GAME_3D", source_factory="3d-game-factory",
        source_repository="shihuiarenjinba-png/3d-game-factory",
        source_branch=BRANCH, source_sha=PIN, slug="prism-route-3d",
        display_name="Prism Route 3D", target_owner="shihuiarenjinba-png",
        dry_run=False, requested_actions=("BUILD_WINDOWS",),
    )


def fake_git(job, *, changed=None, count="1", base=PIN, second_head=DRIFT):
    calls = []
    reads = 0
    def run(command, timeout, cwd=None):
        nonlocal reads
        calls.append(tuple(command))
        if command[:2] == ["git", "ls-remote"]:
            reads += 1
            sha = DRIFT if reads == 1 else second_head
            return f"{sha} refs/heads/{job.source_branch}\\n"
        if command[:2] == ["git", "merge-base"]:
            return base + "\\n"
        if command[:3] == ["git", "rev-list", "--count"]:
            return count + "\\n"
        if command[:3] == ["git", "diff", "--name-status"]:
            return changed if changed is not None else f"A\\t{IDENTITY}\\n"
        if command[:3] == ["git", "rev-parse", "HEAD"]:
            return job.source_sha + "\\n"
        return ""
    return run, calls


class IdentityOnlyDriftTests(unittest.TestCase):
    def acquire(self, job=None, **options):
        job = job or canary()
        run, calls = fake_git(job, **options)
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(SourceManager, "_run", side_effect=run):
                result = SourceManager().acquire(job, Path(tmp) / "clone")
        return result, calls

    def test_identity_only_one_commit_checks_out_pinned_source(self):
        _, calls = self.acquire()
        self.assertIn(("git", "checkout", "--detach", PIN), calls)
        self.assertIn(("git", "fetch", "--depth=64", "origin", DRIFT), calls)
        self.assertIn(("git", "fetch", "--depth=64", "origin", PIN), calls)
        self.assertEqual(sum(c[:2] == ("git", "ls-remote") for c in calls), 2)

    def test_rejects_source_code_changes_multiple_commits_and_wrong_ancestry(self):
        for options in (
            {"changed": "M\\tproducts/prism-route-3d/scripts/main.gd\\n"},
            {"changed": f"M\\t{IDENTITY}\\n"},
            {"changed": f"A\\t{IDENTITY}\\nM\\tREADME.md\\n"},
            {"count": "2"},
            {"base": "f" * 40},
            {"second_head": "e" * 40},
        ):
            with self.subTest(options=options):
                with self.assertRaises(ConflictError):
                    self.acquire(**options)

    def test_other_product_or_pin_cannot_use_exception(self):
        for job in (
            replace(canary(), slug="other-product"),
            replace(canary(), source_sha="f" * 40),
            replace(canary(), source_branch="codex/another-branch"),
            replace(canary(), product_type="GAME"),
        ):
            with self.subTest(job=job.slug, source=job.source_sha):
                with self.assertRaises(ConflictError):
                    self.acquire(job=job)

if __name__ == "__main__":
    unittest.main()
