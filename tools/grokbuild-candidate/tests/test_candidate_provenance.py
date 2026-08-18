import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "candidate_provenance.py"
SPEC = importlib.util.spec_from_file_location("candidate_provenance", MODULE_PATH)
candidate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(candidate)


class CandidateProvenanceTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout.strip()

    def fixture_document(self):
        source_sha = "a" * 40
        return {
            "schemaVersion": 1,
            "source": {
                "officialBaseSHA": "b" * 40,
                "upstreamReplayBaseSHA": "c" * 40,
                "forkSourceSHA": source_sha,
                "sourceRev": "f" * 40,
                "cargoLockSHA256": "d" * 64,
            },
            "toolchain": {
                "rustVersion": "rustc 1.94.0 (fixture)",
                "cargoVersion": "cargo 1.94.0 (fixture)",
                "dotslashVersion": "DotSlash 0.5.7",
                "rustcSHA256": "1" * 64,
                "cargoSHA256": "2" * 64,
                "dotslashSHA256": "3" * 64,
                "targetTriple": "aarch64-apple-darwin",
                "architecture": "arm64",
            },
            "build": {
                "preBuildCommand": candidate.PREBUILD_COMMAND,
                "command": candidate.BUILD_COMMAND,
                "environment": json.loads(json.dumps(candidate.BUILD_ENVIRONMENT)),
                "profile": "release-dist",
                "package": "xai-grok-pager-bin",
                "features": ["release-dist"],
            },
            "binary": {
                "artifactName": "xai-grok-pager",
                "sha256": "e" * 64,
                "sizeBytes": 123,
                "architecture": "arm64",
                "expectedVersionWithCommit": "1.0.5 (aaaaaaa)",
                "expectedACPCLIBuild": "1.0.5 (aaaaaaa)",
                "observedVersionWithCommit": "1.0.5 (aaaaaaa)",
            },
            "signing": {
                "state": "unsigned",
                "strictVerification": False,
                "teamIdentifier": None,
                "designatedRequirement": None,
            },
        }

    def test_canonical_manifest_is_byte_stable(self):
        first = candidate.canonical_bytes(self.fixture_document())
        second = candidate.canonical_bytes(json.loads(first))
        self.assertEqual(first, second)
        self.assertEqual(first[-1:], b"\n")

    def test_shape_rejects_wrong_cli_build(self):
        document = self.fixture_document()
        document["binary"]["expectedACPCLIBuild"] = "1.0.5 (bbbbbbb)"
        with self.assertRaisesRegex(candidate.CandidateError, "build string"):
            candidate.validate_shape(document)

    def test_shape_rejects_build_without_release_dist_feature(self):
        document = self.fixture_document()
        document["build"]["features"] = []
        with self.assertRaisesRegex(candidate.CandidateError, "feature"):
            candidate.validate_shape(document)

    def test_shape_rejects_invalid_signing_claim(self):
        document = self.fixture_document()
        document["signing"]["state"] = "signed"
        document["signing"]["teamIdentifier"] = "DD2GCQJVB4"
        document["signing"]["designatedRequirement"] = "identifier fixture"
        with self.assertRaisesRegex(candidate.CandidateError, "strict"):
            candidate.validate_shape(document)

    def test_shape_accepts_honest_ad_hoc_signing(self):
        document = self.fixture_document()
        document["signing"] = {
            "state": "adHoc",
            "strictVerification": True,
            "teamIdentifier": None,
            "designatedRequirement": "identifier fixture",
        }
        candidate.validate_shape(document)

    def test_codesign_parser_reports_ad_hoc_without_team_identity(self):
        def fake_run(args, **_kwargs):
            command = " ".join(args)
            if "--verbose=4" in command:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    "",
                    "Executable=/private/tmp/candidate\nSignature=adhoc\nTeamIdentifier=not set\n",
                )
            if "--verify" in command:
                return subprocess.CompletedProcess(args, 0, "", "valid on disk\n")
            return subprocess.CompletedProcess(
                args,
                0,
                "",
                "designated => identifier fixture\n",
            )

        with mock.patch.object(candidate, "run", side_effect=fake_run):
            signing = candidate.signing_identity(Path("/private/tmp/candidate"))
        self.assertEqual(signing["state"], "adHoc")
        self.assertIsNone(signing["teamIdentifier"])
        self.assertTrue(signing["strictVerification"])

    def test_version_probe_uses_disposable_home(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "candidate"
            binary.write_text(
                "#!/bin/sh\n"
                "test \"$GROK_HOME\" != \"/sentinel/live-grok-home\" || exit 91\n"
                "test \"$HOME\" != \"/sentinel/live-home\" || exit 92\n"
                "test \"$GROK_HOME\" = \"$HOME/grok-home\" || exit 93\n"
                "printf 'grok 1.0.5 (aaaaaaa) [stable]\\n'\n",
                encoding="utf-8",
            )
            os.chmod(binary, 0o700)
            with mock.patch.dict(
                os.environ,
                {"GROK_HOME": "/sentinel/live-grok-home", "HOME": "/sentinel/live-home"},
            ):
                self.assertEqual(candidate.observed_cli_build(binary), "1.0.5 (aaaaaaa)")

    def test_binary_symlink_is_rejected_before_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_bytes(b"fixture")
            os.chmod(target, 0o700)
            link = root / "candidate"
            link.symlink_to(target)
            with self.assertRaisesRegex(candidate.CandidateError, "non-symlink"):
                candidate.build_document(
                    repo=root,
                    binary=link,
                    official_base="b" * 40,
                    replay_base="c" * 40,
                    require_clean=False,
                )

    def test_private_directory_rejects_symlink_component(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            physical = root / "physical"
            physical.mkdir(mode=0o700)
            link = root / "linked"
            link.symlink_to(physical, target_is_directory=True)
            with self.assertRaisesRegex(candidate.CandidateError, "symbolic-link"):
                candidate.require_private_directory(link)

    def test_verifier_rejects_substituted_binary(self):
        document = self.fixture_document()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            binary = root / "candidate"
            manifest.write_bytes(candidate.canonical_bytes(document))
            os.chmod(manifest, 0o600)
            binary.write_bytes(b"substituted")
            os.chmod(binary, 0o700)
            changed = json.loads(candidate.canonical_bytes(document))
            changed["binary"]["sha256"] = candidate.sha256_file(binary)
            changed["binary"]["sizeBytes"] = binary.stat().st_size
            with mock.patch.object(candidate, "build_document", return_value=changed):
                with self.assertRaisesRegex(candidate.CandidateError, "does not match"):
                    candidate.verify_manifest(
                        repo=root,
                        binary=binary,
                        manifest=manifest,
                        official_base="b" * 40,
                        replay_base="c" * 40,
                        require_clean=False,
                    )

    def test_real_verifier_rejects_physical_binary_substitution(self):
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("C compiler unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repo = root / "repo"
            repo.mkdir(mode=0o700)
            self.git(repo, "init", "-q")
            self.git(repo, "config", "user.name", "GrokBuild Test")
            self.git(repo, "config", "user.email", "grokbuild-test@example.invalid")
            (repo / "Cargo.lock").write_text("# fixture lock\n", encoding="utf-8")
            (repo / "SOURCE_REV").write_text("f" * 40 + "\n", encoding="utf-8")
            self.git(repo, "add", "Cargo.lock", "SOURCE_REV")
            self.git(repo, "commit", "-qm", "official base")
            official = self.git(repo, "rev-parse", "HEAD")
            (repo / "replay").write_text("replay\n", encoding="utf-8")
            self.git(repo, "add", "replay")
            self.git(repo, "commit", "-qm", "replay base")
            replay = self.git(repo, "rev-parse", "HEAD")
            (repo / "source").write_text("source\n", encoding="utf-8")
            self.git(repo, "add", "source")
            self.git(repo, "commit", "-qm", "fork source")
            source = self.git(repo, "rev-parse", "HEAD")

            candidate_dir = root / "candidate"
            candidate_dir.mkdir(mode=0o700)
            binary = candidate_dir / "xai-grok-pager"

            def compile_fixture(extra):
                source_file = root / "fixture.c"
                source_file.write_text(
                    "#include <stdio.h>\n"
                    f"int main(void) {{ puts(\"grok 1.0.5 ({source[:7]}) [stable]\"); {extra} return 0; }}\n",
                    encoding="utf-8",
                )
                subprocess.run([compiler, str(source_file), "-o", str(binary)], check=True)
                os.chmod(binary, 0o700)

            compile_fixture("")
            manifest = candidate_dir / "candidate-provenance-v1.json"
            toolchain = {
                "rustVersion": "rustc 1.94.0 (fixture)",
                "cargoVersion": "cargo 1.94.0 (fixture)",
                "dotslashVersion": "DotSlash 0.5.7",
                "rustcSHA256": "1" * 64,
                "cargoSHA256": "2" * 64,
                "dotslashSHA256": "3" * 64,
                "targetTriple": "aarch64-apple-darwin",
                "architecture": candidate.binary_architecture(binary),
            }
            with mock.patch.object(candidate, "toolchain_identity", return_value=toolchain):
                first = candidate.build_document(
                    repo=repo,
                    binary=binary,
                    official_base=official,
                    replay_base=replay,
                )
                candidate.write_private(manifest, candidate.canonical_bytes(first))
                compile_fixture("volatile int substituted = 1; (void)substituted;")
                with self.assertRaisesRegex(candidate.CandidateError, "does not match"):
                    candidate.verify_manifest(
                        repo=repo,
                        binary=binary,
                        manifest=manifest,
                        official_base=official,
                        replay_base=replay,
                    )

    def test_private_manifest_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "manifest.json"
            candidate.write_private(path, b"{}\n")
            with self.assertRaisesRegex(candidate.CandidateError, "refusing to replace"):
                candidate.write_private(path, b"changed\n")

    def test_source_rev_requires_small_regular_full_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = root / "SOURCE_REV"
            valid.write_text("a" * 40 + "\n", encoding="ascii")
            self.assertEqual(candidate.read_source_rev(valid), "a" * 40)

            oversized = root / "oversized"
            oversized.write_bytes(b"b" * 129)
            with self.assertRaisesRegex(candidate.CandidateError, "bounded|limit"):
                candidate.read_source_rev(oversized)

            link = root / "linked"
            link.symlink_to(valid)
            with self.assertRaisesRegex(candidate.CandidateError, "safely"):
                candidate.read_source_rev(link)

    def test_tool_resolution_ignores_ambient_path(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "cargo"
            fake.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
            os.chmod(fake, 0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": directory,
                    "HOME": directory,
                    "CARGO_HOME": directory,
                    "RUSTUP_HOME": directory,
                    "RUSTUP_TOOLCHAIN": "hostile",
                },
            ):
                resolved = candidate.resolve_tool("cargo")
        self.assertNotEqual(resolved, fake)
        self.assertTrue(resolved.is_absolute())

    def test_multicall_rustup_preserves_approved_invocation_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "rustup-init"
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(target, 0o700)
            invocation = root / "rustup"
            invocation.symlink_to(target)
            self.assertEqual(
                candidate.require_executable(
                    invocation,
                    "rustup",
                    preserve_invocation_path=True,
                ),
                invocation.absolute(),
            )
            self.assertEqual(candidate.require_executable(invocation, "rustup"), target.resolve())

    def test_build_wrapper_uses_absolute_attestation_tools_and_preclean(self):
        wrapper = MODULE_PATH.with_name("build_candidate.sh").read_text(encoding="utf-8")
        self.assertIn('git_bin="/usr/bin/git"', wrapper)
        self.assertIn('python_bin="/usr/bin/python3"', wrapper)
        self.assertIn("unset CARGO_HOME RUSTUP_HOME RUSTUP_TOOLCHAIN", wrapper)
        self.assertIn("user Cargo configuration is not allowed", wrapper)
        self.assertIn("cargo_environment=(", wrapper)
        self.assertIn("/usr/bin/env -i", wrapper)
        self.assertIn('"$cargo_bin" clean --target-dir', wrapper)
        self.assertIn('"$cargo_bin" build --locked', wrapper)
        self.assertNotIn("repo_root=\"$(git ", wrapper)
        self.assertNotIn("\npython3 ", wrapper)

    def test_manifest_build_command_matches_hardened_wrapper(self):
        self.assertNotIn("+1.94.0", candidate.BUILD_COMMAND)
        self.assertEqual(candidate.BUILD_COMMAND[0:2], ["cargo", "build"])
        self.assertTrue(candidate.BUILD_ENVIRONMENT["clearEnvironment"])
        self.assertEqual(candidate.BUILD_ENVIRONMENT["path"][0], "/usr/bin")

    def test_shape_rejects_build_environment_drift(self):
        document = self.fixture_document()
        document["build"]["environment"]["path"].reverse()
        with self.assertRaisesRegex(candidate.CandidateError, "environment"):
            candidate.validate_shape(document)

    def test_schema_file_is_valid_json(self):
        schema_path = MODULE_PATH.with_name("candidate-provenance-v1.schema.json")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["schemaVersion"]["const"], 1)
        self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
