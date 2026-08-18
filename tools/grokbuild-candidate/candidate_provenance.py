#!/usr/bin/env python3
"""Build and verify deterministic GrokBuild CLI candidate provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence


SCHEMA_VERSION = 1
BUILD_COMMAND = [
    "cargo",
    "+1.94.0",
    "build",
    "--locked",
    "--profile",
    "release-dist",
    "-p",
    "xai-grok-pager-bin",
    "--features",
    "release-dist",
]
EXPECTED_TOP_LEVEL_KEYS = {
    "schemaVersion",
    "source",
    "toolchain",
    "build",
    "binary",
    "signing",
}
CLI_BUILD_RE = re.compile(r"(?P<build>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)? \([0-9a-f]{7,40}\))")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")


class CandidateError(RuntimeError):
    """A provenance invariant failed."""


def run(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(args),
        cwd=cwd,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy() if env is None else env,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise CandidateError(f"command failed ({result.returncode}): {' '.join(args)}: {detail}")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        initial = os.fstat(fd)
        if not stat.S_ISREG(initial.st_mode):
            raise CandidateError(f"hash target is not a regular file: {path}")
        with os.fdopen(os.dup(fd), "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        final = os.fstat(fd)
        if (initial.st_dev, initial.st_ino, initial.st_size) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
        ):
            raise CandidateError(f"hash target changed during inspection: {path}")
    finally:
        os.close(fd)
    return digest.hexdigest()


def canonical_bytes(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def absolute_path(path: Path) -> Path:
    normalized = Path(os.path.abspath(os.fspath(path)))
    parts = normalized.parts
    if len(parts) >= 2 and parts[1] in {"tmp", "var"}:
        return Path("/private").joinpath(*parts[1:])
    return normalized


def require_no_symlink_components(path: Path) -> Path:
    path = absolute_path(path)
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise CandidateError(f"path contains a symbolic-link component: {current}")
    return path


def require_private_directory(path: Path) -> Path:
    path = require_no_symlink_components(path)
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise CandidateError(f"private directory does not exist: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CandidateError(f"private path is not a physical directory: {path}")
    if metadata.st_uid != os.getuid():
        raise CandidateError(f"private directory is not owned by the current user: {path}")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise CandidateError(f"private directory grants group/other access: {path}")
    return path


def prepare_private_directory(path: Path, *, must_not_exist: bool = False) -> Path:
    path = absolute_path(path)
    existed = path.exists() or path.is_symlink()
    if must_not_exist and existed:
        raise CandidateError(f"private output directory already exists: {path}")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise CandidateError(f"output path is not a physical directory: {current}")
    if not existed:
        os.chmod(path, 0o700)
    return require_private_directory(path)


def write_private(path: Path, payload: bytes) -> None:
    path = absolute_path(path)
    parent = require_private_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise CandidateError(f"refusing to replace existing candidate manifest: {path}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise CandidateError("candidate manifest write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temporary_path, path, follow_symlinks=False)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary_path.unlink(missing_ok=True)


def git(repo: Path, *args: str) -> str:
    return run(["git", *args], cwd=repo).stdout.strip()


def require_clean_repo(repo: Path) -> None:
    if git(repo, "status", "--porcelain=v1"):
        raise CandidateError("candidate provenance requires a clean source worktree")


def require_commit(repo: Path, value: str, label: str) -> str:
    resolved = git(repo, "rev-parse", f"{value}^{{commit}}")
    if not GIT_SHA_RE.fullmatch(resolved):
        raise CandidateError(f"{label} did not resolve to a full commit SHA")
    return resolved


def require_ancestor(repo: Path, ancestor: str, descendant: str, label: str) -> None:
    result = run(["git", "merge-base", "--is-ancestor", ancestor, descendant], cwd=repo, check=False)
    if result.returncode != 0:
        raise CandidateError(f"{label} {ancestor} is not an ancestor of {descendant}")


def toolchain_identity(repo: Path) -> dict[str, str]:
    rust = run(["rustc", "+1.94.0", "--version"], cwd=repo).stdout.strip()
    cargo = run(["cargo", "+1.94.0", "--version"], cwd=repo).stdout.strip()
    dotslash = run(["dotslash", "--version"], cwd=repo).stdout.strip()
    verbose = run(["rustc", "+1.94.0", "-vV"], cwd=repo).stdout
    host = next((line.split(":", 1)[1].strip() for line in verbose.splitlines() if line.startswith("host:")), "")
    if not host:
        raise CandidateError("rustc did not report a host target")
    machine = platform.machine().lower()
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x86_64"}.get(machine, machine)
    return {
        "rustVersion": rust,
        "cargoVersion": cargo,
        "dotslashVersion": dotslash,
        "targetTriple": host,
        "architecture": architecture,
    }


def binary_architecture(path: Path) -> str:
    output = run(["/usr/bin/file", "-b", str(path)]).stdout.lower()
    if "arm64" in output or "aarch64" in output:
        return "arm64"
    if "x86_64" in output or "x86-64" in output:
        return "x86_64"
    return "unknown"


def observed_cli_build(binary: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="grokbuild-candidate-version-") as directory:
        isolated_root = Path(directory)
        os.chmod(isolated_root, 0o700)
        grok_home = isolated_root / "grok-home"
        grok_home.mkdir(mode=0o700)
        environment = {
            "GROK_HOME": str(grok_home),
            "HOME": str(isolated_root),
            "TMPDIR": str(isolated_root),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
        }
        result = run([str(binary), "--version"], check=False, env=environment)
    combined = "\n".join(part for part in (result.stdout.strip(), result.stderr.strip()) if part)
    if result.returncode != 0:
        raise CandidateError(f"candidate --version failed with status {result.returncode}")
    match = CLI_BUILD_RE.search(combined)
    if not match:
        raise CandidateError("candidate --version did not expose VERSION_WITH_COMMIT")
    return match.group("build")


def signing_identity(binary: Path) -> dict[str, Any]:
    codesign = shutil.which("codesign")
    if codesign is None:
        return {
            "state": "unsupported",
            "strictVerification": False,
            "teamIdentifier": None,
            "designatedRequirement": None,
        }

    display = run([codesign, "-d", "--verbose=4", str(binary)], check=False)
    display_text = "\n".join((display.stdout, display.stderr))
    if display.returncode != 0 and "not signed at all" in display_text.lower():
        return {
            "state": "unsigned",
            "strictVerification": False,
            "teamIdentifier": None,
            "designatedRequirement": None,
        }

    strict = run([codesign, "--verify", "--strict", "--verbose=2", str(binary)], check=False)
    requirement = run([codesign, "-d", "-r-", str(binary)], check=False)
    requirement_text = "\n".join((requirement.stdout, requirement.stderr))
    designated = None
    for line in requirement_text.splitlines():
        if "designated =>" in line:
            designated = line.split("designated =>", 1)[1].strip()
            break
    team_match = re.search(r"^TeamIdentifier=(.+)$", display_text, re.MULTILINE)
    team = team_match.group(1).strip() if team_match else None
    if team is not None and team.lower() in {"not set", "none"}:
        team = None
    signature_match = re.search(r"^Signature=(.+)$", display_text, re.MULTILINE)
    signature = signature_match.group(1).strip().lower() if signature_match else ""
    if strict.returncode == 0 and team and designated:
        state = "signed"
    elif strict.returncode == 0 and signature == "adhoc" and not team:
        state = "adHoc"
    else:
        state = "invalid"
    return {
        "state": state,
        "strictVerification": strict.returncode == 0,
        "teamIdentifier": team,
        "designatedRequirement": designated,
    }


def build_document(
    *,
    repo: Path,
    binary: Path,
    official_base: str,
    replay_base: str,
    require_clean: bool = True,
) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    binary = absolute_path(binary)
    require_private_directory(binary.parent)
    try:
        initial = binary.lstat()
    except FileNotFoundError as exc:
        raise CandidateError("candidate binary does not exist") from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise CandidateError("candidate binary must be a non-symlink regular file")
    if require_clean:
        require_clean_repo(repo)
    if not os.access(binary, os.X_OK):
        raise CandidateError("candidate binary must be an executable regular file")

    source_sha = require_commit(repo, "HEAD", "source")
    official_sha = require_commit(repo, official_base, "official base")
    replay_sha = require_commit(repo, replay_base, "upstream replay base")
    require_ancestor(repo, official_sha, replay_sha, "official base")
    require_ancestor(repo, replay_sha, source_sha, "upstream replay base")

    lockfile = repo / "Cargo.lock"
    source_rev = (repo / "SOURCE_REV").read_text(encoding="utf-8").strip()
    cli_build = observed_cli_build(binary)
    expected_cli_build = f"1.0.5 ({source_sha[:7]})"
    if cli_build != expected_cli_build:
        raise CandidateError(f"candidate cliBuild mismatch: expected {expected_cli_build}, observed {cli_build}")

    toolchain = toolchain_identity(repo)
    binary_arch = binary_architecture(binary)
    if binary_arch != toolchain["architecture"]:
        raise CandidateError(
            f"candidate architecture mismatch: host {toolchain['architecture']}, binary {binary_arch}"
        )

    document = {
        "schemaVersion": SCHEMA_VERSION,
        "source": {
            "officialBaseSHA": official_sha,
            "upstreamReplayBaseSHA": replay_sha,
            "forkSourceSHA": source_sha,
            "sourceRev": source_rev,
            "cargoLockSHA256": sha256_file(lockfile),
        },
        "toolchain": toolchain,
        "build": {
            "command": BUILD_COMMAND,
            "profile": "release-dist",
            "package": "xai-grok-pager-bin",
            "features": ["release-dist"],
        },
        "binary": {
            "artifactName": "xai-grok-pager",
            "sha256": sha256_file(binary),
            "sizeBytes": binary.stat().st_size,
            "architecture": binary_arch,
            "expectedVersionWithCommit": expected_cli_build,
            "expectedACPCLIBuild": expected_cli_build,
            "observedVersionWithCommit": cli_build,
        },
        "signing": signing_identity(binary),
    }
    final = binary.lstat()
    identity = (initial.st_dev, initial.st_ino, initial.st_size)
    final_identity = (final.st_dev, final.st_ino, final.st_size)
    if identity != final_identity or not stat.S_ISREG(final.st_mode):
        raise CandidateError("candidate binary identity changed during inspection")
    return document


def validate_shape(document: dict[str, Any]) -> None:
    if set(document) != EXPECTED_TOP_LEVEL_KEYS:
        raise CandidateError("manifest top-level keys do not match schema v1")
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise CandidateError("unsupported candidate provenance schema version")
    source = document.get("source")
    if not isinstance(source, dict) or set(source) != {
        "officialBaseSHA",
        "upstreamReplayBaseSHA",
        "forkSourceSHA",
        "sourceRev",
        "cargoLockSHA256",
    }:
        raise CandidateError("manifest source fields do not match schema v1")
    for key in ("officialBaseSHA", "upstreamReplayBaseSHA", "forkSourceSHA"):
        if not isinstance(source[key], str) or not GIT_SHA_RE.fullmatch(source[key]):
            raise CandidateError(f"invalid {key}")
    if not isinstance(source["cargoLockSHA256"], str) or not SHA256_RE.fullmatch(source["cargoLockSHA256"]):
        raise CandidateError("invalid cargoLockSHA256")
    if not isinstance(source["sourceRev"], str) or not source["sourceRev"]:
        raise CandidateError("invalid sourceRev")

    toolchain = document.get("toolchain")
    if not isinstance(toolchain, dict) or set(toolchain) != {
        "rustVersion",
        "cargoVersion",
        "dotslashVersion",
        "targetTriple",
        "architecture",
    }:
        raise CandidateError("manifest toolchain fields do not match schema v1")
    if not all(isinstance(toolchain[key], str) and toolchain[key] for key in toolchain):
        raise CandidateError("manifest toolchain fields must be non-empty strings")

    build = document.get("build")
    if not isinstance(build, dict) or set(build) != {"command", "profile", "package", "features"}:
        raise CandidateError("manifest build fields do not match schema v1")
    if build["command"] != BUILD_COMMAND:
        raise CandidateError("manifest build command is not the frozen release-dist command")
    if build["profile"] != "release-dist" or build["package"] != "xai-grok-pager-bin":
        raise CandidateError("manifest build target is not frozen")
    if build["features"] != ["release-dist"]:
        raise CandidateError("manifest release-dist feature is missing or widened")

    binary = document.get("binary")
    if not isinstance(binary, dict) or set(binary) != {
        "artifactName",
        "sha256",
        "sizeBytes",
        "architecture",
        "expectedVersionWithCommit",
        "expectedACPCLIBuild",
        "observedVersionWithCommit",
    }:
        raise CandidateError("manifest binary fields do not match schema v1")
    if binary["artifactName"] != "xai-grok-pager":
        raise CandidateError("unexpected candidate artifact name")
    if not isinstance(binary["sha256"], str) or not SHA256_RE.fullmatch(binary["sha256"]):
        raise CandidateError("invalid candidate binary SHA-256")
    if not isinstance(binary["sizeBytes"], int) or binary["sizeBytes"] <= 0:
        raise CandidateError("invalid candidate binary size")
    expected_build = f"1.0.5 ({source['forkSourceSHA'][:7]})"
    if binary["expectedVersionWithCommit"] != expected_build or binary["expectedACPCLIBuild"] != expected_build:
        raise CandidateError("candidate build string does not match fork source")
    if binary["observedVersionWithCommit"] != expected_build:
        raise CandidateError("observed VERSION_WITH_COMMIT does not match the fork source")

    signing = document.get("signing")
    if not isinstance(signing, dict) or set(signing) != {
        "state",
        "strictVerification",
        "teamIdentifier",
        "designatedRequirement",
    }:
        raise CandidateError("manifest signing fields do not match schema v1")
    if signing["state"] not in {"unsigned", "adHoc", "signed", "unsupported"}:
        raise CandidateError("invalid candidate signing state")
    if not isinstance(signing["strictVerification"], bool):
        raise CandidateError("invalid strict signing verification state")
    if signing["state"] == "signed":
        if signing["strictVerification"] is not True:
            raise CandidateError("signed candidate did not pass strict verification")
        if not isinstance(signing["teamIdentifier"], str) or not signing["teamIdentifier"]:
            raise CandidateError("signed candidate is missing Team Identifier")
        if not isinstance(signing["designatedRequirement"], str) or not signing["designatedRequirement"]:
            raise CandidateError("signed candidate is missing designated requirement")
    elif signing["state"] == "adHoc":
        if signing["strictVerification"] is not True or signing["teamIdentifier"] is not None:
            raise CandidateError("ad-hoc candidate signing claim is inconsistent")
        if signing["designatedRequirement"] is not None and not isinstance(
            signing["designatedRequirement"], str
        ):
            raise CandidateError("ad-hoc designated requirement is invalid")
    elif any(signing[key] is not None for key in ("teamIdentifier", "designatedRequirement")):
        raise CandidateError("unsigned/unsupported candidate cannot claim signing identity")


def verify_manifest(
    *,
    repo: Path,
    binary: Path,
    manifest: Path,
    official_base: str,
    replay_base: str,
    require_clean: bool = True,
) -> dict[str, Any]:
    manifest = absolute_path(manifest)
    require_private_directory(manifest.parent)
    try:
        metadata = manifest.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise CandidateError("candidate manifest must be a non-symlink regular file")
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CandidateError("candidate manifest must be owner-private")
        if metadata.st_nlink != 1:
            raise CandidateError("candidate manifest must have exactly one filesystem link")
        if metadata.st_size > 1024 * 1024:
            raise CandidateError("candidate manifest exceeds the 1 MiB limit")
        flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
        fd = os.open(manifest, flags)
        try:
            chunks: list[bytes] = []
            remaining = 1024 * 1024 + 1
            while remaining:
                chunk = os.read(fd, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            final = os.fstat(fd)
        finally:
            os.close(fd)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            final.st_dev,
            final.st_ino,
            final.st_size,
        ):
            raise CandidateError("candidate manifest changed during inspection")
        document = json.loads(payload.decode("utf-8"))
    except CandidateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateError(f"cannot read candidate manifest: {exc}") from exc
    if not isinstance(document, dict):
        raise CandidateError("candidate manifest must be a JSON object")
    validate_shape(document)
    expected = build_document(
        repo=repo,
        binary=binary,
        official_base=official_base,
        replay_base=replay_base,
        require_clean=require_clean,
    )
    if canonical_bytes(document) != canonical_bytes(expected):
        raise CandidateError("candidate manifest does not match current source, toolchain, binary, or signing identity")
    return document


def command_inspect(args: argparse.Namespace) -> None:
    document = build_document(
        repo=args.repo,
        binary=args.binary,
        official_base=args.official_base,
        replay_base=args.replay_base,
        require_clean=not args.allow_dirty,
    )
    validate_shape(document)
    write_private(args.output, canonical_bytes(document))


def command_verify(args: argparse.Namespace) -> None:
    verify_manifest(
        repo=args.repo,
        binary=args.binary,
        manifest=args.manifest,
        official_base=args.official_base,
        replay_base=args.replay_base,
        require_clean=not args.allow_dirty,
    )


def command_prepare_directory(args: argparse.Namespace) -> None:
    prepare_private_directory(args.directory, must_not_exist=args.must_not_exist)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)
    for name, function in (("inspect", command_inspect), ("verify", command_verify)):
        command = subparsers.add_parser(name)
        command.add_argument("--repo", type=Path, required=True)
        command.add_argument("--binary", type=Path, required=True)
        command.add_argument("--official-base", required=True)
        command.add_argument("--replay-base", required=True)
        command.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
        if name == "inspect":
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--manifest", type=Path, required=True)
        command.set_defaults(function=function)
    prepare = subparsers.add_parser("prepare-directory")
    prepare.add_argument("--directory", type=Path, required=True)
    prepare.add_argument("--must-not-exist", action="store_true")
    prepare.set_defaults(function=command_prepare_directory)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.function(args)
    except CandidateError as exc:
        print(f"candidate provenance refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
