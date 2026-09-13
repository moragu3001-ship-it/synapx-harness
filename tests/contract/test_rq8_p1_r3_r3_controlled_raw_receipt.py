"""RQ8-P1-R3-R3 Phase B pre-repair RED tests -- raw CommandResult receipt truth.

These tests pin RQ8-P1-R3-R3 §B. The sealed ``red_observation_receipt`` MUST
be a bounded projection of the actual controlled ``CommandResult`` -- not a
hybrid of CommandResult identity plus decode/re-encode observation
metadata.

Pre-repair (HEAD 95431b37), tests FAIL because:

  * ``CommandResult.stdout_path`` is a placeholder (``/tmp/command_...``) and
    is NOT the actual persisted file. The runner never writes the raw
    subprocess bytes anywhere.
  * ``_observe_red_state`` round-trips the raw bytes through
    ``stdout_text.encode("utf-8")`` (``decode("utf-8", "replace")`` then
    re-encode) before writing to the artifact directory. Bytes that were
    invalid UTF-8 in the subprocess output are corrupted in the persisted
    file.
  * ``_receipt_to_json_dict`` projects ``observation.stdout_ref`` /
    ``observation.stdout_sha256`` / ``observation.stdout_size_bytes`` --
    none of which come from the controlled ``CommandResult`` that produced
    the observation.

Post-repair, every test PASSES because:

  * ``run_controlled`` accepts a bounded ``artifact_dir: Path | None`` kwarg.
    When provided, the runner persists the raw subprocess bytes to
    ``<artifact_dir>/stdout.log`` and ``<artifact_dir>/stderr.log`` and
    computes the receipt's path/sha/size from the persisted file. The
    receipt is the authoritative artifact truth.
  * ``RedObservation`` binds ``stdout_ref``/``stdout_sha256``/
    ``stdout_size_bytes`` (and stderr counterparts) directly from the
    controlled receipt -- no re-computation, no re-encoding.
  * ``_receipt_to_json_dict`` projects the bounded identity fields from
    the controlled receipt; the sealed envelope shares the same identity.
"""
from __future__ import annotations

import hashlib
import json
import sys
import textwrap
from pathlib import Path

from synapx_harness.evidence.command_runner import (
    CommandResult,
    run_controlled,
)
from synapx_harness.kernel.governed_execution import (
    GovernedExecutionRequest,
    _fixture_root_sha,
    run_governed_execution,
)
from synapx_harness.kernel.mutation_proposal_contract import (
    PROPOSAL_BEGIN,
    PROPOSAL_END,
)

CALC_BROKEN = "def add(a, b):\n    return a + b\n"

CALC_FIXED = (
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "\n"
    "def subtract(a, b):\n"
    "    return a - b\n"
)

CALC_TEST = textwrap.dedent(
    """\
    import calculator


    def test_add():
        assert calculator.add(2, 3) == 5


    def test_subtract():
        assert calculator.subtract(5, 3) == 2
    """
)

CALC_TASK = (
    "Fix the subtract regression.\n"
    "\n"
    "Allowed write paths:\n"
    "- calculator.py\n"
    "\n"
    "Do not modify unrelated files.\n"
    "Run the repository's authoritative tests and only complete "
    "if verification passes.\n"
)

CALC_FAILED_IDS = ["tests/test_calculator.py::test_subtract"]
VERIFICATION_COMMAND = [sys.executable, "-m", "pytest", "-q"]
EXPECTATION_FILENAME = ".synapx_red_expectation.json"


def _fp(command: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(command, separators=(",", ":"), ensure_ascii=True).encode(
            "utf-8"
        )
    ).hexdigest()


def _write_calc_repo(root: Path, *, broken: bool) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "calculator.py").write_text(
        CALC_BROKEN if broken else CALC_FIXED, encoding="utf-8"
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "__init__.py").write_text("", encoding="utf-8")
    (tests_dir / "test_calculator.py").write_text(CALC_TEST, encoding="utf-8")
    return root


def _stage_expectation(
    repo: Path,
    *,
    revision: str | None = None,
    fingerprint: str | None = None,
    failed_ids: list[str] | None = None,
) -> Path:
    path = repo / EXPECTATION_FILENAME
    payload: dict[str, object] = {
        "expectation_id": "test/r3r3/expectation/v1",
        "expectation_version": 1,
        "status": "QUALIFIED",
        "source_type": "BENCHMARK_FIXTURE",
        "source_revision": (
            revision if revision is not None else _fixture_root_sha(repo)
        ),
        "verification_command_fingerprint": fingerprint or "",
        "expected_exit_code": 1,
        "match_rule": "EXACT_FAILED_TEST_IDS",
        "required_failed_test_ids": (
            list(CALC_FAILED_IDS) if failed_ids is None else list(failed_ids)
        ),
        "provenance": {"source_ref": "test", "source_sha256": "a" * 64},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _proposal(old: str, new: str, path: str = "calculator.py") -> str:
    return (
        f"{PROPOSAL_BEGIN}\n"
        f"FILE: {path}\n"
        f"<<<< OLD\n"
        f"{old}\n"
        f">>>> OLD\n"
        f"<<<< NEW\n"
        f"{new}\n"
        f">>>> NEW\n"
        f"{PROPOSAL_END}\n"
    )


def _run(repo: Path, *, proposal: str):
    return run_governed_execution(
        GovernedExecutionRequest(
            workspace_root=repo,
            task=CALC_TASK,
            verification_command=list(VERIFICATION_COMMAND),
            codex_stdout_override=proposal,
        )
    )


# ---------------------------------------------------------------------------
# B1 -- run_controlled bounded artifact_dir extension
# ---------------------------------------------------------------------------


class TestRunControlledArtifactDir:
    def test_artifact_dir_persists_raw_subprocess_bytes(
        self, tmp_path: Path
    ) -> None:
        """When ``artifact_dir`` is provided, ``run_controlled`` MUST
        persist the raw subprocess stdout/stderr bytes to
        ``<artifact_dir>/stdout.log`` and ``<artifact_dir>/stderr.log``.
        The disk files MUST contain the bytes the subprocess emitted,
        not a decode/re-encode-of-text round trip."""
        artifact_dir = tmp_path / "artifacts"
        artifact_dir.mkdir()
        # The WorkContract scope must include the actual executable token
        # so the controlled-runner tool gate accepts it. The first token
        # of the shell command is the python executable's full path; we
        # pass it verbatim so the case-sensitive string comparison in
        # ``_extract_scope_tools`` matches ``command.strip().split()[0]``.
        python_token = sys.executable
        wc = {
            "work_contract_id": "wc-art",
            "risk_class": "R0",
            "issuer": "HARNESS_CORE_ADMISSION",
            "scope": [
                "phase:public_governed",
                f"tool:{python_token}",
                f"path:{tmp_path.as_posix()}",
            ],
        }
        # ``python -c`` writes 5 valid bytes (b'hello') then a single
        # invalid UTF-8 sequence (0xFF 0xFE). The decode/re-encode round
        # trip replaces 0xFF 0xFE with U+FFFD (3 bytes) and corrupts the
        # artifact.
        cmd = (
            f"{sys.executable} -c "
            "\"import sys; sys.stdout.buffer.write(b'hello\\xff\\xfe\\n'); "
            "sys.stderr.buffer.write(b'err\\xff\\xff\\n')\""
        )
        receipt: CommandResult = run_controlled(
            cmd,
            wc,
            cwd=tmp_path,
            timeout=30,
            artifact_dir=artifact_dir,
        )

        # Receipt identity MUST point to the persisted files.
        expected_stdout_path = (artifact_dir / "stdout.log").as_posix()
        expected_stderr_path = (artifact_dir / "stderr.log").as_posix()
        assert receipt.stdout_path == expected_stdout_path, (
            "B1: receipt.stdout_path must equal the persisted artifact path"
        )
        assert receipt.stderr_path == expected_stderr_path, (
            "B1: receipt.stderr_path must equal the persisted artifact path"
        )
        assert (artifact_dir / "stdout.log").is_file()
        assert (artifact_dir / "stderr.log").is_file()

        # Persisted bytes MUST equal the raw subprocess output (not a
        # decode/re-encode round trip).
        expected_stdout = b"hello\xff\xfe\n"
        expected_stderr = b"err\xff\xff\n"
        assert (artifact_dir / "stdout.log").read_bytes() == expected_stdout, (
            "B1: persisted stdout is not the raw subprocess bytes "
            "(decode/re-encode round trip detected)"
        )
        assert (artifact_dir / "stderr.log").read_bytes() == expected_stderr, (
            "B1: persisted stderr is not the raw subprocess bytes "
            "(decode/re-encode round trip detected)"
        )

        # Receipt SHA / size MUST equal the persisted file (not a
        # round-trip recomputation).
        assert receipt.stdout_sha256 == hashlib.sha256(expected_stdout).hexdigest()
        assert receipt.stdout_size == len(expected_stdout)
        assert receipt.stderr_sha256 == hashlib.sha256(expected_stderr).hexdigest()
        assert receipt.stderr_size == len(expected_stderr)

    def test_artifact_dir_omitted_keeps_legacy_path_shape(
        self, tmp_path: Path
    ) -> None:
        """When ``artifact_dir`` is None, the receipt shape is unchanged
        (legacy ``/tmp/command_...`` placeholder path). No artifact
        directory is created."""
        python_token = sys.executable
        wc = {
            "work_contract_id": "wc-legacy",
            "risk_class": "R0",
            "issuer": "HARNESS_CORE_ADMISSION",
            "scope": [
                "phase:public_governed",
                f"tool:{python_token}",
                f"path:{tmp_path.as_posix()}",
            ],
        }
        cmd = f"{sys.executable} -c \"import sys; sys.stdout.write('hi')\""
        receipt = run_controlled(
            cmd, wc, cwd=tmp_path, timeout=30, artifact_dir=None
        )
        assert receipt.stdout_path.startswith("/tmp/command_"), (
            "B1: omitting artifact_dir must keep the legacy placeholder path"
        )

    def test_artifact_dir_recomputes_sha_from_disk(
        self, tmp_path: Path
    ) -> None:
        """The receipt's stdout_sha256 / stderr_sha256 / size fields MUST
        be derived from the persisted file (authoritative artifact),
        not from an in-memory ``stdout_data`` that may be discarded."""
        artifact_dir = tmp_path / "artifacts2"
        artifact_dir.mkdir()
        python_token = sys.executable
        wc = {
            "work_contract_id": "wc-sha",
            "risk_class": "R0",
            "issuer": "HARNESS_CORE_ADMISSION",
            "scope": [
                "phase:public_governed",
                f"tool:{python_token}",
                f"path:{tmp_path.as_posix()}",
            ],
        }
        cmd = f"{sys.executable} -c \"import sys; sys.stdout.write('12345')\""
        receipt = run_controlled(
            cmd, wc, cwd=tmp_path, timeout=30, artifact_dir=artifact_dir
        )
        on_disk = (artifact_dir / "stdout.log").read_bytes()
        assert receipt.stdout_sha256 == hashlib.sha256(on_disk).hexdigest()
        assert receipt.stdout_size == len(on_disk)


# ---------------------------------------------------------------------------
# B2 -- RedObservation binding is the controlled CommandResult, not a copy
# ---------------------------------------------------------------------------


class TestRedObservationBoundToControlledReceipt:
    def test_observation_refs_equal_receipt_refs(
        self, tmp_path: Path
    ) -> None:
        """RedObservation.stdout_ref / stderr_ref MUST equal the actual
        controlled receipt.stdout_path / receipt.stderr_path (one
        identity). RedObservation.stdout_sha256 / stderr_sha256 /
        stdout_size_bytes / stderr_size_bytes MUST equal the receipt
        fields directly -- no re-hash, no re-computation."""
        repo = _write_calc_repo(tmp_path / "obs", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        # We can only inspect the receipt via the sealed envelope projection.
        sealed_recv = result.sealed_evidence.get("red_observation_receipt")
        assert isinstance(sealed_recv, dict)
        stdout_art = sealed_recv.get("stdout_artifact")
        stderr_art = sealed_recv.get("stderr_artifact")
        assert isinstance(stdout_art, dict)
        assert isinstance(stderr_art, dict)

        # The sealed stdout ref must be a real on-disk path with content.
        stdout_ref = stdout_art.get("ref")
        stderr_ref = stderr_art.get("ref")
        assert isinstance(stdout_ref, str) and stdout_ref
        assert isinstance(stderr_ref, str) and stderr_ref
        assert Path(stdout_ref).is_file()
        assert Path(stderr_ref).is_file()

        # SHA + size in the sealed envelope MUST equal the persisted file.
        stdout_bytes = Path(stdout_ref).read_bytes()
        stderr_bytes = Path(stderr_ref).read_bytes()
        assert stdout_art.get("sha256") == hashlib.sha256(stdout_bytes).hexdigest()
        assert stdout_art.get("size_bytes") == len(stdout_bytes)
        assert stderr_art.get("sha256") == hashlib.sha256(stderr_bytes).hexdigest()
        assert stderr_art.get("size_bytes") == len(stderr_bytes)

        # The receipt itself (via CommandResult identity) MUST match the
        # sealed envelope -- command_id and exit_code at minimum.
        evidence = result.red_qualification_evidence
        assert evidence is not None
        assert sealed_recv.get("command_id") == evidence.command_receipt_id


# ---------------------------------------------------------------------------
# B3 -- sealed envelope projection equals controlled receipt
# ---------------------------------------------------------------------------


class TestSealedReceiptEqualsControlledReceipt:
    def test_sealed_envelope_carries_receipt_command_id(
        self, tmp_path: Path
    ) -> None:
        """The sealed envelope's red_observation_receipt MUST carry the
        SAME command_id as the qualification evidence's command_receipt_id
        (no replay, no recomputation)."""
        repo = _write_calc_repo(tmp_path / "env", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        evidence = result.red_qualification_evidence
        sealed_recv = result.sealed_evidence.get("red_observation_receipt")
        assert isinstance(sealed_recv, dict)
        assert sealed_recv.get("command_id") == evidence.command_receipt_id

    def test_sealed_envelope_artifacts_match_disk_after_fix(
        self, tmp_path: Path
    ) -> None:
        """The sealed envelope's stdout_artifact.sha256 / size_bytes
        MUST match the persisted file's bytes (artifact byte test).
        Same for stderr."""
        repo = _write_calc_repo(tmp_path / "disk", broken=True)
        _stage_expectation(repo, fingerprint=_fp(VERIFICATION_COMMAND))
        result = _run(repo, proposal=_proposal(CALC_BROKEN, CALC_FIXED))

        sealed_recv = result.sealed_evidence.get("red_observation_receipt")
        assert isinstance(sealed_recv, dict)
        for stream in ("stdout_artifact", "stderr_artifact"):
            artifact = sealed_recv.get(stream)
            assert isinstance(artifact, dict), f"missing {stream}"
            ref = artifact.get("ref")
            assert isinstance(ref, str) and ref
            data = Path(ref).read_bytes()
            assert (
                hashlib.sha256(data).hexdigest() == artifact.get("sha256")
            ), f"B3: {stream} sha does not match persisted file"
            assert artifact.get("size_bytes") == len(data), (
                f"B3: {stream} size_bytes does not match persisted file"
            )
