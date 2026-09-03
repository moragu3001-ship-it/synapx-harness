"""Lane D / R1 — Codex Adapter contract tests (RED + NEG + GREEN + R1-RED).

RED-D-*   : conditions that MUST be REJECTED / MUST NOT be promoted.
NEG-D-*   : negative-authority guards (status never inferred from strings,
            late DONE after cancel/timeout preserves the stronger authority).
R1-RED-*  : R1 boundary repairs (identity composition, interface truth,
            fake leak, bounded capture, cancellation fail-closed, probe truth,
            SHA-256 truth, provider-neutral naming).
GREEN-*   : happy-path behavior through the deterministic FakeCodexRuntime.

A real bounded Codex probe (A6/R1-07) lives in ``test_real_codex_probe`` and is
skipped unless ``LANE_D_REAL_PROBE=1`` is set, so the suite never depends on
external auth/network.
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import threading
import time

import pytest
from pydantic import ValidationError

from synapx_harness.adapters.codex import (
    INTERACTIVE_TUI_AUTHORITATIVE,
    SELECTED_INTERFACE,
    AgentExecutionContext,
    AgentInvocation,
    AgentLimits,
    AgentOutput,
    AgentRequest,
    AgentResult,
    AgentStatus,
    AgentTask,
    AgentWorkspace,
    CodexAdapter,
    CodexInterface,
    FakeCodexRuntime,
    FakeScenario,
)
from synapx_harness.adapters.codex.models import ProviderMeta
from synapx_harness.adapters.codex.runtime import (
    RawRuntimeResult,
    RuntimeInvocation,
    SubprocessCodexRuntime,
    build_invocation,
    classify_probe_outcome,
)
from synapx_harness.contracts.runtime_models import ExecutionIdentity


def _request(**overrides: object) -> AgentRequest:
    base: dict[str, object] = dict(
        execution_identity=AgentExecutionContext(
            execution_identity=ExecutionIdentity(
                job_id="job-1",
                task_id="task-1",
                root_task_id="root-1",
                attempt_id="attempt-1",
            ),
            agent_session_id="synapx-sess-1",
        ),
        workspace=AgentWorkspace(root="/tmp/ws"),
        task=AgentTask(instruction="summarize this repo"),
        limits=AgentLimits(timeout_seconds=30),
        invocation=AgentInvocation(provider="codex", model="gpt-5-codex"),
    )
    base.update(overrides)
    return AgentRequest(**base)  # type: ignore[arg-type]


def _fake_adapter(scenario: FakeScenario, **kw: object) -> CodexAdapter:
    return CodexAdapter(backend=FakeCodexRuntime(scenario=scenario, **kw))  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# RED-D-01: Codex DONE must NOT auto-promote to SynapX COMPLETED
# --------------------------------------------------------------------------
def test_red_d01_done_is_not_completed():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    result = adapter.execute(_request())
    assert result.status == AgentStatus.DONE
    assert str(result.status) != "COMPLETED"
    assert "COMPLETED" not in str(AgentStatus.DONE)
    assert not hasattr(result, "terminal_decision")
    assert "terminal" not in result.model_dump().keys()


# --------------------------------------------------------------------------
# RED-D-02/03/04: missing required Core identity fields -> REJECT
# --------------------------------------------------------------------------
@pytest.mark.parametrize("missing", ["job_id", "task_id", "attempt_id", "root_task_id"])
def test_red_d02_d04_missing_core_identity_rejected(missing: str):
    ident = dict(job_id="job-1", task_id="task-1", root_task_id="root-1", attempt_id="attempt-1")
    ident.pop(missing)
    with pytest.raises(ValidationError):
        AgentRequest(
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(**ident),  # type: ignore[arg-type]
                agent_session_id="synapx-sess-1",
            ),
            workspace=AgentWorkspace(root="/tmp/ws"),
            task=AgentTask(instruction="x"),
            limits=AgentLimits(timeout_seconds=30),
            invocation=AgentInvocation(provider="codex", model="m"),
        )


# --------------------------------------------------------------------------
# RED-D-05: agent_session_id must be owned BEFORE invocation (never minted)
# --------------------------------------------------------------------------
def test_red_d05_adapter_never_mints_session_id():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    assert not hasattr(adapter, "allocate_agent_session_id")
    assert not hasattr(adapter, "create_session_id")
    with pytest.raises(ValidationError):
        AgentRequest(
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(
                    job_id="job-1", task_id="task-1", root_task_id="root-1", attempt_id="attempt-1"
                ),
                # agent_session_id omitted -> required
            ),  # type: ignore[call-arg]
            workspace=AgentWorkspace(root="/tmp/ws"),
            task=AgentTask(instruction="x"),
            limits=AgentLimits(timeout_seconds=30),
            invocation=AgentInvocation(provider="codex", model="m"),
        )


# --------------------------------------------------------------------------
# RED-D-06/07/08: non-zero / timeout / cancel must NOT normalize to DONE
# --------------------------------------------------------------------------
def test_red_d06_nonzero_not_done():
    result = _fake_adapter(FakeScenario.FAILURE, exit_code=3).execute(_request())
    assert result.status == AgentStatus.FAILED
    assert result.status != AgentStatus.DONE


def test_red_d07_timeout_not_done():
    result = _fake_adapter(FakeScenario.TIMEOUT).execute(_request())
    assert result.status == AgentStatus.TIMEOUT
    assert result.status != AgentStatus.DONE


def test_red_d08_cancel_not_done():
    result = _fake_adapter(FakeScenario.CANCEL).execute(_request())
    assert result.status == AgentStatus.CANCELLED
    assert result.status != AgentStatus.DONE


# --------------------------------------------------------------------------
# RED-D-09: Codex-specific object must not leak into the contract
# --------------------------------------------------------------------------
def test_red_d09_codex_object_leak_rejected():
    class _CodexRawSession:
        session_id = "codex-internal-xyz"

    with pytest.raises(ValidationError):
        AgentResult(
            status=AgentStatus.DONE,
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(
                    job_id="j", task_id="t", root_task_id="r", attempt_id="a"
                ),
                agent_session_id="s",
            ),
            provider=ProviderMeta(name="codex", model="m"),
            output=_CodexRawSession(),  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------
# RED-D-10: interactive TUI scraping is NOT an authoritative adapter
# --------------------------------------------------------------------------
def test_red_d10_interactive_tui_rejected():
    with pytest.raises(ValueError):
        CodexAdapter(interface=CodexInterface.INTERACTIVE_TUI)
    assert SELECTED_INTERFACE == CodexInterface.OFFICIAL_HEADLESS_CLI
    assert INTERACTIVE_TUI_AUTHORITATIVE is False


# --------------------------------------------------------------------------
# NEG-D-01: provider_session_id must stay distinct from agent_session_id
# --------------------------------------------------------------------------
def test_neg_d01_session_identity_collision_rejected():
    with pytest.raises(ValidationError):
        AgentResult.model_validate(
            {
                "status": AgentStatus.DONE,
                "execution_identity": AgentExecutionContext(
                    execution_identity=ExecutionIdentity(
                        job_id="j", task_id="t", root_task_id="r", attempt_id="a"
                    ),
                    agent_session_id="same-id",
                ),
                "provider": ProviderMeta(
                    name="codex", model="m", provider_session_id="same-id"
                ),
                "output": AgentOutput(stdout="", stderr=""),
            }
        )


def test_neg_d01_backend_collision_rejected():
    backend = FakeCodexRuntime(
        scenario=FakeScenario.SUCCESS, provider_session_id="synapx-sess-1"
    )
    adapter = CodexAdapter(backend=backend)
    with pytest.raises(ValueError):
        adapter.execute(_request())


# --------------------------------------------------------------------------
# NEG-D-02: "success" in stdout alone must not force DONE on failure
# --------------------------------------------------------------------------
def test_neg_d02_success_string_with_nonzero_failed():
    result = _fake_adapter(
        FakeScenario.FAILURE, exit_code=1, stdout="everything success!"
    ).execute(_request())
    assert result.status == AgentStatus.FAILED
    assert result.status != AgentStatus.DONE


# --------------------------------------------------------------------------
# NEG-D-03: stderr presence alone must not force FAILED
# --------------------------------------------------------------------------
def test_neg_d03_stderr_present_but_done():
    result = _fake_adapter(
        FakeScenario.SUCCESS, stdout="ok", stderr="warn: something"
    ).execute(_request())
    assert result.status == AgentStatus.DONE


# --------------------------------------------------------------------------
# NEG-D-04: timeout + late success must keep TIMEOUT authority
# --------------------------------------------------------------------------
def test_neg_d04_timeout_late_success_keeps_timeout():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    raw = RawRuntimeResult(
        exit_code=0, stdout="late", stderr="", duration_ms=10, timed_out=True
    )
    result = adapter._normalize(raw, _request(), cancel_requested=False)
    assert result.status == AgentStatus.TIMEOUT


# --------------------------------------------------------------------------
# NEG-D-05: cancellation authority (confirmed vs unconfirmed)
# --------------------------------------------------------------------------
def test_neg_d05_confirmed_cancel_late_done_not_done():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    raw = RawRuntimeResult(
        exit_code=0, stdout="late", stderr="", duration_ms=10, cancelled=True
    )
    result = adapter._normalize(raw, _request(), cancel_requested=False)
    assert result.status == AgentStatus.CANCELLED
    assert result.status != AgentStatus.DONE


def test_neg_d05_unconfirmed_cancel_is_failed_not_cancelled():
    # cancel requested before execution, runtime returns a normal DONE, but
    # cancellation was NOT confirmed by the runtime -> fail-closed FAILED.
    adapter = CodexAdapter(backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    result = adapter.execute(_request())
    assert result.status == AgentStatus.FAILED
    assert result.status != AgentStatus.CANCELLED
    assert result.cancellation_uncertain is True


def test_cancel_race_confirmed_cancelled():
    # Concurrency-safe deterministic race: cancel fires during execute().
    adapter = CodexAdapter(
        backend=FakeCodexRuntime(scenario=FakeScenario.CANCEL_RACE, race_window=2.0)
    )
    holder: list[AgentResult | None] = [None]

    def run() -> None:
        holder[0] = adapter.execute(_request())

    t = threading.Thread(target=run)
    t.start()
    time.sleep(0.2)
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    t.join(timeout=10)
    result = holder[0]
    assert result is not None
    assert result.status == AgentStatus.CANCELLED


# --------------------------------------------------------------------------
# NEG-D-06: credentials in stdout/stderr must be redacted
# --------------------------------------------------------------------------
def test_neg_d06_secret_redaction():
    secret = "sk-abcdef1234567890SECRETKEY"
    result = _fake_adapter(
        FakeScenario.SUCCESS, stdout=f"here is your key {secret}", stderr=""
    ).execute(_request())
    assert secret not in result.output.stdout
    assert "[REDACTED]" in result.output.stdout


# --------------------------------------------------------------------------
# NEG-D-07 missing provider/model fingerprint -> REJECT
# --------------------------------------------------------------------------
def test_neg_d07_missing_model_fingerprint_rejected():
    with pytest.raises(ValidationError):
        AgentRequest(
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(
                    job_id="j", task_id="t", root_task_id="r", attempt_id="a"
                ),
                agent_session_id="s",
            ),
            workspace=AgentWorkspace(root="/tmp/ws"),
            task=AgentTask(instruction="x"),
            limits=AgentLimits(timeout_seconds=30),
            invocation=AgentInvocation(provider="codex", model=""),
        )


# --------------------------------------------------------------------------
# NEG-D-08: Codex DONE must not bypass Verification
# --------------------------------------------------------------------------
def test_neg_d08_done_does_not_bypass_verification():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    result = adapter.execute(_request())
    assert result.status == AgentStatus.DONE
    assert str(AgentStatus.DONE) != "PASS"
    assert not hasattr(adapter, "verify")


# --------------------------------------------------------------------------
# GREEN: happy-path + identity preservation + provider metadata
# --------------------------------------------------------------------------
def test_green_success_preserves_identity_and_provider():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    req = _request()
    result = adapter.execute(req)
    assert result.status == AgentStatus.DONE
    assert result.execution_identity.execution_identity.job_id == "job-1"
    assert result.execution_identity.agent_session_id == "synapx-sess-1"
    assert result.provider.name == "codex"
    assert result.provider.model == "gpt-5-codex"
    assert result.process is not None and result.process.exit_code == 0
    assert result.failure is None


def test_green_launch_error_normalized():
    result = _fake_adapter(FakeScenario.LAUNCH_ERROR).execute(_request())
    assert result.status == AgentStatus.FAILED
    assert result.failure is not None
    assert result.failure.category.value == "LAUNCH_ERROR"


def test_green_malformed_output_normalized():
    result = _fake_adapter(FakeScenario.MALFORMED_OUTPUT, stdout="\x00\x01").execute(
        _request()
    )
    assert result.status == AgentStatus.FAILED
    assert result.failure is not None
    assert result.failure.category.value == "MALFORMED_OUTPUT"


def test_green_cancel_signal_flow():
    adapter = CodexAdapter(backend=FakeCodexRuntime(scenario=FakeScenario.CANCEL))
    ok = adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    assert ok is True
    result = adapter.execute(_request())
    assert result.status == AgentStatus.CANCELLED


def test_green_bounded_capture_within_limit():
    req = _request(
        limits=AgentLimits(timeout_seconds=30, max_stdout_bytes=100, max_stderr_bytes=100)
    )
    result = _fake_adapter(FakeScenario.SUCCESS, stdout="x" * 50, stderr="y" * 40).execute(req)
    assert result.output.truncated is False
    assert result.output.stdout_original_bytes == 50
    assert result.output.stdout_captured_bytes == 50
    assert result.output.stderr_original_bytes == 40


# --------------------------------------------------------------------------
# R1-RED-01: Core ExecutionIdentity lineage must not be weakened
# --------------------------------------------------------------------------
def test_r1_red01_core_identity_lineage_required():
    with pytest.raises(ValidationError):
        AgentExecutionContext.model_validate(
            {
                "execution_identity": ExecutionIdentity.model_validate(
                    {"job_id": "j", "task_id": "t", "attempt_id": "a"}  # no root_task_id
                ),
                "agent_session_id": "s",
            }
        )


# --------------------------------------------------------------------------
# R1-RED-02: OFFICIAL_SDK_API must be rejected (no SDK backend)
# --------------------------------------------------------------------------
def test_r1_red02_sdk_api_rejected():
    with pytest.raises(ValueError):
        CodexAdapter(interface=CodexInterface.OFFICIAL_SDK_API)


# --------------------------------------------------------------------------
# R1-RED-03: FakeScenario must not leak into production capabilities
# --------------------------------------------------------------------------
def test_r1_red03_fake_capability_not_leaked():
    caps = CodexAdapter().capabilities()
    assert "scenarios_supported" not in caps
    for forbidden in ("SUCCESS", "FAILURE", "TIMEOUT", "CANCEL", "MALFORMED_OUTPUT"):
        assert forbidden not in caps
    assert caps["interface"] == "OFFICIAL_HEADLESS_CLI"
    assert set(caps["supports"].keys()) == {
        "prompt",
        "stdin",
        "cwd",
        "model_selection",
        "timeout",
        "cancel",
    }


# --------------------------------------------------------------------------
# R1-RED-04/05: bounded capture truncation at limit + 1
# --------------------------------------------------------------------------
def test_r1_red04_stdout_limit_plus_one_truncated():
    req = _request(
        limits=AgentLimits(timeout_seconds=30, max_stdout_bytes=10, max_stderr_bytes=1000)
    )
    result = _fake_adapter(FakeScenario.SUCCESS, stdout="x" * 11).execute(req)
    assert result.output.truncated is True
    assert result.output.stdout_captured_bytes == 10
    assert result.output.stdout_original_bytes == 11
    assert len(result.output.stdout) == 10


def test_r1_red05_stderr_limit_plus_one_truncated():
    req = _request(
        limits=AgentLimits(timeout_seconds=30, max_stdout_bytes=1000, max_stderr_bytes=10)
    )
    result = _fake_adapter(FakeScenario.SUCCESS, stdout="", stderr="y" * 11).execute(req)
    assert result.output.truncated is True
    assert result.output.stderr_captured_bytes == 10
    assert result.output.stderr_original_bytes == 11


# --------------------------------------------------------------------------
# R1-RED-06: unconfirmed cancellation must NOT normalize to CANCELLED
# --------------------------------------------------------------------------
def test_r1_red06_unconfirmed_cancel_not_cancelled():
    adapter = CodexAdapter(backend=FakeCodexRuntime(scenario=FakeScenario.SUCCESS))
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    result = adapter.execute(_request())
    assert result.status != AgentStatus.CANCELLED
    assert result.status == AgentStatus.FAILED


# --------------------------------------------------------------------------
# R1-RED-07: confirmed cancellation + late DONE must NOT become DONE
# --------------------------------------------------------------------------
def test_r1_red07_confirmed_cancel_late_done_not_done():
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    raw = RawRuntimeResult(exit_code=0, stdout="late", stderr="", duration_ms=10, cancelled=True)
    result = adapter._normalize(raw, _request(), cancel_requested=False)
    assert result.status != AgentStatus.DONE
    assert result.status == AgentStatus.CANCELLED


# --------------------------------------------------------------------------
# R1-RED-08: a FAILED runtime must never be promoted to probe PASS
# --------------------------------------------------------------------------
def test_r1_red08_failed_runtime_not_promoted_to_probe_pass():
    verdict = classify_probe_outcome(status="FAILED", stderr="process exited 1", stdout="")
    assert verdict != "ADAPTER_RUNTIME_PROBE_PASS"
    verdict_ext = classify_probe_outcome(
        status="FAILED", stderr="error: not logged in / invalid api key", stdout=""
    )
    assert verdict_ext == "BLOCKED_EXTERNAL_DEPENDENCY"


# --------------------------------------------------------------------------
# R1-RED-09: 40-char git object hash is not a valid SHA-256
# --------------------------------------------------------------------------
def test_r1_red09_forty_char_hash_rejected_as_sha256():
    git_object_hash = "0fca2a2836b4f0996885fee2db1352eaa494c3fa"  # 40 chars
    assert len(git_object_hash) == 40
    # A 40-char Git object hash must be rejected as a sha256 field value.
    with pytest.raises(ValidationError):
        AgentOutput(stdout="x", stderr="", content_sha256=git_object_hash)
    # A real 64-char SHA-256 is accepted.
    real_sha = hashlib.sha256(b"x").hexdigest()
    assert len(real_sha) == 64
    out = AgentOutput(stdout="x", stderr="", content_sha256=real_sha)
    assert out.content_sha256 == real_sha


# --------------------------------------------------------------------------
# R1-RED-10: provider-neutral contract_type must not use CODEX_*
# --------------------------------------------------------------------------
def test_r1_red10_codex_contract_type_rejected():
    with pytest.raises(ValidationError):
        AgentRequest(
            contract_type="CODEX_AGENT_REQUEST",  # type: ignore[arg-type]
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(
                    job_id="j", task_id="t", root_task_id="r", attempt_id="a"
                ),
                agent_session_id="s",
            ),
            workspace=AgentWorkspace(root="/tmp/ws"),
            task=AgentTask(instruction="x"),
            limits=AgentLimits(timeout_seconds=30),
            invocation=AgentInvocation(provider="codex", model="m"),
        )


# --------------------------------------------------------------------------
# R2-OUT-01..10: byte-truthful bounded concurrent capture (R2-02 / R2-03)
# --------------------------------------------------------------------------
def _capture(backend, *, stdout: str = "", stderr: str = "",
             max_out: int = 1_000_000, max_err: int = 1_000_000):
    req = _request(limits=AgentLimits(timeout_seconds=30, max_stdout_bytes=max_out,
                                       max_stderr_bytes=max_err))
    return _fake_adapter(backend, stdout=stdout, stderr=stderr).execute(req)


def test_r2_out01_exact_stdout_limit():
    result = _capture(FakeScenario.SUCCESS, stdout="x" * 100, max_out=100)
    assert result.output.truncated is False
    assert result.output.stdout_original_bytes == 100
    assert result.output.stdout_captured_bytes == 100


def test_r2_out02_stdout_limit_plus_one():
    result = _capture(FakeScenario.SUCCESS, stdout="x" * 101, max_out=100)
    assert result.output.truncated is True
    assert result.output.stdout_original_bytes == 101
    assert result.output.stdout_captured_bytes is not None  # field present
    assert result.output.stdout_captured_bytes == 100


def test_r2_out03_stdout_gt_64kib():
    data = "x" * 100_000
    result = _capture(FakeScenario.SUCCESS, stdout=data, max_out=200_000)
    assert result.status == AgentStatus.DONE
    assert result.output.truncated is False
    assert result.output.stdout_original_bytes == 100_000
    assert result.output.stdout_captured_bytes == 100_000


def test_r2_out04_stdout_gt_1mib():
    data = "x" * 2_000_000
    result = _capture(FakeScenario.SUCCESS, stdout=data, max_out=1_000_000)
    assert result.output.truncated is True
    assert result.output.stdout_original_bytes == 2_000_000
    assert result.output.stdout_captured_bytes == 1_000_000


def test_r2_out05_stderr_gt_64kib():
    data = "y" * 100_000
    result = _capture(FakeScenario.SUCCESS, stderr=data, max_err=200_000)
    assert result.output.truncated is False
    assert result.output.stderr_original_bytes == 100_000
    assert result.output.stderr_captured_bytes == 100_000


def test_r2_out06_stderr_gt_1mib():
    data = "y" * 2_000_000
    result = _capture(FakeScenario.SUCCESS, stderr=data, max_err=1_000_000)
    assert result.output.truncated is True
    assert result.output.stderr_original_bytes == 2_000_000
    assert result.output.stderr_captured_bytes == 1_000_000


def test_r2_out07_stdout_stderr_simultaneous_large():
    so = "x" * 200_000
    se = "y" * 200_000
    result = _capture(FakeScenario.SUCCESS, stdout=so, stderr=se,
                      max_out=1_000_000, max_err=1_000_000)
    # No pipe-buffer deadlock: both streams drain to completion.
    assert result.status == AgentStatus.DONE
    assert result.output.stdout_original_bytes == 200_000
    assert result.output.stderr_original_bytes == 200_000


def test_r2_out08_utf8_multibyte_byte_counting():
    kor = "한" * 10  # 30 UTF-8 bytes, 10 characters
    result = _capture(FakeScenario.SUCCESS, stdout=kor, max_out=100)
    assert result.output.stdout_original_bytes == 30  # bytes, not chars
    assert result.output.stdout_captured_bytes == 30
    # Crossing the byte boundary: 30 bytes, 29-byte cap.
    result2 = _capture(FakeScenario.SUCCESS, stdout=kor, max_out=29)
    assert result2.output.truncated is True
    assert result2.output.stdout_original_bytes == 30
    assert result2.output.stdout_captured_bytes == 29


def test_r2_out09_credential_before_truncation_boundary():
    secret = "sk-ABCDEFGHIJKLMNOP"
    result = _capture(FakeScenario.SUCCESS, stdout=f"prefix {secret} suffix", max_out=1000)
    assert secret not in result.output.stdout
    assert "[REDACTED]" in result.output.stdout


def test_r2_out10_credential_crossing_truncation_boundary():
    secret = "sk-ABCDEFGHIJKLMNOP"
    beyond = "z" * 5000
    head = "a" * 200 + secret + "b" * 200
    data = head + beyond
    result = _capture(FakeScenario.SUCCESS, stdout=data, max_out=1000)
    assert result.output.truncated is True
    assert result.output.stdout_original_bytes == len(data.encode("utf-8"))
    assert result.output.stdout_captured_bytes == 1000
    assert secret not in result.output.stdout
    assert "[REDACTED]" in result.output.stdout
    assert beyond[:50] not in result.output.stdout


# --------------------------------------------------------------------------
# R2-OUT-11: REAL subprocess concurrent pipe drain (FC1-02)
# Spawns an actual child process writing >1 MiB to BOTH stdout and stderr
# simultaneously, then exercises the genuine SubprocessCodexRuntime.invoke
# (binary pipes + two concurrent drain threads). No Codex/network/API involved.
# A deadlock on the OS pipe buffer would hang or truncate this test.
# --------------------------------------------------------------------------
def test_r2_out11_real_subprocess_concurrent_pipes():
    # Child: write 1.5 MiB to stdout AND 1.5 MiB to stderr at the same time.
    child = (
        "import sys; "
        "sys.stdout.write('A' * 1500000); "
        "sys.stderr.write('B' * 1500000); "
        "sys.stdout.flush(); sys.stderr.flush()"
    )
    with tempfile.TemporaryDirectory() as cwd:
        inv = RuntimeInvocation(
            command=[sys.executable, "-c", child],
            cwd=cwd,
            timeout_seconds=60,
            model="",
            provider="",
            max_stdout_bytes=1_000_000,
            max_stderr_bytes=1_000_000,
        )
        backend = SubprocessCodexRuntime()
        cancel = threading.Event()
        raw = backend.invoke(inv, cancel)

    assert raw.timed_out is False, "real pipe drain must not deadlock"
    assert raw.launch_error is False
    # Exact byte accounting (R2-02), measured on REAL subprocess pipes.
    assert raw.stdout_original_bytes == 1_500_000
    assert raw.stderr_original_bytes == 1_500_000
    assert raw.stdout_captured_bytes == 1_000_000
    assert raw.stderr_captured_bytes == 1_000_000
    assert raw.truncated is True
    assert len(raw.stdout) == 1_000_000
    assert len(raw.stderr) == 1_000_000


# --------------------------------------------------------------------------
# A6/R1-07: bounded real Codex probe (opt-in, never required for GREEN)
# --------------------------------------------------------------------------
@pytest.mark.skipif(
    os.environ.get("LANE_D_REAL_PROBE") != "1",
    reason="real Codex probe requires LANE_D_REAL_PROBE=1 and live auth",
)
def test_real_codex_probe():
    adapter = CodexAdapter()
    assert adapter.capabilities()["interface"] == "OFFICIAL_HEADLESS_CLI"
    with tempfile.TemporaryDirectory() as tmp:
        req = AgentRequest(
            execution_identity=AgentExecutionContext(
                execution_identity=ExecutionIdentity(
                    job_id="probe-job",
                    task_id="probe-task",
                    root_task_id="probe-root",
                    attempt_id="probe-attempt",
                ),
                agent_session_id="synapx-probe-sess",
            ),
            workspace=AgentWorkspace(root=tmp),
            task=AgentTask(
                instruction="List the files in the current directory and return their names only."
            ),
            limits=AgentLimits(timeout_seconds=120),
            invocation=AgentInvocation(provider="codex", model="gpt-5-codex"),
        )
        try:
            result = adapter.execute(req)
        except Exception as exc:  # pragma: no cover - environment dependent
            pytest.xfail(f"codex probe blocked by environment: {exc}")
        verdict = classify_probe_outcome(
            status=str(result.status), stderr=result.output.stderr, stdout=result.output.stdout
        )
        assert verdict != "ADAPTER_RUNTIME_PROBE_PASS" or result.status == AgentStatus.DONE
        assert str(result.status) != "COMPLETED"


# --------------------------------------------------------------------------
# R2-CANCEL-01..04: mid-flight cancellation truth (R2-04)
# --------------------------------------------------------------------------
def _run_execute(adapter, req, holder):
    holder["result"] = adapter.execute(req)


def test_r2_cancel01_confirmed_cancel_mid_flight():
    adapter = CodexAdapter(
        backend=FakeCodexRuntime(scenario=FakeScenario.CANCEL_RACE, race_window=1.0)
    )
    req = _request()
    holder: dict = {}
    t = threading.Thread(target=_run_execute, args=(adapter, req, holder), daemon=True)
    t.start()
    time.sleep(0.1)
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    t.join(timeout=5)
    assert "result" in holder
    result = holder["result"]
    assert result.status == AgentStatus.CANCELLED


def test_r2_cancel02_ignored_cancel_unconfirmed_failed():
    adapter = CodexAdapter(
        backend=FakeCodexRuntime(scenario=FakeScenario.CANCEL_IGNORED, race_window=1.0)
    )
    req = _request()
    holder: dict = {}
    t = threading.Thread(target=_run_execute, args=(adapter, req, holder), daemon=True)
    t.start()
    time.sleep(0.1)
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    t.join(timeout=5)
    assert "result" in holder
    result = holder["result"]
    # Cancel requested but process finished normally -> NOT DONE, FAILED + uncertain.
    assert result.status == AgentStatus.FAILED
    assert result.cancellation_uncertain is True
    assert result.status != AgentStatus.DONE


def test_r2_cancel03_timeout_with_late_done():
    adapter = CodexAdapter(
        backend=FakeCodexRuntime(scenario=FakeScenario.TIMEOUT_LATE_DONE, exit_code=0)
    )
    req = _request(limits=AgentLimits(timeout_seconds=1, max_stdout_bytes=1_000_000))
    result = adapter.execute(req)
    assert result.status == AgentStatus.TIMEOUT
    assert result.status != AgentStatus.DONE


def test_r2_cancel04_confirmed_cancel_with_late_done():
    adapter = CodexAdapter(
        backend=FakeCodexRuntime(
            scenario=FakeScenario.CANCEL_CONFIRMED_LATE_DONE, race_window=1.0
        )
    )
    req = _request()
    holder: dict = {}
    t = threading.Thread(target=_run_execute, args=(adapter, req, holder), daemon=True)
    t.start()
    time.sleep(0.1)
    adapter.cancel(job_id="job-1", task_id="task-1", attempt_id="attempt-1")
    t.join(timeout=5)
    assert "result" in holder
    result = holder["result"]
    # Confirmed cancel must win over a late DONE.
    assert result.status == AgentStatus.CANCELLED
    assert result.cancellation_uncertain is False


# --------------------------------------------------------------------------
# I3-D1: Codex Profile Binding (RED tests)
# --------------------------------------------------------------------------


def test_t01_profile_injection():
    """T01: profile configured -> build_invocation contains --profile."""
    req = _request(
        invocation=AgentInvocation(
            provider="codex",
            model="qwen3.8-27b",
            provider_config={"profile": "i3-qwen"},
        ),
    )
    inv = build_invocation(req)
    assert "--profile" in inv.command, (
        f"--profile not in command: {inv.command}"
    )
    idx = inv.command.index("--profile")
    assert inv.command[idx + 1] == "i3-qwen", (
        f"Expected i3-qwen after --profile, got: {inv.command[idx + 1]}"
    )


def test_t02_no_profile_backward_compatible():
    """T02: profile=None -> no --profile in command, backward compatible."""
    req = _request(
        invocation=AgentInvocation(
            provider="codex",
            model="gpt-5-codex",
        ),
    )
    inv = build_invocation(req)
    assert "--profile" not in inv.command, (
        f"--profile should not be in command when profile is None: {inv.command}"
    )


def test_t03_no_hardcoded_i3_provider_in_product_source():
    """T03: No hardcoded i3-qwen/beellama-i3/192.168.0.216 in product source."""
    import pathlib
    product_files = [
        "src/synapx_harness/adapters/codex/runtime.py",
        "src/synapx_harness/adapters/codex/contract.py",
        "src/synapx_harness/adapters/codex/models.py",
    ]
    forbidden = ["i3-qwen", "beellama-i3", "192.168.0.216", "qwen3.8-27b"]
    repo_root = pathlib.Path(__file__).resolve().parent.parent.parent
    for rel_path in product_files:
        content = (repo_root / rel_path).read_text(encoding="utf-8")
        for term in forbidden:
            assert term not in content, f"Forbidden term '{term}' found in {rel_path}"


def test_t04_profile_is_argv_element():
    """T04: profile is passed as argv element, not shell string concatenation."""
    req = _request(
        invocation=AgentInvocation(
            provider="codex",
            model="qwen3.8-27b",
            provider_config={"profile": "i3-qwen"},
        ),
    )
    inv = build_invocation(req)
    # --profile and its value must be separate argv elements
    idx = inv.command.index("--profile")
    assert isinstance(inv.command[idx], str)
    assert isinstance(inv.command[idx + 1], str)
    assert inv.command[idx + 1] != ""
    # Must not be combined like "--profile i3-qwen" as single string
    assert "--profile i3-qwen" not in inv.command


def test_t05_agent_result_normalization_unchanged():
    """T05: profile addition does not change AgentResult normalization."""
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    req = _request(
        invocation=AgentInvocation(
            provider="codex",
            model="qwen3.8-27b",
            provider_config={"profile": "i3-qwen"},
        ),
    )
    result = adapter.execute(req)
    assert result.status == AgentStatus.DONE
    assert result.status != "VERIFIED"
    assert result.status != "COMPLETED"
    assert result.status != "PASS"


def test_t06_adapter_not_terminal_authority():
    """T06: CodexAdapter never produces terminal authority."""
    adapter = _fake_adapter(FakeScenario.SUCCESS)
    req = _request(
        invocation=AgentInvocation(
            provider="codex",
            model="qwen3.8-27b",
            provider_config={"profile": "i3-qwen"},
        ),
    )
    result = adapter.execute(req)
    result_dict = result.model_dump()
    assert "VERIFIED" not in str(result_dict)
    assert "COMPLETED" not in str(result_dict)
    assert "terminal" not in result_dict
