"""RQ4-R2-C3-R1 N1-N6 mutant package generator and verifier.

This module builds six physically distinct mutant ZIPs on top of a
canonical C3-R1 clean package and reuses the single canonical
:class:`synapx_harness.review.package_verifier.verify_c3_r1_package_zip_bytes`
verifier to prove each mutant is rejected with FAIL.

The aggregator rule (RQ4 §15) is::

    all(item["detected"] is True for item in negatives)

There are no hardcoded 6/6 counts; every mutant is independently built
and re-verified at run time.

Mutants
-------
N1 -- inventory self-entry points to wrong target
       (manifest is renamed in ``inventory.self_entry.path``)
N2 -- inventory self-entry missing
       (``inventory.self_entry`` removed from manifest JSON)
N3 -- undeclared ZIP member
       (an extra file is added to the ZIP but not declared in manifest)
N4 -- declared NON-SELF member absent
       (a manifest entry references a file absent from the ZIP;
        the manifest's ``payload_file_count`` is updated so the
        detector can attribute the violation to N4 rather than to a
        generic count mismatch)
N5 -- declared NON-SELF member SHA mismatch
       (a manifest entry's declared sha256 is corrupted)
N6 -- duplicate ZIP entry
       (one of the payload files is written twice into the ZIP)
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.review.c3_r1_package_builder import (
    C3_R1_MANIFEST_FILENAME,
    C3R1PackageSpec,
    build_c3_r1_package_bytes,
)
from synapx_harness.review.package_verifier import (
    PackageVerificationResult,
    verify_c3_r1_package_zip_bytes,
)


@dataclass(frozen=True)
class CleanPayload:
    """A single payload primitive used to seed the clean package.

    ``(package_relative_path, blob)`` tuple, identical in shape to the
    canonical :class:`PackagePayload`.
    """

    package_path: str
    blob: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.blob).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.blob)


@dataclass(frozen=True)
class MutantSpec:
    """Spec for one mutant ZIP.

    Attributes
    ----------
    name:
        Stable mutant identifier (e.g. ``"N1"``).
    description:
        Human-readable description of the mutation applied.
    expected_verdict:
        Always ``"FAIL"`` for the canonical six mutants.
    build:
        Callable that takes the clean ZIP bytes + parsed manifest and
        returns the mutated ZIP bytes.
    """

    name: str
    description: str
    expected_verdict: str
    build: "callable"


@dataclass
class MutantVerification:
    """Outcome of re-verifying one mutant through the canonical verifier."""

    name: str
    description: str
    expected_verdict: str
    actual_verdict: str
    detected: bool
    gate: str
    self_entry_present: bool
    recursive_self_binding: bool
    zip_self_placeholder_absent: bool
    self_inventory_violations: tuple[str, ...] = field(default_factory=tuple)
    unmanifested_entries: tuple[str, ...] = field(default_factory=tuple)
    missing_manifest_entries: tuple[str, ...] = field(default_factory=tuple)
    actual_duplicate_exact: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "description": self.description,
            "expected_verdict": self.expected_verdict,
            "actual_verdict": self.actual_verdict,
            "detected": self.detected,
            "gate": self.gate,
            "self_entry_present": self.self_entry_present,
            "recursive_self_binding": self.recursive_self_binding,
            "zip_self_placeholder_absent": self.zip_self_placeholder_absent,
            "self_inventory_violations": list(self.self_inventory_violations),
            "unmanifested_entries": list(self.unmanifested_entries),
            "missing_manifest_entries": list(self.missing_manifest_entries),
            "actual_duplicate_exact": self.actual_duplicate_exact,
        }


def build_clean_package_bytes(
    payloads: Iterable[CleanPayload],
) -> tuple[bytes, dict[str, object], dict[str, bytes]]:
    """Build the canonical C3-R1 clean package from a list of payloads.

    Returns
    -------
    (clean_zip_bytes, clean_manifest_dict, payload_blobs_by_path)
        The clean ZIP bytes, the parsed manifest, and a path->blob map
        that mutant builders reuse.
    """
    payload_list = list(payloads)
    payload_blobs_by_path: dict[str, bytes] = {
        p.package_path: p.blob for p in payload_list
    }
    entries = tuple(
        (p.package_path, p.sha256, p.size_bytes, p.blob) for p in payload_list
    )
    zip_bytes = build_c3_r1_package_bytes(C3R1PackageSpec(payload_entries=entries))

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        manifest_bytes = zf.read(C3_R1_MANIFEST_FILENAME)
        for p in payload_list:
            zf.read(p.package_path)
    manifest_obj = json.loads(manifest_bytes.decode("utf-8"))
    return zip_bytes, manifest_obj, payload_blobs_by_path


# ---------------------------------------------------------------------------
# Mutant builders
# ---------------------------------------------------------------------------


def _mutant_n1(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N1: inventory.self_entry points to wrong target."""
    m = copy.deepcopy(manifest_obj)
    inv = m.get("inventory")
    if not isinstance(inv, dict) or not isinstance(inv.get("self_entry"), dict):
        raise RuntimeError("clean manifest has no self_entry to mutate")
    inv["self_entry"]["path"] = "synapx-harness/NOT_THE_MANIFEST.json"
    new_manifest_bytes = json.dumps(m, indent=2).encode("utf-8")
    return _repack_zip(blobs, new_manifest_bytes)


def _mutant_n2(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N2: inventory.self_entry missing."""
    m = copy.deepcopy(manifest_obj)
    inv = m.get("inventory")
    if isinstance(inv, dict):
        inv.pop("self_entry", None)
    new_manifest_bytes = json.dumps(m, indent=2).encode("utf-8")
    return _repack_zip(blobs, new_manifest_bytes)


def _mutant_n3(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N3: undeclared ZIP member."""
    blobs = dict(blobs)
    blobs["synapx-harness/UNDECLARED.txt"] = b"I was never declared."
    return _repack_zip(blobs, json.dumps(manifest_obj, indent=2).encode("utf-8"))


def _mutant_n4(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N4: declared NON-SELF member absent.

    The manifest is updated to claim a file that is intentionally
    omitted from the ZIP. ``payload_file_count`` is bumped so the
    violation is attributed to N4 (``missing_manifest_entries`` /
    ``missing zip member``) rather than to a generic count mismatch.
    """
    m = copy.deepcopy(manifest_obj)
    files_field = m.get("files")
    if not isinstance(files_field, list):
        raise RuntimeError("clean manifest has no files list to mutate")
    fake_path = "synapx-harness/CLAIMED_BUT_ABSENT.py"
    placeholder_sha = "0" * 64
    placeholder_size = 1
    files_field.append(
        {
            "path": fake_path,
            "sha256": placeholder_sha,
            "size_bytes": placeholder_size,
        }
    )
    m["payload_file_count"] = len(files_field)
    new_manifest_bytes = json.dumps(m, indent=2).encode("utf-8")
    return _repack_zip(blobs, new_manifest_bytes)


def _mutant_n5(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N5: declared NON-SELF member SHA mismatch."""
    m = copy.deepcopy(manifest_obj)
    files_field = m.get("files")
    if not isinstance(files_field, list) or not files_field:
        raise RuntimeError("clean manifest has no files list to mutate")
    files_field[0]["sha256"] = "deadbeef" + "0" * 56
    new_manifest_bytes = json.dumps(m, indent=2).encode("utf-8")
    return _repack_zip(blobs, new_manifest_bytes)


def _mutant_n6(
    clean_zip: bytes,
    manifest_obj: dict[str, object],
    blobs: dict[str, bytes],
) -> bytes:
    """N6: duplicate ZIP entry."""
    if not blobs:
        raise RuntimeError("clean package has no payload to duplicate")
    sorted_paths = sorted(blobs.keys())
    dup_path = sorted_paths[0]
    new_manifest_bytes = json.dumps(manifest_obj, indent=2).encode("utf-8")
    return _repack_zip_with_duplicate(
        blobs, new_manifest_bytes, duplicate_path=dup_path
    )


# ---------------------------------------------------------------------------
# Mutant registry
# ---------------------------------------------------------------------------


def _repack_zip(blobs: dict[str, bytes], manifest_bytes: bytes) -> bytes:
    """Rebuild a ZIP with the given blobs + manifest. No duplicates."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(blobs.keys()):
            if path == C3_R1_MANIFEST_FILENAME:
                continue
            zf.writestr(path, blobs[path])
        zf.writestr(C3_R1_MANIFEST_FILENAME, manifest_bytes)
    return buf.getvalue()


def _repack_zip_with_duplicate(
    blobs: dict[str, bytes],
    manifest_bytes: bytes,
    *,
    duplicate_path: str,
) -> bytes:
    """Rebuild a ZIP with one path written twice (ZIP-level duplicate)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(blobs.keys()):
            if path == C3_R1_MANIFEST_FILENAME:
                continue
            if path == duplicate_path:
                zf.writestr(path, blobs[path])
                zf.writestr(path, blobs[path])
            else:
                zf.writestr(path, blobs[path])
        zf.writestr(C3_R1_MANIFEST_FILENAME, manifest_bytes)
    return buf.getvalue()


MUTANT_SPECS: tuple[MutantSpec, ...] = (
    MutantSpec(
        name="N1",
        description="inventory self-entry points to wrong target",
        expected_verdict="FAIL",
        build=_mutant_n1,
    ),
    MutantSpec(
        name="N2",
        description="inventory self-entry missing",
        expected_verdict="FAIL",
        build=_mutant_n2,
    ),
    MutantSpec(
        name="N3",
        description="undeclared ZIP member",
        expected_verdict="FAIL",
        build=_mutant_n3,
    ),
    MutantSpec(
        name="N4",
        description="declared NON-SELF member absent",
        expected_verdict="FAIL",
        build=_mutant_n4,
    ),
    MutantSpec(
        name="N5",
        description="declared NON-SELF member SHA mismatch",
        expected_verdict="FAIL",
        build=_mutant_n5,
    ),
    MutantSpec(
        name="N6",
        description="duplicate ZIP entry",
        expected_verdict="FAIL",
        build=_mutant_n6,
    ),
)


def verify_clean_package(
    clean_zip: bytes,
    *,
    zip_path: str = "clean.zip",
) -> PackageVerificationResult:
    """Verify the clean canonical package through the SAME canonical verifier.

    The clean package is expected to PASS. A PASS is required before any
    mutant is built, so a regression in the clean build propagates as
    a hard failure rather than as a silent baseline drift.
    """
    return verify_c3_r1_package_zip_bytes(clean_zip, zip_path=zip_path)


def build_and_verify_all_mutants(
    payloads: Iterable[CleanPayload],
    *,
    out_dir: Path | None = None,
) -> tuple[PackageVerificationResult, list[MutantVerification], dict[str, bytes]]:
    """Build the clean package, then build and verify every mutant.

    Parameters
    ----------
    payloads:
        The clean payload primitives to seed the package.
    out_dir:
        Optional directory to write each mutant ZIP to disk for
        external inspection.

    Returns
    -------
    (clean_result, mutants, mutant_zips_by_name)
        ``mutant_zips_by_name`` lets callers SHA-256 the on-disk mutants
        for the external ``PACKAGE_VERIFICATION.json`` envelope.
    """
    clean_zip, manifest_obj, blobs = build_clean_package_bytes(payloads)
    clean_result = verify_clean_package(clean_zip)
    if not clean_result.ok:
        raise RuntimeError(
            f"clean C3-R1 package failed verification: "
            f"violations={clean_result.self_inventory_violations} "
            f"unmanifested={clean_result.unmanifested_entries} "
            f"missing={clean_result.missing_manifest_entries} "
            f"gate={clean_result.gate}; mutants would be built on a "
            "broken baseline"
        )

    mutants: list[MutantVerification] = []
    mutant_zips: dict[str, bytes] = {}
    for spec in MUTANT_SPECS:
        mutant_zip = spec.build(clean_zip, manifest_obj, blobs)
        mutant_zips[spec.name] = mutant_zip
        if out_dir is not None:
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / f"mutant_{spec.name}.zip").write_bytes(mutant_zip)
        result = verify_c3_r1_package_zip_bytes(
            mutant_zip, zip_path=f"mutant_{spec.name}.zip"
        )
        actual_verdict = "FAIL" if not result.ok else "PASS"
        detected = actual_verdict == spec.expected_verdict == "FAIL"
        mutants.append(
            MutantVerification(
                name=spec.name,
                description=spec.description,
                expected_verdict=spec.expected_verdict,
                actual_verdict=actual_verdict,
                detected=detected,
                gate=result.gate,
                self_entry_present=result.self_entry_present,
                recursive_self_binding=result.recursive_self_binding,
                zip_self_placeholder_absent=result.zip_self_placeholder_absent,
                self_inventory_violations=result.self_inventory_violations,
                unmanifested_entries=result.unmanifested_entries,
                missing_manifest_entries=result.missing_manifest_entries,
                actual_duplicate_exact=result.actual_duplicate_exact,
            )
        )
    return clean_result, mutants, mutant_zips


def aggregate_negatives(mutants: list[MutantVerification]) -> dict[str, object]:
    """Compute the RQ4 §15 aggregator result over the mutant list."""
    detected_count = sum(1 for m in mutants if m.detected)
    total = len(mutants)
    return {
        "package_negative_tests": f"{detected_count}/{total}",
        "all_negative_tests_detected": bool(detected_count == total),
        "expected_verdict": "FAIL",
        "verifier_used": "synapx_harness.review.package_verifier.verify_c3_r1_package_zip_bytes",
        "mutants": [m.to_dict() for m in mutants],
    }


__all__ = [
    "CleanPayload",
    "MUTANT_SPECS",
    "MutantSpec",
    "MutantVerification",
    "aggregate_negatives",
    "build_and_verify_all_mutants",
    "build_clean_package_bytes",
    "verify_clean_package",
]
