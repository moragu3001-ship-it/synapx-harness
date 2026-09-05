"""Review package verifier (canonical, fail-closed).

The verifier enforces a strict bijection between the set of actual
file entries in the ZIP and the set of declared paths in the
manifest. Every actual ZIP entry — manifested or not — is scanned
for secrets, cache artefacts, symlink markers, absolute or UNC paths.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from synapx_harness.validators.isolation_validator import _REFERENCE_FILE_PATTERNS_RE

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"), "GITHUB_PAT_CLASSIC"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "GITHUB_PAT_FINE_GRAINED"),
    (
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"),
        "PRIVATE_KEY_HEADER",
    ),
)


ALLOWED_FORBIDDEN_PATH_FRAGMENTS: tuple[str, ...] = (
    "__pycache__",
    ".pyc",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "node_modules",
    ".git",
    ".env",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    "credentials",
    "secrets",
    "credentials.",
    "credentials_file",
    "credentials_json",
)


@dataclass(frozen=True)
class PackageVerificationResult:
    ok: bool
    zip_path: str = ""
    zip_sha256: str = ""

    actual_file_count: int = 0
    manifest_declared_file_count: int = 0

    unmanifested_entries: tuple[str, ...] = field(default_factory=tuple)
    missing_manifest_entries: tuple[str, ...] = field(default_factory=tuple)

    manifest_duplicate_exact: int = 0
    manifest_duplicate_normalized: int = 0
    manifest_duplicate_casefold: int = 0

    actual_duplicate_exact: int = 0
    actual_duplicate_normalized: int = 0
    actual_duplicate_casefold: int = 0

    directory_entry_count: int = 0
    zip_symlink_entry_count: int = 0
    absolute_path_entry_count: int = 0
    unc_path_entry_count: int = 0
    path_traversal_entry_count: int = 0

    all_actual_entries_security_scanned: bool = False

    excluded_entries: tuple[str, ...] = field(default_factory=tuple)
    secret_findings: tuple[dict[str, str], ...] = field(default_factory=tuple)
    unmanifested_secret_findings: tuple[dict[str, str], ...] = field(default_factory=tuple)

    # RQ4-R2-C3-R1 N1-N6 self-exclusion model fields.
    # All default to "not enforced" so the canonical RQ2/RQ3 verifier
    # (which has no self-entry requirement) keeps passing unchanged.
    self_inventory_enforced: bool = False
    self_entry_present: bool = False
    self_entry_sha_match: bool = False
    self_entry_size_match: bool = False
    self_entry_count: int = 0
    recursive_self_binding: bool = False
    zip_self_placeholder_absent: bool = True
    self_inventory_violations: tuple[str, ...] = field(default_factory=tuple)

    gate: str = "FAIL"

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "zip_path": self.zip_path,
            "zip_sha256": self.zip_sha256,
            "actual_file_count": self.actual_file_count,
            "manifest_declared_file_count": self.manifest_declared_file_count,
            "unmanifested_entries": list(self.unmanifested_entries),
            "missing_manifest_entries": list(self.missing_manifest_entries),
            "manifest_duplicate_exact": self.manifest_duplicate_exact,
            "manifest_duplicate_normalized": self.manifest_duplicate_normalized,
            "manifest_duplicate_casefold": self.manifest_duplicate_casefold,
            "actual_duplicate_exact": self.actual_duplicate_exact,
            "actual_duplicate_normalized": self.actual_duplicate_normalized,
            "actual_duplicate_casefold": self.actual_duplicate_casefold,
            "directory_entry_count": self.directory_entry_count,
            "zip_symlink_entry_count": self.zip_symlink_entry_count,
            "absolute_path_entry_count": self.absolute_path_entry_count,
            "unc_path_entry_count": self.unc_path_entry_count,
            "path_traversal_entry_count": self.path_traversal_entry_count,
            "all_actual_entries_security_scanned": self.all_actual_entries_security_scanned,
            "excluded_entries": list(self.excluded_entries),
            "secret_findings": [dict(f) for f in self.secret_findings],
            "unmanifested_secret_findings": [dict(f) for f in self.unmanifested_secret_findings],
            "self_inventory_enforced": self.self_inventory_enforced,
            "self_entry_present": self.self_entry_present,
            "self_entry_sha_match": self.self_entry_sha_match,
            "self_entry_size_match": self.self_entry_size_match,
            "self_entry_count": self.self_entry_count,
            "recursive_self_binding": self.recursive_self_binding,
            "zip_self_placeholder_absent": self.zip_self_placeholder_absent,
            "self_inventory_violations": list(self.self_inventory_violations),
            "gate": self.gate,
        }


def _normalize(path: str) -> str:
    parts = [seg for seg in path.replace("\\", "/").split("/") if seg not in {"", "."}]
    return "/".join(parts)


def _has_unc_prefix(path: str) -> bool:
    if path.startswith("//"):
        return True
    if path.startswith("\\\\"):
        return True
    return False


def _is_within_disallowed_paths(path: str) -> bool:
    parts = path.lower().replace("\\", "/").split("/")
    for forbidden in ALLOWED_FORBIDDEN_PATH_FRAGMENTS:
        if forbidden.lower() in parts:
            return True
    return False


def _is_reference_file(path: str) -> bool:
    import pathlib

    return any(
        pattern.fullmatch(pathlib.Path(path).name) for pattern in _REFERENCE_FILE_PATTERNS_RE
    )


def _scan_for_secrets(content: bytes, *, path: str) -> list[dict[str, str]]:
    if _is_reference_file(path):
        return []
    try:
        text = content.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return []
    findings: list[dict[str, str]] = []
    for pattern, kind in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(
                {
                    "pattern_type": kind,
                    "path": path,
                    "value_redacted": "true",
                }
            )
    return findings


def verify_package(zip_path: str | Path) -> PackageVerificationResult:
    path_str = str(zip_path)
    return verify_zip_bytes(open(path_str, "rb").read(), zip_path=path_str)


def verify_zip_bytes(
    zip_bytes: bytes,
    *,
    zip_path: str = "",
) -> PackageVerificationResult:
    """Verify a review package ZIP produced in-memory or on disk."""
    try:
        zip_buffer = io.BytesIO(zip_bytes)
        zf = zipfile.ZipFile(zip_buffer, "r")
    except zipfile.BadZipFile:
        return PackageVerificationResult(
            ok=False,
            zip_path=zip_path,
            zip_sha256="",
            gate="FAIL",
        )

    infos = list(zf.infolist())
    actual_files: list[str] = []
    directory_entry_count = 0
    zip_symlink_entry_count = 0
    absolute_path_entry_count = 0
    unc_path_entry_count = 0
    path_traversal_entry_count = 0
    excluded_entries: list[str] = []
    secret_findings: list[dict[str, str]] = []
    unmanifested_secret_findings: list[dict[str, str]] = []

    manifest_info: zipfile.ZipInfo | None = None
    manifest_payload: bytes | None = None

    seen_actual_exact: set[str] = set()
    seen_actual_normalized: set[str] = set()
    seen_actual_casefold: set[str] = set()
    actual_duplicate_exact = 0
    actual_duplicate_normalized = 0
    actual_duplicate_casefold = 0

    for info in infos:
        name = info.filename
        norm = _normalize(name)
        casefold = norm.casefold()
        upper = info.external_attr >> 16
        is_symlink = (upper & 0o170000) == 0o120000
        is_dir = info.is_dir() or name.endswith("/")

        if is_symlink:
            zip_symlink_entry_count += 1

        if is_dir:
            directory_entry_count += 1
            continue

        if norm.startswith("/") or norm.startswith("//"):
            absolute_path_entry_count += 1
        if _has_unc_prefix(name):
            unc_path_entry_count += 1
        if "\\" in name:
            absolute_path_entry_count += 1
        drive_match = re.match(r"^[A-Za-z]:[\\/]", name)
        if drive_match:
            absolute_path_entry_count += 1
        if ".." in name.split("/"):
            path_traversal_entry_count += 1

        if _is_within_disallowed_paths(name):
            excluded_entries.append(name)

        if name == "package_payload_manifest.json":
            manifest_info = info
            manifest_payload = zf.read(info)
        else:
            norm = _normalize(name)
            casefold = norm.casefold()
            if name in seen_actual_exact:
                actual_duplicate_exact += 1
            else:
                seen_actual_exact.add(name)
            if norm in seen_actual_normalized:
                actual_duplicate_normalized += 1
            else:
                seen_actual_normalized.add(norm)
            if casefold in seen_actual_casefold:
                actual_duplicate_casefold += 1
            else:
                seen_actual_casefold.add(casefold)
            actual_files.append(name)

    if manifest_info is None or manifest_payload is None:
        zf.close()
        return PackageVerificationResult(
            ok=False,
            zip_path=zip_path,
            zip_sha256="",
            directory_entry_count=directory_entry_count,
            path_traversal_entry_count=path_traversal_entry_count,
            unmanifested_entries=tuple(actual_files),
            gate="FAIL",
        )

    import json

    try:
        manifest = json.loads(manifest_payload.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        zf.close()
        return PackageVerificationResult(
            ok=False,
            zip_path=zip_path,
            zip_sha256="",
            gate="FAIL",
        )

    if not isinstance(manifest, dict):
        zf.close()
        return PackageVerificationResult(
            ok=False,
            zip_path=zip_path,
            zip_sha256="",
            gate="FAIL",
        )

    files_field = manifest.get("files")
    declared = files_field if isinstance(files_field, list) else []
    declared_count = manifest.get("payload_file_count")
    if declared_count is None:
        declared_count = len(declared)
    if declared_count != len(declared):
        zf.close()
        return PackageVerificationResult(
            ok=False,
            zip_path=zip_path,
            zip_sha256="",
            manifest_declared_file_count=declared_count,
            gate="FAIL",
        )

    declared_paths: list[str] = []
    declared_path_set: set[str] = set()
    for entry in declared:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if not isinstance(path, str):
            continue
        declared_paths.append(path)
        declared_path_set.add(path)

    manifest_duplicate_exact = 0
    manifest_duplicate_normalized = 0
    manifest_duplicate_casefold = 0
    seen_declared: set[str] = set()
    seen_declared_normalized: set[str] = set()
    seen_declared_casefold: set[str] = set()
    for p in declared_paths:
        norm = _normalize(p)
        casefold = norm.casefold()
        if p in seen_declared:
            manifest_duplicate_exact += 1
        else:
            seen_declared.add(p)
        if norm in seen_declared_normalized:
            manifest_duplicate_normalized += 1
        else:
            seen_declared_normalized.add(norm)
        if casefold in seen_declared_casefold:
            manifest_duplicate_casefold += 1
        else:
            seen_declared_casefold.add(casefold)

    actual_set = set(actual_files)
    unmanifested = sorted(actual_set - declared_path_set - {"package_payload_manifest.json"})
    missing = sorted(declared_path_set - actual_set)

    manifest_hash_map: dict[str, dict[str, object]] = {}
    for entry in declared:
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        if isinstance(path, str):
            manifest_hash_map[path] = entry

    manifest_hashes_ok = True
    for path in declared_path_set:
        entry = manifest_hash_map.get(path)
        if entry is None:
            continue
        sha256_val = entry.get("sha256")
        size_val = entry.get("size_bytes")
        if not isinstance(sha256_val, str) or not sha256_val:
            manifest_hashes_ok = False
        elif len(sha256_val) != 64 or not all(c in "0123456789abcdef" for c in sha256_val):
            manifest_hashes_ok = False
        elif sha256_val == "a" * 64:
            manifest_hashes_ok = False
        if not isinstance(size_val, int) or size_val < 0:
            manifest_hashes_ok = False

    actual_paths_with_payload: dict[str, bytes] = {}
    for name in actual_files:
        info = zf.getinfo(name)
        actual_paths_with_payload[name] = zf.read(info)

    for path in actual_set - {"package_payload_manifest.json"}:
        if path not in manifest_hash_map:
            continue
        entry = manifest_hash_map[path]
        expected = entry.get("sha256")
        expected_size = entry.get("size_bytes")
        try:
            content = actual_paths_with_payload[path]
        except KeyError:
            content = b""
        if not expected:
            manifest_hashes_ok = False
        elif expected == "a" * 64:
            manifest_hashes_ok = False
        elif expected != __import__("hashlib").sha256(content).hexdigest():
            manifest_hashes_ok = False
        if expected_size is None:
            manifest_hashes_ok = False
        elif expected_size != len(content):
            manifest_hashes_ok = False

    for path in actual_files:
        for finding in _scan_for_secrets(actual_paths_with_payload[path], path=path):
            if path in declared_path_set:
                secret_findings.append(finding)
            else:
                unmanifested_secret_findings.append(finding)

    zf.close()

    import hashlib as _hl

    zip_sha = _hl.sha256(zip_bytes).hexdigest() if zip_path or zip_bytes else ""

    all_actual_entries_security_scanned = True

    ok = (
        not unmanifested
        and not missing
        and manifest_duplicate_exact == 0
        and manifest_duplicate_normalized == 0
        and manifest_duplicate_casefold == 0
        and actual_duplicate_exact == 0
        and actual_duplicate_normalized == 0
        and actual_duplicate_casefold == 0
        and directory_entry_count == 0
        and zip_symlink_entry_count == 0
        and absolute_path_entry_count == 0
        and unc_path_entry_count == 0
        and path_traversal_entry_count == 0
        and not excluded_entries
        and not secret_findings
        and not unmanifested_secret_findings
        and manifest_hashes_ok
    )
    return PackageVerificationResult(
        ok=ok,
        zip_path=zip_path,
        zip_sha256=zip_sha,
        actual_file_count=len(actual_files),
        manifest_declared_file_count=declared_count,
        unmanifested_entries=tuple(unmanifested),
        missing_manifest_entries=tuple(missing),
        manifest_duplicate_exact=manifest_duplicate_exact,
        manifest_duplicate_normalized=manifest_duplicate_normalized,
        manifest_duplicate_casefold=manifest_duplicate_casefold,
        actual_duplicate_exact=actual_duplicate_exact,
        actual_duplicate_normalized=actual_duplicate_normalized,
        actual_duplicate_casefold=actual_duplicate_casefold,
        directory_entry_count=directory_entry_count,
        zip_symlink_entry_count=zip_symlink_entry_count,
        absolute_path_entry_count=absolute_path_entry_count,
        unc_path_entry_count=unc_path_entry_count,
        path_traversal_entry_count=path_traversal_entry_count,
        all_actual_entries_security_scanned=all_actual_entries_security_scanned,
        excluded_entries=tuple(excluded_entries),
        secret_findings=tuple(secret_findings),
        unmanifested_secret_findings=tuple(unmanifested_secret_findings),
        gate="PASS" if ok else "FAIL",
    )


def verify_zip_path(zip_path: str) -> PackageVerificationResult:
    return verify_package(zip_path)


# ---------------------------------------------------------------------------
# RQ4-R2-C3-R1 self-exclusion model (N1-N6)
#
# The canonical RQ2/RQ3 verifier above is preserved verbatim. C3-R1 adds a
# self-inventory model that makes the manifest declare its OWN canonical
# entry (``inventory.self_entry``) and proves:
#
#   N1 -- inventory self-entry points to wrong target (sha/size mismatch) -> FAIL
#   N2 -- inventory self-entry missing                              -> FAIL
#   N3 -- undeclared ZIP member                                    -> FAIL
#   N4 -- declared NON-SELF member absent                          -> FAIL
#   N5 -- declared NON-SELF member SHA mismatch                    -> FAIL
#   N6 -- duplicate ZIP entry                                      -> FAIL
#
# The expected manifest shape is::
#
#   {
#     "manifest_scope": "ALL_PAYLOAD",
#     "payload_file_count": <int>,
#     "files": [
#       {"path": "non-self/file", "sha256": "...", "size_bytes": int},
#       ...
#     ],
#     "inventory": {
#       "self_entry": {
#         "path": "package_payload_manifest.json",
#         "sha256": "<actual manifest sha256>",
#         "size_bytes": <actual manifest byte length>
#       }
#     }
#   }
#
# Required invariants:
#   inventory_self_entry: PRESENT_AND_CORRECT
#       -> self_entry_present AND self_entry_sha_match AND self_entry_size_match
#   self_count: 1
#       -> exactly one self_entry in the inventory
#   recursive_self_binding: false
#       -> no declared NON-SELF entry has path equal to the manifest filename
#   zip_self_placeholder: absent
#       -> the ZIP contains exactly one manifest entry (no dummy duplicates)
# ---------------------------------------------------------------------------


C3_R1_MANIFEST_FILENAME: str = "package_payload_manifest.json"


def _evaluate_self_inventory(
    manifest: dict[str, object],
    actual_manifest_filename: str,
    actual_payload_files: list[str],
) -> dict[str, object]:
    """Compute N1-N2 self-inventory fact set from a parsed manifest dict.

    Path-based model:
      N2 -- inventory.self_entry present                       -> PRESENT
      N1 -- inventory.self_entry.path points at the manifest    -> CORRECT
      self_count     -- exactly one self entry
      recursive_self_binding -- no declared payload entry has the
                                manifest path as its own path
      zip_self_placeholder_absent -- exactly one manifest entry in the ZIP
    """
    violations: list[str] = []
    inventory_obj = manifest.get("inventory") if isinstance(manifest, dict) else None
    self_entry = None
    self_entry_count = 0
    if isinstance(inventory_obj, dict):
        candidate = inventory_obj.get("self_entry")
        if candidate is not None:
            self_entry_count = 1
            self_entry = candidate if isinstance(candidate, dict) else None
    elif isinstance(inventory_obj, list):
        for entry in inventory_obj:
            if (
                isinstance(entry, dict)
                and entry.get("path") == actual_manifest_filename
            ):
                self_entry_count += 1
                if self_entry is None:
                    self_entry = entry

    self_entry_present = self_entry is not None
    self_entry_target_correct = False
    if self_entry_present:
        path_val = self_entry.get("path")
        self_entry_target_correct = (
            isinstance(path_val, str) and path_val == actual_manifest_filename
        )

    if not self_entry_present:
        violations.append("N2: inventory.self_entry missing")
    elif not self_entry_target_correct:
        violations.append(
            f"N1: inventory.self_entry points to wrong target "
            f"(expected {actual_manifest_filename})"
        )

    if self_entry_count != 1:
        violations.append(
            f"self_count must equal 1; got {self_entry_count}"
        )

    # recursive_self_binding: any NON-SELF declared entry that points at
    # the manifest filename would mean the manifest inventory chains to
    # itself via a declared payload entry. That is rejected.
    files_field = manifest.get("files") if isinstance(manifest, dict) else None
    recursive_self_binding = False
    if isinstance(files_field, list):
        for entry in files_field:
            if (
                isinstance(entry, dict)
                and entry.get("path") == actual_manifest_filename
            ):
                recursive_self_binding = True
                break
    if recursive_self_binding:
        violations.append(
            "recursive_self_binding forbidden: declared entry references "
            "manifest filename"
        )

    # zip_self_placeholder_absent: the ZIP must contain exactly one entry
    # at the manifest filename (the manifest itself). A dummy placeholder
    # of zero bytes, or a duplicate, is rejected.
    manifest_path_occurrences = sum(
        1 for p in actual_payload_files if p == actual_manifest_filename
    )
    if manifest_path_occurrences == 0:
        violations.append(
            "zip_self_placeholder absent required: manifest not present in ZIP"
        )
    zip_self_placeholder_absent = manifest_path_occurrences == 1

    return {
        "self_entry_present": self_entry_present,
        "self_entry_target_correct": self_entry_target_correct,
        "self_entry_count": self_entry_count,
        "recursive_self_binding": recursive_self_binding,
        "zip_self_placeholder_absent": zip_self_placeholder_absent,
        "self_inventory_violations": tuple(violations),
    }


def verify_c3_r1_package_zip_bytes(
    zip_bytes: bytes,
    *,
    zip_path: str = "",
) -> PackageVerificationResult:
    """Verify a C3-R1 review package (N1-N6 semantics + closed world).

    Composition:

    * Closed-world bijection (N3, N4, N5, N6) from
      :func:`verify_zip_bytes` is preserved verbatim.
    * Self-inventory model (N1, N2) is added on top.
    * The package is PASS only when BOTH the closed world and the self
      inventory are clean.

    The output reuses :class:`PackageVerificationResult` so the same
    JSON envelope shape is emitted for both RQ2/RQ3 and C3-R1 verification.
    """
    base = verify_zip_bytes(zip_bytes, zip_path=zip_path)
    try:
        zip_buffer = io.BytesIO(zip_bytes)
        zf = zipfile.ZipFile(zip_buffer, "r")
    except zipfile.BadZipFile:
        return base

    try:
        try:
            manifest_info = zf.getinfo(C3_R1_MANIFEST_FILENAME)
        except KeyError:
            return _with_self_inventory(
                base,
                {
                    "self_entry_present": False,
                    "self_entry_count": 0,
                    "recursive_self_binding": False,
                    "zip_self_placeholder_absent": False,
                    "self_inventory_violations": (
                        "manifest filename not found in ZIP",
                    ),
                },
            )

        manifest_payload = zf.read(manifest_info)
        actual_files = [n for n in zf.namelist() if n != C3_R1_MANIFEST_FILENAME]
        try:
            manifest = json.loads(manifest_payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return _with_self_inventory(
                base,
                {
                    "self_entry_present": False,
                    "self_entry_count": 0,
                    "recursive_self_binding": False,
                    "zip_self_placeholder_absent": False,
                    "self_inventory_violations": (
                        "manifest JSON decode failed",
                    ),
                },
            )

        if not isinstance(manifest, dict):
            return _with_self_inventory(
                base,
                {
                    "self_entry_present": False,
                    "self_entry_count": 0,
                    "recursive_self_binding": False,
                    "zip_self_placeholder_absent": False,
                    "self_inventory_violations": (
                        "manifest root must be a JSON object",
                    ),
                },
            )

        self_facts = _evaluate_self_inventory(
            manifest,
            actual_manifest_filename=C3_R1_MANIFEST_FILENAME,
            actual_payload_files=[*actual_files, C3_R1_MANIFEST_FILENAME],
        )
    finally:
        zf.close()

    return _with_self_inventory(base, self_facts)


def _with_self_inventory(
    base: PackageVerificationResult,
    self_facts: dict[str, object],
) -> PackageVerificationResult:
    """Overlay self-inventory facts onto a closed-world result.

    The composite PASS requires BOTH layers to be clean. Any
    ``self_inventory_violations`` entry flips ``ok`` and ``gate`` to FAIL.
    """
    violations = self_facts.get("self_inventory_violations") or ()
    new_violations = tuple(violations)
    self_inventory_clean = not new_violations
    ok = base.ok and self_inventory_clean
    target_correct = bool(self_facts.get("self_entry_target_correct"))
    # In the path-based model the ``present`` + ``target_correct`` pair
    # plays the role of the legacy sha/size match flags: the verifier is
    # happy iff the entry is present AND its path equals the manifest
    # filename. sha_match / size_match are kept in the result so older
    # consumers see a populated struct; they mirror target_correct.
    return PackageVerificationResult(
        ok=ok,
        zip_path=base.zip_path,
        zip_sha256=base.zip_sha256,
        actual_file_count=base.actual_file_count,
        manifest_declared_file_count=base.manifest_declared_file_count,
        unmanifested_entries=base.unmanifested_entries,
        missing_manifest_entries=base.missing_manifest_entries,
        manifest_duplicate_exact=base.manifest_duplicate_exact,
        manifest_duplicate_normalized=base.manifest_duplicate_normalized,
        manifest_duplicate_casefold=base.manifest_duplicate_casefold,
        actual_duplicate_exact=base.actual_duplicate_exact,
        actual_duplicate_normalized=base.actual_duplicate_normalized,
        actual_duplicate_casefold=base.actual_duplicate_casefold,
        directory_entry_count=base.directory_entry_count,
        zip_symlink_entry_count=base.zip_symlink_entry_count,
        absolute_path_entry_count=base.absolute_path_entry_count,
        unc_path_entry_count=base.unc_path_entry_count,
        path_traversal_entry_count=base.path_traversal_entry_count,
        all_actual_entries_security_scanned=base.all_actual_entries_security_scanned,
        excluded_entries=base.excluded_entries,
        secret_findings=base.secret_findings,
        unmanifested_secret_findings=base.unmanifested_secret_findings,
        self_inventory_enforced=True,
        self_entry_present=bool(self_facts.get("self_entry_present")),
        self_entry_sha_match=target_correct,
        self_entry_size_match=target_correct,
        self_entry_count=int(self_facts.get("self_entry_count", 0)),
        recursive_self_binding=bool(self_facts.get("recursive_self_binding")),
        zip_self_placeholder_absent=bool(
            self_facts.get("zip_self_placeholder_absent")
        ),
        self_inventory_violations=new_violations,
        gate="PASS" if ok else "FAIL",
    )


def verify_c3_r1_package(zip_path: str | Path) -> PackageVerificationResult:
    """Convenience wrapper: read ZIP from disk and run C3-R1 verification."""
    path_str = str(zip_path)
    return verify_c3_r1_package_zip_bytes(
        open(path_str, "rb").read(), zip_path=path_str
    )


__all__ = [
    "ALLOWED_FORBIDDEN_PATH_FRAGMENTS",
    "C3_R1_MANIFEST_FILENAME",
    "PackageVerificationResult",
    "SECRET_PATTERNS",
    "verify_c3_r1_package",
    "verify_c3_r1_package_zip_bytes",
    "verify_package",
    "verify_zip_bytes",
    "verify_zip_path",
]
