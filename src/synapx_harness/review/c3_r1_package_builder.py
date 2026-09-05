"""RQ4-R2-C3-R1 package builder helper.

The canonical RQ2/RQ3 builder in ``synapx_harness.review.package_builder``
emits a manifest WITHOUT a self-entry. C3-R1 requires the manifest to
declare its OWN canonical entry (``inventory.self_entry``) so the
canonical package verifier can prove N1 (self-entry points to its own
manifest, correctly) and N2 (self-entry present) are satisfied.

This module reuses the same closed-world serialization primitive
(:class:`PackagePayload` -> manifest.bytes -> ZIP) without introducing a
second incompatible format. The only material addition is the
``inventory.self_entry`` block.

The builder is intentionally minimal: it accepts an in-memory manifest
payload + a list of payload entries and produces a ``bytes`` blob. It
does not consult git, does not read a working tree, and does not emit
synthetic placeholders.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Union

from synapx_harness.review.package_builder import PackagePayload
from synapx_harness.review.package_verifier import C3_R1_MANIFEST_FILENAME


@dataclass(frozen=True)
class C3R1PackageSpec:
    """In-memory C3-R1 package spec.

    Attributes
    ----------
    payload_entries:
        Iterable of ``(path, sha256_hex, size_bytes, blob)`` tuples. The
        ``path`` MUST NOT equal ``C3_R1_MANIFEST_FILENAME``; self entries
        are added automatically by the builder.
    payload_file_count:
        Pre-computed ``payload_file_count`` for the manifest. When
        omitted, the builder computes it from ``len(payload_entries)``.
    manifest_scope:
        Optional scope label baked into the manifest. Defaults to
        ``"ALL_PAYLOAD"`` (the canonical C3-R1 contract).
    """

    payload_entries: tuple[tuple[str, str, int, bytes], ...]
    payload_file_count: int | None = None
    manifest_scope: str = "ALL_PAYLOAD"


def _build_manifest_bytes(
    spec: C3R1PackageSpec,
) -> bytes:
    """Serialize the C3-R1 manifest (files + inventory.self_entry).

    The ``inventory.self_entry`` carries only the path of the manifest
    itself; it deliberately does NOT carry the manifest's own SHA-256
    or size to avoid a self-referential fixed-point that cannot be
    resolved in a single deterministic pass. The path-based N1/N2
    semantics (see :func:`verify_c3_r1_package_zip_bytes`) cover the
    self-binding invariant without resolving a self-hash.
    """
    files_field = [
        {
            "path": str(path),
            "sha256": str(sha256_hex),
            "size_bytes": int(size_bytes),
        }
        for (path, sha256_hex, size_bytes, _blob) in spec.payload_entries
    ]
    payload_file_count = (
        int(spec.payload_file_count)
        if spec.payload_file_count is not None
        else len(files_field)
    )
    manifest: dict[str, object] = {
        "manifest_scope": spec.manifest_scope,
        "payload_file_count": payload_file_count,
        "files": files_field,
        "inventory": {
            "self_entry": {
                "path": C3_R1_MANIFEST_FILENAME,
            }
        },
    }
    return json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")


def build_c3_r1_package_bytes(spec: C3R1PackageSpec) -> bytes:
    """Build the C3-R1 ZIP bytes from an in-memory spec.

    The manifest's ``inventory.self_entry`` carries only the path of the
    manifest itself, eliminating the self-referential fixed-point that
    would otherwise require a sha-of-sha to resolve. The path-based
    verifier semantics prove the self-binding invariant without a
    hash-of-self.

    No ``package_payload_manifest.json`` is expected in
    ``spec.payload_entries``; the builder adds it. ZIP entries are
    emitted deterministically (sorted path order) so re-runs produce
    identical bytes for identical specs.
    """
    sorted_entries = sorted(
        spec.payload_entries, key=lambda entry: entry[0]
    )
    manifest_bytes = _build_manifest_bytes(spec)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, _sha, _size, blob in sorted_entries:
            if path == C3_R1_MANIFEST_FILENAME:
                raise ValueError(
                    "payload_entries must not contain manifest filename; "
                    "the builder adds the manifest itself"
                )
            zf.writestr(path, blob)
        zf.writestr(C3_R1_MANIFEST_FILENAME, manifest_bytes)
    return zip_buffer.getvalue()


def build_c3_r1_package_from_payloads(
    payloads: Iterable[Union[PackagePayload, tuple[str, bytes]]],
) -> bytes:
    """Convenience wrapper: build a C3-R1 ZIP from existing payload primitives.

    Each input is either a :class:`PackagePayload` or a ``(path, bytes)``
    tuple. SHA256 and size are computed by the builder from the bytes
    so the caller does not need to pre-hash.
    """
    entries: list[tuple[str, str, int, bytes]] = []
    for item in payloads:
        if isinstance(item, PackagePayload):
            path = item.package_path
            blob = item.payload
        elif isinstance(item, tuple) and len(item) == 2:
            path, blob = item
        else:
            raise TypeError(
                f"payload entries must be PackagePayload or (path, bytes); "
                f"got {type(item).__name__}"
            )
        sha = hashlib.sha256(blob).hexdigest()
        entries.append((str(path), sha, len(blob), blob))
    return build_c3_r1_package_bytes(C3R1PackageSpec(payload_entries=tuple(entries)))


__all__ = [
    "C3R1PackageSpec",
    "build_c3_r1_package_bytes",
    "build_c3_r1_package_from_payloads",
]
