"""Build the R3-R3 code-repair review ZIP (convenience bundle, not Owner package)."""
from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path


REPO = Path("C:\\krag_work\\synapx_harness_rq0_bootstrap")
EVIDENCE = REPO / "_rq8_p1_r3_r3_evidence"
OUTPUT_ZIP = (
    REPO
    / "SYNAPX_HARNESS_RQ8_P1_R3_R3_CODE_REPAIR_REVIEW.zip"
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_manifest(members: list[tuple[str, Path]]) -> dict[str, object]:
    """Build the manifest. The manifest file itself is NOT listed in
    ``members`` because listing it would require the manifest to contain
    its own SHA256, which is a circular dependency. The verifier reads
    the manifest entry from the ZIP and verifies it appears in the
    archive independently."""
    return {
        "package_name": "SYNAPX_HARNESS_RQ8_P1_R3_R3_CODE_REPAIR_REVIEW",
        "package_status": (
            "R3_R3_CODE_REPAIR_COMPLETE_SEED_CUSTODY_BLOCKED"
        ),
        "is_official_owner_review_package": False,
        "note": (
            "PACKAGE_MANIFEST.json itself is included in the ZIP for "
            "transparency but is NOT listed in the members array "
            "(self-reference would be circular)."
        ),
        "built_at": datetime.now(UTC).isoformat(),
        "members": [
            {
                "name": arcname,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
            for arcname, path in members
        ],
        "explicitly_excluded": [
            {
                "name": (
                    "RQ8_ITS_DANGEROUS_COMPRESSED_PAYLOAD_SEED.patch"
                ),
                "reason": "SEED_ARTIFACT_CUSTODY_BLOCKED -- not present on New PC",
                "expected_sha256": (
                    "142FB0FC583D5AA001DCD02100778EE13DAE792A632C351C71D22CD04697BD9A"
                ),
                "required_path": "C:\\rq8\\seeds\\",
            },
            {
                "name": "RQ8_ITS_DANGEROUS_QUALIFIED_RED_EXPECTATION.json",
                "reason": "Depends on canonical seed + Old-PC fixture run",
            },
            {
                "name": "RQ8_ITS_DANGEROUS_EXPECTATION_GENERATION_RECEIPT.json",
                "reason": "Depends on canonical seed + qualified expectation",
            },
            {
                "name": "RQ8_ITS_DANGEROUS_EXPECTATION_RAW_RED.log",
                "reason": "Depends on independent Old-PC seeded pytest run",
            },
            {
                "name": "SYNAPX_HARNESS_RQ8_P1_R3_R3_OWNER_REVIEW.zip",
                "reason": "Spec §20 forbids building Owner package when seed is BLOCKED",
            },
        ],
    }


def main() -> None:
    # Members in deterministic order
    members: list[tuple[str, Path]] = [
        ("REVIEW_README.md", EVIDENCE / "REVIEW_README.md"),
        ("STATUS.txt", EVIDENCE / "STATUS.txt"),
        (
            "R3_R3_POST_COMPARATOR_BRANCH_CENSUS.json",
            EVIDENCE / "R3_R3_POST_COMPARATOR_BRANCH_CENSUS.json",
        ),
        (
            "PRE_R3_R3_POST_COMPARATOR_LINEAGE_FAILURE.log",
            EVIDENCE / "PRE_R3_R3_POST_COMPARATOR_LINEAGE_FAILURE.log",
        ),
        (
            "RQ8_SEED_ARTIFACT_VERIFICATION.json",
            EVIDENCE / "RQ8_SEED_ARTIFACT_VERIFICATION.json",
        ),
        (
            "START_REVISION_BINDING.json",
            EVIDENCE / "START_REVISION_BINDING.json",
        ),
        (
            "FINAL_REVISION_BINDING.json",
            EVIDENCE / "FINAL_REVISION_BINDING.json",
        ),
        ("SOURCE_DIFF.txt", EVIDENCE / "SOURCE_DIFF.txt"),
        ("TARGETED_TESTS.log", EVIDENCE / "TARGETED_TESTS.log"),
        ("FULL_REGRESSION.log", EVIDENCE / "FULL_REGRESSION.log"),
        ("RUFF_CHANGED_FILES.log", EVIDENCE / "RUFF_CHANGED_FILES.log"),
        ("PYRIGHT_CHANGED_FILES.log", EVIDENCE / "PYRIGHT_CHANGED_FILES.log"),
        (
            "tests/contract/test_rq8_p1_r3_r3_post_comparator_lineage.py",
            REPO / "tests" / "contract" / "test_rq8_p1_r3_r3_post_comparator_lineage.py",
        ),
        (
            "tests/contract/test_rq8_p1_r3_r3_controlled_raw_receipt.py",
            REPO / "tests" / "contract" / "test_rq8_p1_r3_r3_controlled_raw_receipt.py",
        ),
    ]

    # Verify all member files exist
    for arcname, path in members:
        if not path.is_file():
            raise FileNotFoundError(f"missing member file: {path}")

    # Build manifest (without self-reference)
    manifest = _build_manifest(members)
    manifest_path = EVIDENCE / "PACKAGE_MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )

    # The manifest is included in the ZIP but NOT in the manifest's own
    # members array. The verifier must check it separately.
    all_members = members + [("PACKAGE_MANIFEST.json", manifest_path)]

    # Build the ZIP deterministically
    with zipfile.ZipFile(
        OUTPUT_ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as zf:
        for arcname, path in all_members:
            zf.write(path, arcname)

    # Compute final SHA256
    zip_sha = _sha256_file(OUTPUT_ZIP)
    sidecar = OUTPUT_ZIP.with_suffix(".zip.sha256")
    sidecar.write_text(f"{zip_sha}  {OUTPUT_ZIP.name}\n", encoding="utf-8")

    # Print summary
    print("BUILD_OK")
    print(f"OUTPUT_ZIP={OUTPUT_ZIP}")
    print(f"OUTPUT_ZIP_SHA256={zip_sha}")
    print(f"MEMBER_COUNT={len(all_members)}")
    print(f"PACKAGE_STATUS={manifest['package_status']}")
    print(f"IS_OFFICIAL_OWNER_REVIEW={manifest['is_official_owner_review_package']}")


if __name__ == "__main__":
    main()
