"""Independent verification of the R3-R3 code-repair review ZIP.

Runs in a separate process from the builder to avoid self-validation.
Per R3-R3 §39, ZIP bytes are re-read from disk and every gate is recomputed
without trusting the builder's claims.
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path


REPO = Path("C:\\krag_work\\synapx_harness_rq0_bootstrap")
ZIP_PATH = (
    REPO / "SYNAPX_HARNESS_RQ8_P1_R3_R3_CODE_REPAIR_REVIEW.zip"
)
SIDE_CAR = ZIP_PATH.with_suffix(".zip.sha256")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if not ZIP_PATH.is_file():
        print(f"FAIL: ZIP not found at {ZIP_PATH}")
        return 1

    zip_bytes = ZIP_PATH.read_bytes()
    actual_zip_sha = _sha256_bytes(zip_bytes)
    print(f"zip_sha256={actual_zip_sha}")
    print(f"zip_size_bytes={len(zip_bytes)}")

    # --- Sidecar verification ---
    side_text = SIDE_CAR.read_text(encoding="utf-8").strip()
    expected_side_sha, _, name = side_text.partition("  ")
    if actual_zip_sha != expected_side_sha:
        print(
            f"FAIL: sidecar mismatch -- zip {actual_zip_sha} != "
            f"sidecar {expected_side_sha}"
        )
        return 1
    print("PASS: zip_sha256 matches sidecar")

    # --- ZIP structural verification ---
    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        # CRC test
        bad = zf.testzip()
        if bad is not None:
            print(f"FAIL: CRC error on member {bad}")
            return 1
        print("PASS: zip_crc (testzip)")

        # Duplicate name detection
        names: list[str] = []
        for info in zf.infolist():
            names.append(info.filename)
        seen: set[str] = set()
        duplicates: list[str] = []
        for n in names:
            if n in seen:
                duplicates.append(n)
            seen.add(n)
        if duplicates:
            print(f"FAIL: duplicate members: {duplicates}")
            return 1
        print(f"PASS: duplicate_count=0 (members={len(names)})")

        # Member hashes
        member_hashes: dict[str, str] = {}
        for info in zf.infolist():
            data = zf.read(info.filename)
            member_hashes[info.filename] = _sha256_bytes(data)
        print(f"PASS: member_hashes computed ({len(member_hashes)} members)")

        # Manifest bijection (PACKAGE_MANIFEST.json is in ZIP but excluded
        # from its own members array to avoid circular self-reference)
        manifest_data = json.loads(
            zf.read("PACKAGE_MANIFEST.json").decode("utf-8")
        )
        print("PASS: manifest_json_parse")
        manifest_names = {m["name"] for m in manifest_data["members"]}
        zip_names = set(names)
        # Manifest is expected to be in ZIP but NOT in manifest.members
        declared_in_zip = zip_names - manifest_names
        declared_in_manifest = manifest_names - zip_names
        # Allowed: PACKAGE_MANIFEST.json is in ZIP but not in its own members
        if declared_in_manifest:
            print(
                f"FAIL: manifest names not present in ZIP: {declared_in_manifest}"
            )
            return 1
        unexpected_in_zip = declared_in_zip - {"PACKAGE_MANIFEST.json"}
        if unexpected_in_zip:
            print(
                f"FAIL: ZIP has unexpected members not in manifest: "
                f"{unexpected_in_zip}"
            )
            return 1
        if "PACKAGE_MANIFEST.json" not in zip_names:
            print("FAIL: PACKAGE_MANIFEST.json not in ZIP members")
            return 1
        print("PASS: manifest_bijection (manifest members + manifest file)")

        # Each manifest member hash must equal the actual member sha
        for entry in manifest_data["members"]:
            actual = member_hashes[entry["name"]]
            if actual != entry["sha256"]:
                print(
                    f"FAIL: member hash mismatch -- {entry['name']} "
                    f"manifest {entry['sha256']} != actual {actual}"
                )
                return 1
        print("PASS: every manifest sha256 == member sha256")

        # JSON parse for every JSON member
        for n in names:
            if n.endswith(".json"):
                zf.read(n)  # ensure no decode error first
                try:
                    json.loads(zf.read(n).decode("utf-8"))
                except Exception as exc:
                    print(f"FAIL: json_parse error in {n}: {exc}")
                    return 1
        print("PASS: json_parse for all *.json members")

        # Status gate
        status = manifest_data.get("package_status", "")
        if status != "R3_R3_CODE_REPAIR_COMPLETE_SEED_CUSTODY_BLOCKED":
            print(f"FAIL: package_status expected BLOCKED, got {status!r}")
            return 1
        if manifest_data.get("is_official_owner_review_package") is not False:
            print("FAIL: is_official_owner_review_package must be False")
            return 1
        print("PASS: package_status BLOCKED + is_official_owner_review=False")

        # Check for placeholders / obviously-PENDING strings
        forbidden_tokens = ["PENDING", "TBD", "TODO", "<PLACEHOLDER>"]
        for n in names:
            text = zf.read(n).decode("utf-8", errors="replace")
            for tok in forbidden_tokens:
                if tok in text:
                    print(f"FAIL: forbidden token {tok!r} in member {n}")
                    return 1
        print("PASS: no PENDING/TBD/TODO placeholders in any member")

    print()
    print("ALL_GATES_PASS")
    print(
        "REMINDER: this ZIP is a CONVENIENCE bundle for Owner review "
        "only. The official R3-R3 Owner Review package remains BLOCKED "
        "per R3-R3 §20 until the canonical seed patch bytes are "
        "delivered to the Old PC."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
