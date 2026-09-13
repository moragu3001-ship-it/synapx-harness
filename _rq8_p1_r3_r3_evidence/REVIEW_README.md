================================================================================
SYNAPX-HARNESS RQ8-P1-R3-R3 — Code-Repair Review ZIP (convenience build)
================================================================================

STATUS: R3_R3_CODE_REPAIR_COMPLETE_SEED_CUSTODY_BLOCKED

This ZIP is a CONVENIENCE bundle for Owner review of the R3-R3 code-repair
work only. It is NOT the official R3-R3 Owner Review package and is NOT
eligible for ACCEPT.

The official Owner Review package (§36-§38 of the R3-R3 spec) is BLOCKED
because the canonical seed artifact is missing on this PC
(SEED_ARTIFACT_CUSTODY_BLOCKED; see RQ8_SEED_ARTIFACT_VERIFICATION.json).

--------------------------------------------------------------------------------
WHAT THIS ZIP CONTAINS
--------------------------------------------------------------------------------

  R3-R3 code-repair evidence only:
    - branch census of all post-comparator paths
    - pre-repair RED lineage evidence (F1/F2/F3 gaps)
    - post-repair targeted + full regression logs
    - static check logs (ruff, pyright) for the changed files
    - source diff vs R3-R2 baseline
    - start/final revision bindings

  R3-R3 source changes:
    - command_runner.py (artifact_dir bounded extension)
    - governed_execution.py (post-comparator lineage propagation)
    - 2 new R3-R3 contract test files

  WHAT THIS ZIP DELIBERATELY EXCLUDES (because they do not exist on this PC):

    - RQ8_ITS_DANGEROUS_COMPRESSED_PAYLOAD_SEED.patch
      Required path: C:\rq8\seeds\RQ8_ITS_DANGEROUS_COMPRESSED_PAYLOAD_SEED.patch
      Expected SHA256: 142FB0FC583D5AA001DCD02100778EE13DAE792A632C351C71D22CD04697BD9A
      Actual: NOT FOUND on New PC
      R3-R3 §19 prohibits generating new patch bytes. Owner must deliver
      canonical bytes to Old PC for Phase C to proceed.

    - RQ8_ITS_DANGEROUS_QUALIFIED_RED_EXPECTATION.json
      Not generated: per R3-R3 §25 must be produced by independent
      Old-PC fixture-authoring run, NOT from New-PC observation.

    - RQ8_ITS_DANGEROUS_EXPECTATION_GENERATION_RECEIPT.json
      Not generated: depends on the qualified expectation + canonical seed.

    - RQ8_ITS_DANGEROUS_EXPECTATION_RAW_RED.log
      Not generated: depends on independent Old-PC seeded pytest run.

    - SYNAPX_HARNESS_RQ8_P1_R3_R3_OWNER_REVIEW.zip
      Not built: spec §20 forbids building the Owner package when seed
      custody is BLOCKED. Worker Maximum Declaration (READY_FOR_RQ8_P1_R3_R3_OWNER_REVIEW)
      is therefore WITHHELD.

--------------------------------------------------------------------------------
WHAT THE OWNER MUST DO NEXT
--------------------------------------------------------------------------------

  1. Deliver the canonical seed patch bytes to the Old PC:
       path: C:\rq8\seeds\RQ8_ITS_DANGEROUS_COMPRESSED_PAYLOAD_SEED.patch
       sha256: 142FB0FC583D5AA001DCD02100778EE13DAE792A632C351C71D22CD04697BD9A

  2. On the Old PC, clone pallets/itsdangerous at revision
     672971d66a2ef9f85151e53283113f33d642dabd and apply the canonical patch.
     Baseline: 297 passed. Seeded: 24 failed / 273 passed. Exact mismatch
     aborts as RQ8_FIXTURE_DRIFT (R3-R3 §23).

  3. On the Old PC, regenerate the qualified expectation and the
     expectation generation receipt without consulting the New-PC observation
     (R3-R3 §25).

  4. Hand-deliver the resulting expectation + receipt + raw-red log to the
     New PC.

  5. Worker will then build the official R3-R3 Owner Review package per
     §36-§38 and §40.

--------------------------------------------------------------------------------
FORWARD LINEAGE (preserved, not squashed, not amended)
--------------------------------------------------------------------------------

  b9c1683  initial
    |
  da64adc  REJECTED (preserved for lineage)
    |
  27c8d08
    |
  e684cf20
    |
  1060f8e2
    |
  95431b37  R3-R2 (baseline of this review)
    |
  31c28d69  R3-R3 code repair (Phase A + Phase B)
    |
  6e65ace5  R3-R3 final revision binding v1
    |
  801c2989  R3-R3 final revision binding v2 (absolute HEAD)

--------------------------------------------------------------------------------
VERIFICATION SUMMARY
--------------------------------------------------------------------------------

  Targeted tests (R3-R1 + R3-R2 + R3-R3):
    58 passed in 14.51s

  Full regression:
    1267 passed, 1 skipped, 1 xfail

  Ruff (R3-R3 changed files):
    All checks passed!

  Pyright (R3-R3 changed files):
    0 errors, 0 warnings, 0 informations

  git diff --check:
    clean

  git diff -w --name-only -- src tests (logical scope):
    empty (no EOL collateral)

--------------------------------------------------------------------------------
DECLARATIONS WITHHELD
--------------------------------------------------------------------------------

  Per R3-R3 §40, the following declarations are withheld until ALL gates
  pass (currently blocked by seed custody):

    - READY_FOR_RQ8_P1_R3_R3_OWNER_REVIEW  (NOT declared)
    - RQ8 P1 PASS                          (NOT declared)
    - RQ8 CLOSED                           (NOT declared)
    - PUBLIC_ALPHA_READY                   (NOT declared)
    - PUBLIC_ALPHA_RELEASED                (NOT declared)

================================================================================
END OF README
================================================================================
