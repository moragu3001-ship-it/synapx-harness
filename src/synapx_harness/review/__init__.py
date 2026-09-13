"""Review package: submodule surface."""
from synapx_harness.review.package_scope import (
    CORE_DIR_ALLOWLIST,
    CORE_FILE_ALLOWLIST,
    SERVICE_PACK_DIR_ALLOWLIST,
    SERVICE_PACK_FILE_ALLOWLIST,
    filter_allowed_paths,
    is_excluded,
    is_path_allowed,
    iter_scope_files,
    normalize_path,
)

__all__ = [
    "CORE_DIR_ALLOWLIST",
    "CORE_FILE_ALLOWLIST",
    "SERVICE_PACK_DIR_ALLOWLIST",
    "SERVICE_PACK_FILE_ALLOWLIST",
    "filter_allowed_paths",
    "is_excluded",
    "is_path_allowed",
    "iter_scope_files",
    "normalize_path",
]
