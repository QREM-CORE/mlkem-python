"""
mlkem package top-level API and exports.

This file provides:
- package version (best-effort from installed metadata)
- lazy imports for submodules (PEP 562)
- a small helper to configure logging for the package
- a canonical __all__ for tooling and discoverability
"""
from __future__ import annotations

__all__ = [
    "__version__",
    "configure_logging",
    # add lazy-exported submodules or symbols you expect:
    "core",
    "kem",
    "params",
    "utils",
    "api",
]

# Version: try importlib.metadata, fall back to a safe default if package not installed
try:
    from importlib.metadata import version, PackageNotFoundError  # Python 3.8+
except Exception:  # pragma: no cover - best-effort fallback for older envs
    try:
        from importlib_metadata import version, PackageNotFoundError  # type: ignore
    except Exception:
        version = None
        PackageNotFoundError = Exception  # type: ignore

if version is not None:
    try:
        __version__ = version("mlkem")
    except PackageNotFoundError:
        __version__ = "0.0.0"
else:
    __version__ = "0.0.0"

# List of submodules to expose lazily. Adjust to real submodule names in the package.
_SUBMODULES = {"core", "kem", "params", "utils", "api"}

# Lazy import hook (PEP 562). Accessing e.g. `import mlkem; mlkem.kem` imports mlkem.kem.
def __getattr__(name: str):
    if name in _SUBMODULES:
        import importlib
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

def __dir__():
    return sorted(list(globals().keys()) + list(_SUBMODULES))

# Small utility to configure package logging
def configure_logging(level=None):
    """
    Configure logging for the mlkem package.

    Call configure_logging(logging.DEBUG) to enable debug output from the package modules.
    """
    import logging

    if level is None:
        level = logging.INFO
    logger = logging.getLogger("mlkem")
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)