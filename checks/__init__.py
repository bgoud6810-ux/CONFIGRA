"""
checks/__init__.py - Plug-in check discovery for Automated Security Misconfiguration Detector

Any module placed in this package that exports a `run(ctx)` function is
automatically discovered and executed by `core.runner.run_all()`.
"""

import importlib
import pkgutil
from typing import List, Any


def get_all_checks() -> List[Any]:
    """
    Dynamically discover all check modules inside the `checks` package
    that define a `run(ctx)` callable.
    """
    modules = []
    for _, module_name, is_pkg in pkgutil.iter_modules(__path__):
        if not is_pkg and not module_name.startswith("_"):
            try:
                mod = importlib.import_module(f"checks.{module_name}")
                if hasattr(mod, "run") and callable(getattr(mod, "run")):
                    modules.append(mod)
            except Exception as exc:
                print(f"[!] Warning: Failed to import check module 'checks.{module_name}': {exc}")

    # Return in deterministic order
    modules.sort(key=lambda m: m.__name__)
    return modules
