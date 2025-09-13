import os
"""
Compatibility shim. The library has been moved to the `medcrypto` package.
Import from `medcrypto` instead of the project root. This file re-exports
the public API to avoid breaking existing imports.
"""

import warnings

warnings.warn(
    "Module 'encryption' moved to package 'medcrypto.encryption'. "
    "Please update imports to 'from medcrypto import ...'",
    DeprecationWarning,
    stacklevel=2,
)

from medcrypto.encryption import *  # noqa: F401,F403

