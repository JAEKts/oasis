"""
OASIS Vault Storage System

Provides hierarchical project-based storage with version control and change tracking.
"""

# Import both implementations
from .sqlite_vault import SQLiteVaultStorage
from .json_vault import JSONVaultStorage

# Use SQLite implementation by default
VaultStorage = SQLiteVaultStorage

# Export both for backward compatibility
__all__ = ["VaultStorage", "SQLiteVaultStorage", "JSONVaultStorage"]
