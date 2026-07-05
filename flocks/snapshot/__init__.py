"""
Snapshot module

Provides Git-based snapshot functionality for tracking and reverting file changes.
Based on Flocks' ported src/snapshot/index.ts
"""

from flocks.snapshot.snapshot import (
    Snapshot,
    SnapshotPatch,
    FileDiff,
)

__all__ = [
    "Snapshot",
    "SnapshotPatch",
    "FileDiff",
]
