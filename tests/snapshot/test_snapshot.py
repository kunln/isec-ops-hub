"""
Tests for snapshot module

Tests Git-based snapshot functionality including tracking,
patching, restoring, and reverting file changes.
"""

import os
import asyncio
import tempfile
import shutil
import pytest
from pathlib import Path

from flocks.snapshot import Snapshot, SnapshotPatch, FileDiff


class TestSnapshotBasics:
    """Basic snapshot functionality tests"""
    
    def setup_method(self):
        """Set up test environment"""
        # Create temporary directory for tests
        self.test_dir = tempfile.mkdtemp(prefix="flocks_snapshot_test_")
        self.project_id = "test_project"
        
        # Initialize a git repo in test directory (required for snapshots)
        os.system(f"cd {self.test_dir} && git init -q")
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @pytest.mark.asyncio
    async def test_track_creates_snapshot(self):
        """Test that track creates a snapshot hash"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World!")
        
        # Track snapshot
        hash = await Snapshot.track(self.project_id, self.test_dir)
        
        assert hash is not None
        assert len(hash) == 40  # Git SHA-1 hash length
    
    @pytest.mark.asyncio
    async def test_track_returns_same_hash_for_unchanged_files(self):
        """Test that tracking unchanged files returns the same hash"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World!")
        
        # Track twice
        hash1 = await Snapshot.track(self.project_id, self.test_dir)
        hash2 = await Snapshot.track(self.project_id, self.test_dir)
        
        assert hash1 == hash2
    
    @pytest.mark.asyncio
    async def test_track_returns_different_hash_for_changed_files(self):
        """Test that tracking changed files returns different hash"""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World!")
        
        # Track first snapshot
        hash1 = await Snapshot.track(self.project_id, self.test_dir)
        
        # Modify file
        with open(test_file, "w") as f:
            f.write("Hello, Modified World!")
        
        # Track second snapshot
        hash2 = await Snapshot.track(self.project_id, self.test_dir)
        
        assert hash1 != hash2


class TestSnapshotPatch:
    """Tests for patch functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="flocks_snapshot_test_")
        self.project_id = "test_project"
        os.system(f"cd {self.test_dir} && git init -q")
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @pytest.mark.asyncio
    async def test_patch_detects_changed_files(self):
        """Test that patch detects changed files"""
        # Create initial file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Initial content")
        
        # Track initial state
        initial_hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Modify file
        with open(test_file, "w") as f:
            f.write("Modified content")
        
        # Get patch
        patch = await Snapshot.patch(self.project_id, self.test_dir, initial_hash)
        
        assert patch.hash == initial_hash
        assert len(patch.files) == 1
        assert "test.txt" in patch.files[0]
    
    @pytest.mark.asyncio
    async def test_patch_detects_new_files(self):
        """Test that patch detects new files"""
        # Create initial file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Initial content")
        
        # Track initial state
        initial_hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Add new file
        new_file = os.path.join(self.test_dir, "new.txt")
        with open(new_file, "w") as f:
            f.write("New file content")
        
        # Get patch
        patch = await Snapshot.patch(self.project_id, self.test_dir, initial_hash)
        
        assert len(patch.files) == 1
        assert "new.txt" in patch.files[0]
    
    @pytest.mark.asyncio
    async def test_patch_empty_when_no_changes(self):
        """Test that patch is empty when no changes"""
        # Create file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Content")
        
        # Track state
        hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Get patch without changes
        patch = await Snapshot.patch(self.project_id, self.test_dir, hash)
        
        assert len(patch.files) == 0


class TestSnapshotDiff:
    """Tests for diff functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="flocks_snapshot_test_")
        self.project_id = "test_project"
        os.system(f"cd {self.test_dir} && git init -q")
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @pytest.mark.asyncio
    async def test_diff_shows_changes(self):
        """Test that diff shows file changes"""
        # Create initial file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Line 1\nLine 2\n")
        
        # Track initial state
        initial_hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Modify file
        with open(test_file, "w") as f:
            f.write("Line 1\nLine 2 Modified\n")
        
        # Get diff
        diff = await Snapshot.diff(self.project_id, self.test_dir, initial_hash)
        
        assert diff is not None
        assert "test.txt" in diff
        assert "-Line 2" in diff
        assert "+Line 2 Modified" in diff
    
    @pytest.mark.asyncio
    async def test_diff_empty_when_no_changes(self):
        """Test that diff is empty when no changes"""
        # Create file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Content")
        
        # Track state
        hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Get diff without changes
        diff = await Snapshot.diff(self.project_id, self.test_dir, hash)
        
        assert diff == ""


class TestSnapshotRestore:
    """Tests for restore functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="flocks_snapshot_test_")
        self.project_id = "test_project"
        os.system(f"cd {self.test_dir} && git init -q")
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @pytest.mark.asyncio
    async def test_restore_reverts_file_content(self):
        """Test that restore reverts file to snapshot state"""
        # Create initial file
        test_file = os.path.join(self.test_dir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Initial content")
        
        # Track initial state
        initial_hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Modify file
        with open(test_file, "w") as f:
            f.write("Modified content")
        
        # Verify modification
        with open(test_file, "r") as f:
            assert f.read() == "Modified content"
        
        # Restore to initial state
        success = await Snapshot.restore(self.project_id, self.test_dir, initial_hash)
        
        assert success
        
        # Verify restoration
        with open(test_file, "r") as f:
            assert f.read() == "Initial content"


class TestSnapshotRevert:
    """Tests for revert functionality"""
    
    def setup_method(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp(prefix="flocks_snapshot_test_")
        self.project_id = "test_project"
        os.system(f"cd {self.test_dir} && git init -q")
    
    def teardown_method(self):
        """Clean up test environment"""
        if hasattr(self, 'test_dir') and os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    @pytest.mark.asyncio
    async def test_revert_specific_files(self):
        """Test that revert only affects specific files"""
        # Create two files
        file1 = os.path.join(self.test_dir, "file1.txt")
        file2 = os.path.join(self.test_dir, "file2.txt")
        
        with open(file1, "w") as f:
            f.write("File 1 initial")
        with open(file2, "w") as f:
            f.write("File 2 initial")
        
        # Track initial state
        initial_hash = await Snapshot.track(self.project_id, self.test_dir)
        
        # Modify both files
        with open(file1, "w") as f:
            f.write("File 1 modified")
        with open(file2, "w") as f:
            f.write("File 2 modified")
        
        # Revert only file1
        patch = SnapshotPatch(hash=initial_hash, files=[file1])
        await Snapshot.revert(self.project_id, self.test_dir, [patch])
        
        # Verify file1 reverted, file2 unchanged
        with open(file1, "r") as f:
            assert f.read() == "File 1 initial"
        with open(file2, "r") as f:
            assert f.read() == "File 2 modified"


class TestSnapshotModel:
    """Tests for Pydantic models"""
    
    def test_snapshot_patch_model(self):
        """Test SnapshotPatch model"""
        patch = SnapshotPatch(
            hash="abc123" * 6 + "ab",  # 40 char hash
            files=["/path/to/file1.txt", "/path/to/file2.txt"]
        )
        
        assert patch.hash == "abc123" * 6 + "ab"
        assert len(patch.files) == 2
    
    def test_file_diff_model(self):
        """Test FileDiff model"""
        diff = FileDiff(
            file="test.txt",
            before="old content",
            after="new content",
            additions=5,
            deletions=3
        )
        
        assert diff.file == "test.txt"
        assert diff.before == "old content"
        assert diff.after == "new content"
        assert diff.additions == 5
        assert diff.deletions == 3
    
    def test_file_diff_defaults(self):
        """Test FileDiff default values"""
        diff = FileDiff(file="test.txt")
        
        assert diff.before == ""
        assert diff.after == ""
        assert diff.additions == 0
        assert diff.deletions == 0


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
