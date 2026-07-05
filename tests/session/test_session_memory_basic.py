#!/usr/bin/env python3
"""
Test Session Memory Integration (Basic)

Tests the SessionMemory class and basic integration without database writes.
"""

import asyncio
import tempfile
from pathlib import Path


async def test_session_memory_basic():
    """Test session memory basic functionality"""
    print("=" * 70)
    print("Testing Session Memory Integration (Basic)")
    print("=" * 70)
    
    # Test 1: Import modules
    print("\n[1/6] Testing imports...")
    try:
        from flocks.session import SessionMemory, SessionInfo
        from flocks.memory import MemoryConfig
        print("✅ Successfully imported session memory modules")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: Create SessionMemory instance (disabled)
    print("\n[2/6] Testing SessionMemory creation (disabled)...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = SessionMemory(
                session_id="test_session",
                project_id="test_proj",
                workspace_dir=tmpdir,
                enabled=False,
            )
            
            print(f"   Session ID: {memory.session_id}")
            print(f"   Project ID: {memory.project_id}")
            print(f"   Enabled: {memory.enabled}")
            print(f"   Initialized: {memory._initialized}")
            
            assert memory.session_id == "test_session"
            assert memory.project_id == "test_proj"
            assert memory.enabled == False
            assert memory._initialized == False
            
            print("✅ SessionMemory creation (disabled) working")
    except Exception as e:
        print(f"❌ SessionMemory creation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 3: Create SessionMemory instance (enabled)
    print("\n[3/6] Testing SessionMemory creation (enabled)...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = SessionMemory(
                session_id="test_session",
                project_id="test_proj",
                workspace_dir=tmpdir,
                enabled=True,
            )
            
            print(f"   Session ID: {memory.session_id}")
            print(f"   Enabled: {memory.enabled}")
            
            assert memory.enabled == True
            
            print("✅ SessionMemory creation (enabled) working")
    except Exception as e:
        print(f"❌ SessionMemory creation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: Test disabled memory operations
    print("\n[4/6] Testing disabled memory operations...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            memory = SessionMemory(
                session_id="test_session",
                project_id="test_proj",
                workspace_dir=tmpdir,
                enabled=False,
            )
            
            # Search should return empty
            results = await memory.search("test query")
            print(f"   Search results: {len(results)}")
            assert results == [], "Should return empty list when disabled"
            
            # Write should return None
            path = await memory.write("test content")
            print(f"   Write result: {path}")
            assert path is None, "Should return None when disabled"
            
            # Sync should return error dict
            stats = await memory.sync()
            print(f"   Sync result: {stats}")
            assert "error" in stats, "Should return error dict when disabled"
            
            print("✅ Disabled memory operations working correctly")
    except Exception as e:
        print(f"❌ Disabled memory test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Test SessionInfo with memory_enabled
    print("\n[5/6] Testing SessionInfo with memory_enabled...")
    try:
        session_info = SessionInfo(
            project_id="test_proj",
            directory="/tmp/test",
            memory_enabled=True,
        )
        
        print(f"   Session ID: {session_info.id}")
        print(f"   Memory enabled: {session_info.memory_enabled}")
        
        assert hasattr(session_info, "memory_enabled"), "Should have memory_enabled field"
        assert session_info.memory_enabled == True, "Should be enabled"
        
        # Test disabled
        session_info2 = SessionInfo(
            project_id="test_proj",
            directory="/tmp/test",
            memory_enabled=False,
        )
        
        assert session_info2.memory_enabled == False, "Should be disabled"
        
        print("✅ SessionInfo memory_enabled field working")
    except Exception as e:
        print(f"❌ SessionInfo test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 6: Test cache management
    print("\n[6/6] Testing SessionMemory cache...")
    try:
        # Check cache is initially empty
        initial_count = len(SessionMemory._managers)
        print(f"   Initial cache count: {initial_count}")
        
        # Create memory instances
        memory1 = SessionMemory(
            session_id="session1",
            project_id="proj",
            workspace_dir="/tmp",
            enabled=False,
        )
        
        memory2 = SessionMemory(
            session_id="session2",
            project_id="proj",
            workspace_dir="/tmp",
            enabled=False,
        )
        
        print(f"   Created 2 memory instances")
        
        # Clear cache
        SessionMemory.clear_cache()
        cleared_count = len(SessionMemory._managers)
        print(f"   After clear: {cleared_count}")
        
        assert cleared_count == 0, "Cache should be empty after clear"
        
        print("✅ SessionMemory cache management working")
    except Exception as e:
        print(f"❌ Cache management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 70)
    print("✅ All Session Memory basic tests passed!")
    print("=" * 70)
    
    print("\n📋 Session Memory Integration Ready:")
    print("   ✅ SessionMemory class")
    print("   ✅ SessionInfo.memory_enabled field")
    print("   ✅ Enabled/disabled state management")
    print("   ✅ Graceful disabled operations")
    print("   ✅ Cache management")
    
    print("\n🎯 Integration Points:")
    print("   • SessionInfo has memory_enabled flag")
    print("   • SessionMemory bridges Session and MemoryManager")
    print("   • Session.get_memory() provides access")
    print("   • Auto-initialization when enabled")
    
    print("\n⚠️  Note: Full integration test requires writable database")
    print("   Use 'python test_session_memory.py' with proper permissions")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_session_memory_basic())
    exit(0 if success else 1)
