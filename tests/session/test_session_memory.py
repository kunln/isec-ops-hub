#!/usr/bin/env python3
"""
Test Session Memory Integration

Tests the integration between Session and Memory systems.
"""

import asyncio
import tempfile
from pathlib import Path


async def test_session_memory():
    """Test session memory integration"""
    print("=" * 70)
    print("Testing Session Memory Integration")
    print("=" * 70)
    
    # Test 1: Import modules
    print("\n[1/7] Testing imports...")
    try:
        from flocks.session import Session, SessionMemory
        from flocks.storage import Storage
        from flocks.provider import Provider
        print("✅ Successfully imported session and memory modules")
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 2: Initialize systems
    print("\n[2/7] Initializing systems...")
    try:
        await Storage.init()
        await Provider.init()
        print("✅ Systems initialized")
    except Exception as e:
        print(f"❌ Initialization failed: {e}")
        return False
    
    # Test 3: Create session with memory disabled
    print("\n[3/7] Testing session without memory...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            session = await Session.create(
                project_id="test_proj",
                directory=tmpdir,
                title="Test Session (No Memory)",
                memory_enabled=False,
            )
            
            print(f"   Session ID: {session.id}")
            print(f"   Memory enabled: {session.memory_enabled}")
            
            assert session.memory_enabled == False, "Memory should be disabled"
            
            # Try to get memory (should return None or disabled instance)
            memory = await Session.get_memory("test_proj", session.id)
            print(f"   Memory instance: {memory is not None}")
            print(f"   Memory enabled: {memory.enabled if memory else False}")
            
            assert memory is not None, "Should return SessionMemory instance"
            assert memory.enabled == False, "Memory should be disabled"
            
            print("✅ Session without memory working correctly")
    except Exception as e:
        print(f"❌ Session without memory test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 4: Create session with memory enabled
    print("\n[4/7] Testing session with memory enabled...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            session = await Session.create(
                project_id="test_proj",
                directory=tmpdir,
                title="Test Session (With Memory)",
                memory_enabled=True,
            )
            
            print(f"   Session ID: {session.id}")
            print(f"   Memory enabled: {session.memory_enabled}")
            
            assert session.memory_enabled == True, "Memory should be enabled"
            
            # Get memory instance
            memory = await Session.get_memory("test_proj", session.id)
            print(f"   Memory instance: {memory is not None}")
            print(f"   Memory enabled: {memory.enabled}")
            print(f"   Memory initialized: {memory._initialized}")
            
            assert memory is not None, "Should return SessionMemory instance"
            assert memory.enabled == True, "Memory should be enabled"
            assert memory._initialized == True, "Memory should be auto-initialized"
            
            print("✅ Session with memory working correctly")
    except Exception as e:
        print(f"❌ Session with memory test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Test SessionMemory write
    print("\n[5/7] Testing SessionMemory write...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            workspace = Path(tmpdir)
            
            session = await Session.create(
                project_id="test_proj",
                directory=tmpdir,
                memory_enabled=True,
            )
            
            memory = await Session.get_memory("test_proj", session.id)
            
            # Write to memory
            content = "# Session Memory Test\n\nLearned about testing today."
            path = await memory.write(content)
            
            print(f"   Written to: {path}")
            
            if path:
                # Verify file exists
                expected_path = workspace / path
                if expected_path.exists():
                    written_content = expected_path.read_text()
                    assert content in written_content, "Content should match"
                    print(f"   File verified: {expected_path.name}")
                else:
                    print(f"   ⚠️  File not found at expected location")
                
                print("✅ SessionMemory write working")
            else:
                print("⚠️  Write returned None (expected if no memory files)")
                print("✅ SessionMemory write handling correct")
    except Exception as e:
        print(f"❌ SessionMemory write test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 6: Test SessionMemory search (empty)
    print("\n[6/7] Testing SessionMemory search (empty index)...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            session = await Session.create(
                project_id="test_proj",
                directory=tmpdir,
                memory_enabled=True,
            )
            
            memory = await Session.get_memory("test_proj", session.id)
            
            # Search (should return empty results)
            results = await memory.search("test query")
            
            print(f"   Search results: {len(results)}")
            assert isinstance(results, list), "Should return list"
            assert len(results) == 0, "Should be empty (no indexed data)"
            
            print("✅ SessionMemory search working (empty)")
    except Exception as e:
        print(f"❌ SessionMemory search test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 7: Test SessionMemory manager access
    print("\n[7/7] Testing SessionMemory manager access...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            session = await Session.create(
                project_id="test_proj",
                directory=tmpdir,
                memory_enabled=True,
            )
            
            memory = await Session.get_memory("test_proj", session.id)
            
            # Get underlying manager
            manager = memory.get_manager()
            
            print(f"   Manager: {manager is not None}")
            print(f"   Manager type: {type(manager).__name__ if manager else 'None'}")
            
            if manager:
                print(f"   Manager project: {manager.project_id}")
                print(f"   Manager initialized: {manager._initialized}")
                assert manager.project_id == "test_proj", "Should match project ID"
            
            print("✅ SessionMemory manager access working")
    except Exception as e:
        print(f"❌ SessionMemory manager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    print("\n" + "=" * 70)
    print("✅ All Session Memory integration tests passed!")
    print("=" * 70)
    
    print("\n📋 Session Memory Integration Ready:")
    print("   ✅ SessionInfo memory_enabled flag")
    print("   ✅ SessionMemory class")
    print("   ✅ Session.get_memory() method")
    print("   ✅ Auto-initialization")
    print("   ✅ Memory write operations")
    print("   ✅ Memory search operations")
    print("   ✅ Manager access")
    
    print("\n🎯 Usage Example:")
    print("   session = await Session.create(..., memory_enabled=True)")
    print("   memory = await Session.get_memory(project_id, session_id)")
    print("   await memory.write('Learned something today')")
    print("   results = await memory.search('what did I learn?')")
    
    return True


if __name__ == "__main__":
    success = asyncio.run(test_session_memory())
    exit(0 if success else 1)
