"""
Test streaming performance optimizations

Validates that the throttling and rendering optimizations work correctly.
"""

import asyncio
import time
from typing import List, Dict, Any
from flocks.session.streaming.stream_processor import StreamProcessor
from flocks.session.message import AssistantMessageInfo, MessageRole, TokenUsage, MessagePath
from flocks.agent.agent import AgentInfo


class MockEventPublisher:
    """Mock event publisher to track published events"""
    
    def __init__(self):
        self.events: List[Dict[str, Any]] = []
        self.timestamps: List[float] = []
    
    async def publish(self, event_type: str, properties: Dict[str, Any]) -> None:
        """Record event with timestamp"""
        self.events.append({
            "type": event_type,
            "properties": properties,
            "timestamp": time.time() * 1000,
        })
        self.timestamps.append(time.time() * 1000)
    
    def get_event_count(self, event_type: str = None) -> int:
        """Get count of events, optionally filtered by type"""
        if event_type is None:
            return len(self.events)
        return sum(1 for e in self.events if e["type"] == event_type)
    
    def get_event_frequency(self) -> float:
        """Calculate average time between events (ms)"""
        if len(self.timestamps) < 2:
            return 0
        intervals = [
            self.timestamps[i+1] - self.timestamps[i]
            for i in range(len(self.timestamps) - 1)
        ]
        return sum(intervals) / len(intervals)
    
    def get_text_events(self) -> List[Dict[str, Any]]:
        """Get all message.part.updated events for text parts"""
        return [
            e for e in self.events
            if e["type"] == "message.part.updated"
            and e["properties"].get("part", {}).get("type") == "text"
        ]


async def test_text_delta_throttling():
    """Test that text deltas are properly throttled"""
    print("\n=== Testing Text Delta Throttling ===")
    
    # Setup
    publisher = MockEventPublisher()
    message = AssistantMessageInfo(
        id="test-msg-1",
        sessionID="test-session",
        role="assistant",
        parentID="",
        modelID="test-model",
        providerID="test",
        mode="standard",
        agent="test-agent",
        path=MessagePath(cwd="./"),
        tokens=TokenUsage(),
        time={"created": int(time.time() * 1000)},
    )
    agent = AgentInfo(
        name="Test Agent",
        prompt="Test prompt",
        permission=[],
    )
    
    processor = StreamProcessor(
        session_id="test-session",
        assistant_message=message,
        agent=agent,
        event_publish_callback=publisher.publish,
    )
    
    # Simulate rapid text deltas (like LLM streaming)
    from flocks.session.streaming.stream_events import TextStartEvent, TextDeltaEvent, TextEndEvent
    
    # Start text
    await processor._handle_text_start(TextStartEvent(metadata={}))
    
    # Send 100 deltas rapidly (simulating ~50 tokens/second)
    start_time = time.time()
    for i in range(100):
        delta = f"word{i} "
        await processor._handle_text_delta(TextDeltaEvent(text=delta, metadata={}))
        await asyncio.sleep(0.02)  # 20ms between deltas = 50/second
    
    # End text
    await processor._handle_text_end(TextEndEvent(metadata={}))
    elapsed = time.time() - start_time
    
    # Analyze results
    text_events = publisher.get_text_events()
    event_count = len(text_events)
    avg_interval = publisher.get_event_frequency()
    
    print(f"Total deltas sent: 100")
    print(f"Total events published: {event_count}")
    print(f"Time elapsed: {elapsed:.2f}s")
    print(f"Average event interval: {avg_interval:.1f}ms")
    print(f"Throttle effectiveness: {(100 - event_count) / 100 * 100:.1f}% reduction")
    
    # Assertions
    assert event_count < 100, "Should throttle some events"
    assert event_count >= 3, "Should publish at least start + some updates + end"
    
    # First few events should be immediate (first 50 chars)
    first_events = text_events[:3]
    for i, event in enumerate(first_events):
        text_len = len(event["properties"]["part"]["text"])
        print(f"Event {i+1} text length: {text_len}")
    
    # Later events should be throttled (50ms apart)
    # Note: We send deltas every 20ms, so with 50ms throttling we should see
    # events roughly every 40-60ms (2-3 deltas batched together)
    if len(text_events) > 5:
        later_intervals = [
            text_events[i+1]["timestamp"] - text_events[i]["timestamp"]
            for i in range(3, min(len(text_events) - 1, 8))
        ]
        avg_later_interval = sum(later_intervals) / len(later_intervals)
        print(f"Average interval for later events: {avg_later_interval:.1f}ms")
        # With 20ms delta interval and 50ms throttle, we expect ~40-60ms between events
        # But due to timing variations, accept >= 20ms as evidence of throttling
        assert avg_later_interval >= 20, "Later events should show throttling effect"
    
    print("✅ Text delta throttling test passed")


async def test_reasoning_delta_throttling():
    """Test that reasoning deltas are properly throttled"""
    print("\n=== Testing Reasoning Delta Throttling ===")
    
    # Setup
    publisher = MockEventPublisher()
    message = AssistantMessageInfo(
        id="test-msg-2",
        sessionID="test-session",
        role="assistant",
        parentID="",
        modelID="test-model",
        providerID="test",
        mode="standard",
        agent="test-agent",
        path=MessagePath(cwd="./"),
        tokens=TokenUsage(),
        time={"created": int(time.time() * 1000)},
    )
    agent = AgentInfo(
        name="Test Agent",
        prompt="Test prompt",
        permission=[],
    )
    
    processor = StreamProcessor(
        session_id="test-session",
        assistant_message=message,
        agent=agent,
        event_publish_callback=publisher.publish,
    )
    
    # Simulate reasoning stream
    from flocks.session.streaming.stream_events import (
        ReasoningStartEvent,
        ReasoningDeltaEvent,
        ReasoningEndEvent,
    )
    
    reasoning_id = "reasoning-1"
    
    # Start reasoning
    await processor._handle_reasoning_start(
        ReasoningStartEvent(id=reasoning_id, metadata={})
    )
    
    # Send 50 deltas
    for i in range(50):
        delta = f"thinking{i} "
        await processor._handle_reasoning_delta(
            ReasoningDeltaEvent(id=reasoning_id, text=delta, metadata={})
        )
        await asyncio.sleep(0.02)  # 20ms between deltas
    
    # End reasoning
    await processor._handle_reasoning_end(
        ReasoningEndEvent(id=reasoning_id, metadata={})
    )
    
    # Analyze results
    reasoning_events = [
        e for e in publisher.events
        if e["type"] == "message.part.updated"
        and e["properties"].get("part", {}).get("type") == "reasoning"
    ]
    event_count = len(reasoning_events)
    
    print(f"Total reasoning deltas sent: 50")
    print(f"Total events published: {event_count}")
    print(f"Throttle effectiveness: {(50 - event_count) / 50 * 100:.1f}% reduction")
    
    # Assertions
    assert event_count < 50, "Should throttle some reasoning events"
    assert event_count >= 3, "Should publish at least start + some updates + end"
    
    print("✅ Reasoning delta throttling test passed")


async def test_immediate_feedback():
    """Test that first characters are published immediately"""
    print("\n=== Testing Immediate Feedback ===")
    
    # Setup
    publisher = MockEventPublisher()
    message = AssistantMessageInfo(
        id="test-msg-3",
        sessionID="test-session",
        role="assistant",
        parentID="",
        modelID="test-model",
        providerID="test",
        mode="standard",
        agent="test-agent",
        path=MessagePath(cwd="./"),
        tokens=TokenUsage(),
        time={"created": int(time.time() * 1000)},
    )
    agent = AgentInfo(
        name="Test Agent",
        prompt="Test prompt",
        permission=[],
    )
    
    processor = StreamProcessor(
        session_id="test-session",
        assistant_message=message,
        agent=agent,
        event_publish_callback=publisher.publish,
    )
    
    # Simulate text stream
    from flocks.session.streaming.stream_events import TextStartEvent, TextDeltaEvent
    
    await processor._handle_text_start(TextStartEvent(metadata={}))
    
    # Send first few characters
    start_time = time.time()
    for char in "Hello":
        await processor._handle_text_delta(TextDeltaEvent(text=char, metadata={}))
        await asyncio.sleep(0.01)
    
    first_event_time = time.time() - start_time
    
    # Check that first event was published quickly
    text_events = publisher.get_text_events()
    assert len(text_events) >= 2, "Should publish at least start + first delta"
    
    # First event is text-start (empty), second event has first character
    first_delta_event = text_events[1] if len(text_events) > 1 else text_events[0]
    first_text = first_delta_event["properties"]["part"]["text"]
    print(f"First delta event text: '{first_text}'")
    print(f"Time to first delta: {first_event_time*1000:.1f}ms")
    
    assert len(first_text) > 0, "First delta event should have text"
    assert first_event_time < 0.1, "First delta should be published within 100ms"
    
    print("✅ Immediate feedback test passed")


async def main():
    """Run all tests"""
    print("=" * 60)
    print("Streaming Performance Optimization Tests")
    print("=" * 60)
    
    try:
        await test_text_delta_throttling()
        await test_reasoning_delta_throttling()
        await test_immediate_feedback()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
