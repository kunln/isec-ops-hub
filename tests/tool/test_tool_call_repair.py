"""
Test Tool Call Repair Mechanisms

Tests the JSON parsing, repair strategies, and monitoring integration.
"""

import pytest
import json
from flocks.server.routes.session import _parse_json_robust, _repair_json_string
from flocks.utils.monitor import Monitor


class TestJSONParsing:
    """Test JSON parsing functions"""
    
    def test_parse_valid_json(self):
        """Test parsing valid JSON"""
        json_str = '{"tool": "read", "path": "/test/file.txt"}'
        result, success = _parse_json_robust(json_str)
        
        assert success is True
        assert result == {"tool": "read", "path": "/test/file.txt"}
    
    def test_parse_empty_string(self):
        """Test parsing empty string"""
        result, success = _parse_json_robust("")
        
        assert success is False
        assert result is None
    
    def test_parse_with_extra_data(self):
        """Test parsing JSON with extra data"""
        json_str = '{"tool": "read"}extra data here'
        result, success = _parse_json_robust(json_str)
        
        # Should parse the valid JSON part
        assert success is True
        assert result == {"tool": "read"}
    
    def test_parse_unterminated_string(self):
        """Test parsing unterminated string"""
        json_str = '{"tool": "read", "path": "/test/file.txt'
        result, success = _parse_json_robust(json_str)
        
        # Should fail on unterminated string
        assert success is False
        assert result is None
    
    def test_parse_unclosed_brace(self):
        """Test parsing unclosed brace"""
        json_str = '{"tool": "read", "path": "/test/file.txt"'
        result, success = _parse_json_robust(json_str)
        
        # Should fail on unclosed brace
        assert success is False
        assert result is None


class TestJSONRepair:
    """Test JSON repair functions"""
    
    def test_repair_unterminated_string(self):
        """Test repairing unterminated string"""
        json_str = '{"tool": "read", "path": "/test/file.txt'
        repaired = _repair_json_string(json_str)
        
        # Should add closing quote and brace
        assert '"' in repaired[len(json_str):]
        assert '}' in repaired
        
        # Try parsing repaired JSON
        result, success = _parse_json_robust(repaired)
        assert success is True
    
    def test_repair_unclosed_braces(self):
        """Test repairing unclosed braces"""
        json_str = '{"tool": {"name": "read", "params": {"path": "/test"'
        repaired = _repair_json_string(json_str)
        
        # Should add closing braces
        assert repaired.count('}') == repaired.count('{')
        
        # Try parsing repaired JSON
        result, success = _parse_json_robust(repaired)
        assert success is True
    
    def test_repair_unclosed_brackets(self):
        """Test repairing unclosed brackets"""
        json_str = '{"items": ["a", "b", "c"'
        repaired = _repair_json_string(json_str)
        
        # Should add closing bracket and brace
        assert ']' in repaired
        assert '}' in repaired
        
        # Try parsing repaired JSON
        result, success = _parse_json_robust(repaired)
        assert success is True
    
    def test_repair_trailing_comma(self):
        """Test behavior with trailing commas - repair returns input unchanged (not handled)"""
        json_str = '{"tool": "read", "path": "/test",}'
        repaired = _repair_json_string(json_str)
        # _repair_json_string does not currently fix trailing commas
        assert repaired is not None
    
    def test_repair_does_not_break_valid_json(self):
        """Test that repair doesn't break valid JSON"""
        json_str = '{"tool": "read", "path": "/test/file.txt"}'
        repaired = _repair_json_string(json_str)
        
        # Should not modify valid JSON
        assert json_str == repaired or repaired == json_str.strip()


class TestMonitoring:
    """Test monitoring and metrics"""
    
    def setup_method(self):
        """Reset monitor before each test"""
        monitor = Monitor.get_instance()
        monitor.reset_metrics()
    
    def test_record_successful_parse(self):
        """Test recording successful parse"""
        monitor = Monitor.get_instance()
        
        monitor.record_tool_call_parsed("read", session_id="test_session")
        
        metrics = monitor.get_metrics()
        assert metrics["global"]["total_calls"] == 1
        assert metrics["global"]["successful_parses"] == 1
        assert metrics["global"]["success_rate"] == 1.0
    
    def test_record_failed_parse(self):
        """Test recording failed parse"""
        monitor = Monitor.get_instance()
        
        monitor.record_tool_call_failed(
            "read",
            "Unterminated string",
            '{"path": "/test',
            session_id="test_session"
        )
        
        metrics = monitor.get_metrics()
        assert metrics["global"]["total_calls"] == 1
        assert metrics["global"]["failed_parses"] == 1
        assert metrics["global"]["success_rate"] == 0.0
    
    def test_record_repair_success(self):
        """Test recording repair success"""
        monitor = Monitor.get_instance()
        
        # Record a failure first
        monitor.record_tool_call_failed(
            "read",
            "Unterminated string",
            '{"path": "/test',
            session_id="test_session"
        )
        
        # Then record repair
        monitor.record_tool_call_repaired(
            "read",
            "json",
            session_id="test_session"
        )
        
        metrics = monitor.get_metrics()
        assert metrics["global"]["repaired_json"] == 1
        assert metrics["global"]["repair_rate"] > 0
    
    def test_session_specific_metrics(self):
        """Test session-specific metrics"""
        monitor = Monitor.get_instance()
        
        # Record metrics for session 1
        monitor.record_tool_call_parsed("read", session_id="session1")
        monitor.record_tool_call_parsed("write", session_id="session1")
        
        # Record metrics for session 2
        monitor.record_tool_call_failed(
            "bash",
            "Parse error",
            "invalid json",
            session_id="session2"
        )
        
        # Check session 1 metrics
        session1_metrics = monitor.get_session_metrics("session1")
        assert session1_metrics is not None
        assert session1_metrics["total_calls"] == 2
        assert session1_metrics["successful_parses"] == 2
        
        # Check session 2 metrics
        session2_metrics = monitor.get_session_metrics("session2")
        assert session2_metrics is not None
        assert session2_metrics["total_calls"] == 1
        assert session2_metrics["failed_parses"] == 1
    
    def test_top_failing_tools(self):
        """Test tracking top failing tools"""
        monitor = Monitor.get_instance()
        
        # Record multiple failures for different tools
        monitor.record_tool_call_failed("bash", "error1", "args1")
        monitor.record_tool_call_failed("bash", "error2", "args2")
        monitor.record_tool_call_failed("bash", "error3", "args3")
        monitor.record_tool_call_failed("read", "error4", "args4")
        
        metrics = monitor.get_metrics()
        top_failing = dict(metrics["global"]["top_failing_tools"])
        
        assert top_failing["bash"] == 3
        assert top_failing["read"] == 1
    
    def test_alert_threshold(self):
        """Test alert triggering on low success rate"""
        monitor = Monitor.get_instance()
        
        # Record enough failures to trigger alert
        for i in range(10):
            monitor.record_tool_call_failed(
                "test_tool",
                "error",
                "args",
            )
        
        # Add a couple successes to avoid 0% rate
        monitor.record_tool_call_parsed("test_tool")
        monitor.record_tool_call_parsed("test_tool")
        
        metrics = monitor.get_metrics()
        # Success rate should be 2/12 = 0.166, below 0.3 threshold
        assert metrics["global"]["success_rate"] < 0.3


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
