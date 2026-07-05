"""
Monitoring and Metrics Module

Tracks system metrics including tool call parsing failures, 
repair attempts, and success rates.

Ported from original monitoring patterns.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import defaultdict
import threading

from flocks.utils.log import Log


log = Log.create(service="monitor")


@dataclass
class ToolCallMetrics:
    """Metrics for tool call processing"""
    total_calls: int = 0
    successful_parses: int = 0
    failed_parses: int = 0
    repaired_case: int = 0
    repaired_json: int = 0
    redirected_to_invalid: int = 0
    
    # Per-tool failure tracking
    failures_by_tool: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Recent failure details (last 100)
    recent_failures: List[Dict[str, Any]] = field(default_factory=list)
    
    def success_rate(self) -> float:
        """Calculate parsing success rate"""
        if self.total_calls == 0:
            return 1.0
        return self.successful_parses / self.total_calls
    
    def repair_rate(self) -> float:
        """Calculate repair success rate"""
        if self.failed_parses == 0:
            return 0.0
        repaired = self.repaired_case + self.repaired_json
        return repaired / self.failed_parses
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_calls": self.total_calls,
            "successful_parses": self.successful_parses,
            "failed_parses": self.failed_parses,
            "repaired_case": self.repaired_case,
            "repaired_json": self.repaired_json,
            "redirected_to_invalid": self.redirected_to_invalid,
            "success_rate": self.success_rate(),
            "repair_rate": self.repair_rate(),
            "top_failing_tools": sorted(
                self.failures_by_tool.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10],
        }


class Monitor:
    """
    System Monitor - tracks metrics and alerts
    
    Thread-safe singleton for tracking system-wide metrics.
    """
    
    _instance: Optional['Monitor'] = None
    _lock = threading.Lock()
    
    def __init__(self):
        self.tool_call_metrics = ToolCallMetrics()
        self._alert_threshold = 0.3  # Alert if parsing success rate drops below 70%
        self._last_alert_time: Optional[datetime] = None
        self._alert_cooldown = timedelta(minutes=5)  # Don't spam alerts
        
        # Session-specific metrics
        self._session_metrics: Dict[str, ToolCallMetrics] = {}
    
    @classmethod
    def get_instance(cls) -> 'Monitor':
        """Get singleton instance"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def record_tool_call_parsed(
        self,
        tool_name: str,
        session_id: Optional[str] = None,
    ):
        """Record successful tool call parse"""
        self.tool_call_metrics.total_calls += 1
        self.tool_call_metrics.successful_parses += 1
        
        if session_id:
            if session_id not in self._session_metrics:
                self._session_metrics[session_id] = ToolCallMetrics()
            self._session_metrics[session_id].total_calls += 1
            self._session_metrics[session_id].successful_parses += 1
        
        log.debug("monitor.tool_call.parsed", {
            "tool": tool_name,
            "session_id": session_id,
        })
    
    def record_tool_call_failed(
        self,
        tool_name: str,
        error: str,
        arguments_preview: str,
        session_id: Optional[str] = None,
    ):
        """Record failed tool call parse"""
        self.tool_call_metrics.total_calls += 1
        self.tool_call_metrics.failed_parses += 1
        self.tool_call_metrics.failures_by_tool[tool_name] += 1
        
        # Store failure details
        failure_detail = {
            "tool": tool_name,
            "error": error,
            "arguments_preview": arguments_preview[:100],
            "timestamp": datetime.now().isoformat(),
            "session_id": session_id,
        }
        self.tool_call_metrics.recent_failures.append(failure_detail)
        
        # Keep only last 100 failures
        if len(self.tool_call_metrics.recent_failures) > 100:
            self.tool_call_metrics.recent_failures.pop(0)
        
        if session_id:
            if session_id not in self._session_metrics:
                self._session_metrics[session_id] = ToolCallMetrics()
            self._session_metrics[session_id].total_calls += 1
            self._session_metrics[session_id].failed_parses += 1
        
        log.warn("monitor.tool_call.failed", {
            "tool": tool_name,
            "error": error,
            "session_id": session_id,
        })
        
        # Check if we should alert
        self._check_alert_threshold()
    
    def record_tool_call_repaired(
        self,
        tool_name: str,
        repair_strategy: str,  # "case", "json", etc.
        session_id: Optional[str] = None,
    ):
        """Record successful tool call repair"""
        if repair_strategy == "case":
            self.tool_call_metrics.repaired_case += 1
        elif repair_strategy == "json":
            self.tool_call_metrics.repaired_json += 1
        
        if session_id and session_id in self._session_metrics:
            if repair_strategy == "case":
                self._session_metrics[session_id].repaired_case += 1
            elif repair_strategy == "json":
                self._session_metrics[session_id].repaired_json += 1
        
        log.info("monitor.tool_call.repaired", {
            "tool": tool_name,
            "strategy": repair_strategy,
            "session_id": session_id,
        })
    
    def record_tool_call_invalid(
        self,
        tool_name: str,
        session_id: Optional[str] = None,
    ):
        """Record tool call redirected to invalid"""
        self.tool_call_metrics.redirected_to_invalid += 1
        
        if session_id and session_id in self._session_metrics:
            self._session_metrics[session_id].redirected_to_invalid += 1
        
        log.warn("monitor.tool_call.redirected_to_invalid", {
            "tool": tool_name,
            "session_id": session_id,
        })
    
    def _check_alert_threshold(self):
        """Check if we should send an alert"""
        success_rate = self.tool_call_metrics.success_rate()
        
        # Only alert if we have enough data points
        if self.tool_call_metrics.total_calls < 10:
            return
        
        # Check cooldown
        now = datetime.now()
        if self._last_alert_time:
            if now - self._last_alert_time < self._alert_cooldown:
                return
        
        # Check threshold
        if success_rate < self._alert_threshold:
            self._send_alert(success_rate)
            self._last_alert_time = now
    
    def _send_alert(self, success_rate: float):
        """Send alert for low success rate"""
        log.error("monitor.alert.low_success_rate", {
            "success_rate": success_rate,
            "threshold": self._alert_threshold,
            "total_calls": self.tool_call_metrics.total_calls,
            "failed_parses": self.tool_call_metrics.failed_parses,
            "top_failing_tools": list(sorted(
                self.tool_call_metrics.failures_by_tool.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]),
        })
    
    def get_metrics(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Get current metrics"""
        if session_id and session_id in self._session_metrics:
            return {
                "session": self._session_metrics[session_id].to_dict(),
                "global": self.tool_call_metrics.to_dict(),
            }
        return {
            "global": self.tool_call_metrics.to_dict(),
        }
    
    def get_session_metrics(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get metrics for specific session"""
        if session_id in self._session_metrics:
            return self._session_metrics[session_id].to_dict()
        return None
    
    def reset_metrics(self):
        """Reset all metrics (for testing)"""
        self.tool_call_metrics = ToolCallMetrics()
        self._session_metrics.clear()
        self._last_alert_time = None
        log.info("monitor.metrics.reset")


# Singleton instance
def get_monitor() -> Monitor:
    """Get monitor singleton instance"""
    return Monitor.get_instance()
