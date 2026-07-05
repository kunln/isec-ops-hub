"""
Locale utilities for formatting dates, times, and numbers

Ported from original util/locale.ts
"""

from datetime import datetime, date


class Locale:
    """Locale utilities for formatting"""
    
    @staticmethod
    def today_time_or_datetime(timestamp_ms: int) -> str:
        """
        Format timestamp as time (if today) or date-time (if not today)
        
        Args:
            timestamp_ms: Timestamp in milliseconds
            
        Returns:
            Formatted string
        """
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        today = date.today()
        
        if dt.date() == today:
            # Today - show time only
            return dt.strftime("%H:%M:%S")
        else:
            # Not today - show date and time
            return dt.strftime("%Y-%m-%d %H:%M")
    
    @staticmethod
    def format_datetime(timestamp_ms: int) -> str:
        """
        Format timestamp as full datetime
        
        Args:
            timestamp_ms: Timestamp in milliseconds
            
        Returns:
            Formatted string
        """
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def format_date(timestamp_ms: int) -> str:
        """
        Format timestamp as date only
        
        Args:
            timestamp_ms: Timestamp in milliseconds
            
        Returns:
            Formatted string
        """
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        return dt.strftime("%Y-%m-%d")
    
    @staticmethod
    def format_time(timestamp_ms: int) -> str:
        """
        Format timestamp as time only
        
        Args:
            timestamp_ms: Timestamp in milliseconds
            
        Returns:
            Formatted string
        """
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        return dt.strftime("%H:%M:%S")
    
    @staticmethod
    def truncate(text: str, max_width: int) -> str:
        """
        Truncate text to max width with ellipsis
        
        Args:
            text: Text to truncate
            max_width: Maximum width
            
        Returns:
            Truncated text
        """
        if len(text) <= max_width:
            return text
        return text[:max_width - 1] + "…"
    
    @staticmethod
    def format_number(num: int) -> str:
        """
        Format number with K/M/B suffixes
        
        Args:
            num: Number to format
            
        Returns:
            Formatted string
        """
        if num >= 1_000_000_000:
            return f"{num / 1_000_000_000:.1f}B"
        elif num >= 1_000_000:
            return f"{num / 1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num / 1_000:.1f}K"
        return str(num)
    
    @staticmethod
    def format_cost(cost: float) -> str:
        """
        Format cost in dollars
        
        Args:
            cost: Cost value
            
        Returns:
            Formatted string
        """
        if cost < 0.01:
            return f"${cost:.4f}"
        return f"${cost:.2f}"
    
    @staticmethod
    def format_duration(ms: int) -> str:
        """
        Format duration in human-readable form
        
        Args:
            ms: Duration in milliseconds
            
        Returns:
            Formatted string
        """
        if ms < 1000:
            return f"{ms}ms"
        
        seconds = ms / 1000
        if seconds < 60:
            return f"{seconds:.1f}s"
        
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f}m"
        
        hours = minutes / 60
        if hours < 24:
            return f"{hours:.1f}h"
        
        days = hours / 24
        return f"{days:.1f}d"
    
    @staticmethod
    def relative_time(timestamp_ms: int) -> str:
        """
        Format timestamp as relative time (e.g., "2 hours ago")
        
        Args:
            timestamp_ms: Timestamp in milliseconds
            
        Returns:
            Formatted relative time string
        """
        now = datetime.now()
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        diff = now - dt
        
        seconds = diff.total_seconds()
        
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        elif seconds < 2592000:
            weeks = int(seconds / 604800)
            return f"{weeks} week{'s' if weeks != 1 else ''} ago"
        elif seconds < 31536000:
            months = int(seconds / 2592000)
            return f"{months} month{'s' if months != 1 else ''} ago"
        else:
            years = int(seconds / 31536000)
            return f"{years} year{'s' if years != 1 else ''} ago"
