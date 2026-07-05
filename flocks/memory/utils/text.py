"""
Text utility functions for memory system

Provides text processing utilities for snippets and paths.
"""

from typing import Optional


MAX_SNIPPET_LENGTH = 700  # Match OpenClaw's SNIPPET_MAX_CHARS


def truncate_text(text: str, max_length: int = MAX_SNIPPET_LENGTH) -> str:
    """
    Truncate text to maximum length
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        
    Returns:
        Truncated text with ellipsis if needed
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - 3] + "..."


def extract_snippet(
    text: str,
    start_line: int,
    end_line: int,
    max_length: Optional[int] = MAX_SNIPPET_LENGTH,
) -> str:
    """
    Extract snippet from text by line range
    
    Args:
        text: Full text content
        start_line: Starting line (1-indexed)
        end_line: Ending line (1-indexed)
        max_length: Maximum snippet length
        
    Returns:
        Extracted snippet, truncated if needed
    """
    lines = text.splitlines()
    
    # Adjust for 0-indexing
    start_idx = max(0, start_line - 1)
    end_idx = min(len(lines), end_line)
    
    # Extract lines
    snippet_lines = lines[start_idx:end_idx]
    snippet = "\n".join(snippet_lines)
    
    # Truncate if needed
    if max_length and len(snippet) > max_length:
        snippet = truncate_text(snippet, max_length)
    
    return snippet


def normalize_path(path: str) -> str:
    """
    Normalize file path for consistent comparison
    
    Args:
        path: File path
        
    Returns:
        Normalized path
    """
    # Convert backslashes to forward slashes
    path = path.replace("\\", "/")
    
    # Remove leading ./ prefix (repeating, e.g. ././foo → foo)
    while path.startswith("./"):
        path = path[2:]
    
    return path


def is_memory_path(path: str) -> bool:
    """
    Check if path is a memory file
    
    Args:
        path: File path
        
    Returns:
        True if path is a memory file
    """
    normalized = normalize_path(path)
    
    if not normalized:
        return False
    
    # Check for MEMORY.md or memory.md
    if normalized in ("MEMORY.md", "memory.md"):
        return True
    
    # Check for memory/ directory files
    return normalized.startswith("memory/") and normalized.endswith(".md")
