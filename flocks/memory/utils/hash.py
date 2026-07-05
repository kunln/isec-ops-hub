"""
Hash utility functions for memory system

Provides consistent hashing for files and text content.
"""

import hashlib
from pathlib import Path


def compute_hash(file_path: Path) -> str:
    """
    Compute SHA256 hash of a file
    
    Args:
        file_path: Path to file
        
    Returns:
        Hex digest of hash
    """
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        # Read in chunks to handle large files
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    
    return sha256.hexdigest()


def compute_text_hash(text: str) -> str:
    """
    Compute SHA256 hash of text content
    
    Args:
        text: Text content
        
    Returns:
        Hex digest of hash (truncated to 32 chars / 128 bits)
    """
    sha256 = hashlib.sha256()
    sha256.update(text.encode('utf-8'))
    return sha256.hexdigest()[:32]
