#!/usr/bin/env python3
"""
Bitcoin Node Security Scanner - Utility Functions
Helper functions for data processing, validation, and common operations
"""

import os
import re
import time
from datetime import datetime
from typing import Dict, List, Any
from functools import wraps


def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address format
    
    Args:
        ip: IP address string
        
    Returns:
        True if valid, False otherwise
    """
    # IPv4 pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # IPv6 pattern (simplified)
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
    
    if re.match(ipv4_pattern, ip):
        # Validate octets
        octets = ip.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    if re.match(ipv6_pattern, ip):
        return True
    
    return False


def validate_port(port: int) -> bool:
    """
    Validate port number
    
    Args:
        port: Port number
        
    Returns:
        True if valid, False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def parse_version_number(version: str) -> tuple | None:
    """
    Parse version string into tuple of integers

    Args:
        version: Version string (e.g., "0.21.1")

    Returns:
        Tuple of version components or None if invalid
    """
    try:
        # Limit input length to prevent ReDoS attacks
        if not isinstance(version, str) or len(version) > 100:
            return None

        # Extract numeric version using bounded quantifiers to prevent ReDoS
        match = re.search(r'(\d{1,10})\.(\d{1,10})\.(\d{1,10})', version)
        if match:
            return tuple(map(int, match.groups()))
    except (ValueError, AttributeError):
        pass

    return None


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two version strings
    
    Args:
        version1: First version string
        version2: Second version string
        
    Returns:
        -1 if version1 < version2
         0 if version1 == version2
         1 if version1 > version2
        None if comparison not possible
    """
    v1 = parse_version_number(version1)
    v2 = parse_version_number(version2)
    
    if v1 is None or v2 is None:
        return None
    
    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to remove invalid characters
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    
    return sanitized


def ensure_directory(directory: str):
    """
    Ensure directory exists, create if not
    
    Args:
        directory: Directory path
    """
    os.makedirs(directory, exist_ok=True)


def rate_limit(delay: float = 1.0):
    """
    Decorator for rate limiting function calls
    
    Args:
        delay: Delay in seconds between calls
    """
    def decorator(func):
        last_call = [0.0]
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Calculate time since last call
            elapsed = time.time() - last_call[0]
            
            # Wait if necessary
            if elapsed < delay:
                time.sleep(delay - elapsed)
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Update last call time
            last_call[0] = time.time()
            
            return result
        
        return wrapper
    return decorator


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count as human-readable string
    
    Args:
        bytes_count: Number of bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def format_timestamp(timestamp: Any) -> str:
    """
    Format timestamp in consistent format
    
    Args:
        timestamp: Timestamp (string, int, or datetime)
        
    Returns:
        Formatted timestamp string
    """
    if isinstance(timestamp, str):
        # Try to parse various formats
        for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y%m%d_%H%M%S']:
            try:
                dt = datetime.strptime(timestamp, fmt)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except ValueError:
                continue
        return timestamp
    
    elif isinstance(timestamp, (int, float)):
        # Assume Unix timestamp
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    elif isinstance(timestamp, datetime):
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    
    return str(timestamp)


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length
    
    Args:
        text: Original text
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def parse_banner_fields(banner: str) -> Dict[str, str]:
    """
    Parse structured information from banner string
    
    Args:
        banner: Banner string
        
    Returns:
        Dictionary of parsed fields
    """
    fields = {}
    
    # Extract version information
    if '/Satoshi:' in banner:
        match = re.search(r'/Satoshi:([^/]+)/', banner)
        if match:
            fields['satoshi_version'] = match.group(1)
    
    # Extract protocol version
    match = re.search(r'protocol version (\d+)', banner, re.IGNORECASE)
    if match:
        fields['protocol_version'] = match.group(1)
    
    # Extract user agent
    match = re.search(r'/([^/:]+):[^/]*/', banner)
    if match:
        fields['user_agent'] = match.group(1)
    
    return fields


def deduplicate_list(items: List[Any], key_func=None) -> List[Any]:
    """
    Remove duplicates from list while preserving order
    
    Args:
        items: List of items
        key_func: Optional function to extract comparison key
        
    Returns:
        List with duplicates removed
    """
    seen = set()
    result = []
    
    for item in items:
        # Get key for comparison
        key = key_func(item) if key_func else item
        
        # Add if not seen
        if key not in seen:
            seen.add(key)
            result.append(item)
    
    return result


def merge_dictionaries(*dicts: Dict) -> Dict:
    """
    Merge multiple dictionaries, later values override earlier ones
    
    Args:
        *dicts: Variable number of dictionaries
        
    Returns:
        Merged dictionary
    """
    result = {}
    for d in dicts:
        result.update(d)
    return result


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    Safely divide two numbers, returning default if denominator is zero
    
    Args:
        numerator: Numerator
        denominator: Denominator
        default: Default value if division by zero
        
    Returns:
        Result of division or default value
    """
    try:
        if denominator == 0:
            return default
        return numerator / denominator
    except (TypeError, ValueError):
        return default


def calculate_percentage(part: int, total: int, decimals: int = 2) -> float:
    """
    Calculate percentage with specified decimal places
    
    Args:
        part: Part value
        total: Total value
        decimals: Number of decimal places
        
    Returns:
        Percentage value
    """
    if total == 0:
        return 0.0
    
    percentage = (part / total) * 100
    return round(percentage, decimals)


def batch_list(items: List[Any], batch_size: int) -> List[List[Any]]:
    """
    Split list into batches of specified size
    
    Args:
        items: List of items
        batch_size: Size of each batch
        
    Returns:
        List of batches
    """
    batches = []
    for i in range(0, len(items), batch_size):
        batches.append(items[i:i + batch_size])
    return batches


def extract_asn_number(asn: str) -> int:
    """
    Extract numeric ASN from string
    
    Args:
        asn: ASN string (e.g., "AS1234")
        
    Returns:
        Numeric ASN or 0 if extraction fails
    """
    try:
        # Remove "AS" prefix and extract number
        match = re.search(r'(\d+)', asn)
        if match:
            return int(match.group(1))
    except (ValueError, AttributeError, TypeError):
        pass
    
    return 0


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private/reserved
    
    Args:
        ip: IP address string
        
    Returns:
        True if private, False otherwise
    """
    if not validate_ip_address(ip):
        return False
    
    octets = ip.split('.')
    if len(octets) != 4:
        return False  # IPv6 not implemented
    
    first = int(octets[0])
    second = int(octets[1])
    
    # Check private ranges
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:  # Loopback
        return True
    
    return False


def retry_on_failure(max_attempts: int = 3, delay: float = 1.0):
    """
    Decorator to retry function on failure
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Delay between attempts in seconds
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    time.sleep(delay)
            return None
        return wrapper
    return decorator


class ProgressTracker:
    """Simple progress tracker for long-running operations"""
    
    def __init__(self, total: int, description: str = "Processing"):
        """
        Initialize progress tracker
        
        Args:
            total: Total number of items
            description: Description of operation
        """
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
    
    def update(self, increment: int = 1):
        """
        Update progress
        
        Args:
            increment: Amount to increment
        """
        self.current += increment
        self._print_progress()
    
    def _print_progress(self):
        """Print current progress"""
        percentage = (self.current / self.total * 100) if self.total > 0 else 0
        elapsed = time.time() - self.start_time
        
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
        else:
            remaining = 0
        
        print(f"\r{self.description}: {self.current}/{self.total} "
              f"({percentage:.1f}%) - ETA: {remaining:.0f}s", end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete
    
    def finish(self):
        """Mark operation as finished"""
        self.current = self.total
        self._print_progress()
