"""
Parser configuration with resource limits.

These limits prevent pathological inputs from causing OOM crashes or
stack overflows. The defaults are generous for normal usage but will
catch genuinely problematic files.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ParserConfig(BaseModel):
    """
    Configuration for the EXPLAIN parser with resource limits.
    
    Attributes:
        max_file_size_mb: Maximum file size to parse. Prevents loading
            multi-GB files into memory.
        max_nodes: Maximum number of plan nodes. Prevents memory exhaustion
            from pathologically large plans (e.g., 100K nested loops).
        max_depth: Maximum tree depth. Prevents stack overflow during
            recursive parsing of deeply nested plans.
    
    Example:
        # Use defaults
        config = ParserConfig()
        
        # Stricter limits for a web API
        config = ParserConfig(max_file_size_mb=10, max_nodes=1000)
        
        # Looser limits for known-large plans
        config = ParserConfig(max_nodes=100_000)
    """
    
    max_file_size_mb: float = Field(
        default=100.0,
        gt=0,
        description="Maximum file size in megabytes",
    )
    
    max_nodes: int = Field(
        default=50_000,
        gt=0,
        description="Maximum number of plan nodes",
    )
    
    max_depth: int = Field(
        default=100,
        gt=0,
        description="Maximum tree depth (nesting level)",
    )


# Sensible defaults for different use cases
DEFAULT_CONFIG = ParserConfig()

# Stricter limits for web API / untrusted input
STRICT_CONFIG = ParserConfig(
    max_file_size_mb=10.0,
    max_nodes=5_000,
    max_depth=50,
)
