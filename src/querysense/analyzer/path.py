"""
NodePath: First-class type for plan tree navigation.

Provides type-safe, consistent path representation across all rules.
Ensures paths are formatted identically regardless of which rule generates them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterator

from pydantic import GetCoreSchemaHandler, GetJsonSchemaHandler
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import CoreSchema, core_schema

if TYPE_CHECKING:
    from querysense.parser.models import PlanNode


class NodePath:
    """
    Immutable path to a node in the query plan tree.
    
    Paths are sequences of segments representing the traversal from root to node.
    Format: ("Plan", "Plans[0]", "Plans[2]") means root → first child → third grandchild.
    
    Example:
        path = NodePath.root()           # ("Plan",)
        child = path.child(0)            # ("Plan", "Plans[0]")
        grandchild = child.child(2)      # ("Plan", "Plans[0]", "Plans[2]")
        
        str(grandchild)   # "Plan → Plans[0] → Plans[2]"
        len(grandchild)   # 3
    """
    
    __slots__ = ("_segments",)
    
    def __init__(self, segments: tuple[str, ...] | None = None) -> None:
        """
        Create a path from segments.
        
        Prefer using NodePath.root() or path.child(i) over direct construction.
        """
        self._segments: tuple[str, ...] = segments or ("Plan",)
    
    @classmethod
    def root(cls) -> "NodePath":
        """Create a path pointing to the root Plan node."""
        return cls(("Plan",))
    
    @property
    def segments(self) -> tuple[str, ...]:
        """Get the path segments as a tuple."""
        return self._segments
    
    def child(self, index: int) -> "NodePath":
        """
        Navigate to a child node at the given index.
        
        Args:
            index: Zero-based index into the node's Plans array
            
        Returns:
            New NodePath pointing to the child
        """
        return NodePath(self._segments + (f"Plans[{index}]",))
    
    def parent(self) -> "NodePath | None":
        """
        Navigate to the parent node.
        
        Returns:
            Parent path, or None if this is the root
        """
        if len(self._segments) <= 1:
            return None
        return NodePath(self._segments[:-1])
    
    @property
    def depth(self) -> int:
        """
        Get the depth of this path (0 for root).
        
        Returns:
            Number of child navigations from root
        """
        return len(self._segments) - 1
    
    @property
    def is_root(self) -> bool:
        """Check if this is the root path."""
        return len(self._segments) == 1
    
    def __str__(self) -> str:
        """Human-readable format: 'Plan → Plans[0] → Plans[2]'."""
        return " → ".join(self._segments)
    
    def __repr__(self) -> str:
        """Debug format: NodePath(Plan.Plans[0].Plans[2])."""
        return f"NodePath({'.'.join(self._segments)})"
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, NodePath):
            return self._segments == other._segments
        return False
    
    def __hash__(self) -> int:
        return hash(self._segments)
    
    def __len__(self) -> int:
        """Number of segments in the path."""
        return len(self._segments)
    
    def __lt__(self, other: "NodePath") -> bool:
        """Enable sorting paths lexicographically."""
        return self._segments < other._segments
    
    # Pydantic v2 serialization support
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Define how Pydantic serializes/deserializes NodePath."""
        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.union_schema([
                # Accept NodePath directly
                core_schema.is_instance_schema(cls),
                # Accept list of strings
                core_schema.list_schema(core_schema.str_schema()),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda x: list(x.segments),
                info_arg=False,
            ),
        )
    
    @classmethod
    def _validate(cls, value: Any) -> "NodePath":
        """Validate and convert to NodePath."""
        if isinstance(value, cls):
            return value
        if isinstance(value, (list, tuple)):
            return cls(tuple(value))
        raise ValueError(f"Cannot convert {type(value)} to NodePath")
    
    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        """JSON schema representation."""
        return {
            "type": "array",
            "items": {"type": "string"},
            "description": "Path segments from root to node",
            "example": ["Plan", "Plans[0]", "Plans[2]"],
        }


def traverse_with_path(
    node: "PlanNode",
    path: NodePath | None = None,
) -> Iterator[tuple[NodePath, "PlanNode"]]:
    """
    Traverse the plan tree, yielding (path, node) pairs.
    
    This is the canonical way to iterate over nodes when you need
    to know their location. Use this instead of reconstructing paths.
    
    Args:
        node: Starting node (usually explain.plan)
        path: Starting path (defaults to root)
        
    Yields:
        (NodePath, PlanNode) tuples in depth-first order
        
    Example:
        for path, node in traverse_with_path(explain.plan):
            if node.node_type == "Seq Scan":
                print(f"Found seq scan at {path}")
    """
    current_path = path or NodePath.root()
    yield current_path, node
    
    for i, child in enumerate(node.plans or []):
        yield from traverse_with_path(child, current_path.child(i))
