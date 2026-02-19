"""
Rule registry for centralized rule management.

The registry pattern provides:
- Explicit control over which rules are available
- Plugin system for user-defined rules
- CLI integration (--rules, --exclude-rules)
- Testing isolation (register only specific rules)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from querysense.analyzer.rules.base import Rule

T = TypeVar("T", bound="Rule")


class RuleRegistry:
    """
    Centralized registry for all analysis rules.
    
    Rules register themselves using the @register_rule decorator.
    The analyzer queries the registry to get available rules.
    
    Example:
        # In a rule module:
        @register_rule
        class MyRule(Rule):
            rule_id = "MY_RULE"
            ...
        
        # In analyzer or CLI:
        registry = get_registry()
        rules = registry.filter(exclude={"EXPERIMENTAL_RULE"})
    """
    
    def __init__(self) -> None:
        self._rules: dict[str, type[Rule]] = {}
    
    def register(self, rule_cls: type[T]) -> type[T]:
        """
        Register a rule class.
        
        Can be used as a decorator:
            @register_rule
            class MyRule(Rule):
                ...
        
        Args:
            rule_cls: The rule class to register
            
        Returns:
            The same class (allows decorator usage)
            
        Raises:
            ValueError: If a rule with the same ID is already registered
        """
        rule_id = rule_cls.rule_id
        
        if rule_id in self._rules:
            existing = self._rules[rule_id]
            raise ValueError(
                f"Rule '{rule_id}' already registered by {existing.__module__}.{existing.__name__}. "
                f"Cannot register {rule_cls.__module__}.{rule_cls.__name__}"
            )
        
        self._rules[rule_id] = rule_cls
        return rule_cls
    
    def unregister(self, rule_id: str) -> bool:
        """
        Remove a rule from the registry.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            True if rule was found and removed, False otherwise
        """
        if rule_id in self._rules:
            del self._rules[rule_id]
            return True
        return False
    
    def get(self, rule_id: str) -> type[Rule] | None:
        """
        Get a rule class by ID.
        
        Args:
            rule_id: The rule ID to look up
            
        Returns:
            The rule class, or None if not found
        """
        return self._rules.get(rule_id)
    
    def all(self) -> list[type[Rule]]:
        """
        Get all registered rule classes.
        
        Returns:
            List of all rule classes, in registration order
        """
        return list(self._rules.values())
    
    def all_ids(self) -> list[str]:
        """
        Get all registered rule IDs.
        
        Returns:
            List of all rule IDs
        """
        return list(self._rules.keys())
    
    def filter(
        self,
        include: set[str] | None = None,
        exclude: set[str] | None = None,
    ) -> list[type[Rule]]:
        """
        Get a filtered list of rule classes.
        
        Args:
            include: If provided, only include these rule IDs
            exclude: If provided, exclude these rule IDs
            
        Returns:
            Filtered list of rule classes
            
        Example:
            # Only run specific rules
            rules = registry.filter(include={"SEQ_SCAN", "MISSING_INDEX"})
            
            # Exclude experimental rules
            rules = registry.filter(exclude={"EXPERIMENTAL"})
        """
        rules = self.all()
        
        if include is not None:
            rules = [r for r in rules if r.rule_id in include]
        
        if exclude is not None:
            rules = [r for r in rules if r.rule_id not in exclude]
        
        return rules
    
    def clear(self) -> None:
        """
        Remove all registered rules.
        
        Primarily useful for testing.
        """
        self._rules.clear()
    
    def __len__(self) -> int:
        """Number of registered rules."""
        return len(self._rules)
    
    def __contains__(self, rule_id: str) -> bool:
        """Check if a rule is registered."""
        return rule_id in self._rules


# Global registry instance
_global_registry = RuleRegistry()


def get_registry() -> RuleRegistry:
    """
    Get the global rule registry.
    
    Returns:
        The singleton RuleRegistry instance
    """
    return _global_registry


def register_rule(rule_cls: type[T]) -> type[T]:
    """
    Decorator to register a rule with the global registry.
    
    Example:
        @register_rule
        class SeqScanLargeTable(Rule):
            rule_id = "SEQ_SCAN_LARGE_TABLE"
            ...
    """
    return _global_registry.register(rule_cls)


def reset_registry() -> None:
    """
    Reset the global registry.
    
    Primarily for testing - clears all registered rules.
    """
    _global_registry.clear()
