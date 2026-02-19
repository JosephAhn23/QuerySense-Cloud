"""
Role-Based Access Control (RBAC) for QuerySense.

Supports:
- Workspace-scoped roles (viewer, analyst, admin)
- Fine-grained permissions (analyze, migrate, manage_users, audit)
- Resource-pattern matching (workspace/*, plan/*)
- API key permission scoping
- Permission inheritance (admin > analyst > viewer)

Usage:
    from querysense.auth.rbac import RBACChecker, Permission, Role

    roles = [Role(name="analyst", permissions={Permission.ANALYZE, Permission.MIGRATE})]
    checker = RBACChecker(roles)

    if checker.can(Permission.ANALYZE):
        result = service.analyze(plan)

    checker.require(Permission.MIGRATE)  # raises AuthorizationError if denied
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Permission(str, Enum):
    """Fine-grained permissions for QuerySense operations."""
    # Analysis
    ANALYZE = "analyze"
    COMPARE = "compare"
    REWRITE = "rewrite"

    # Database operations
    MIGRATE = "migrate"
    MIGRATE_EXECUTE = "migrate.execute"
    SCHEMA_SNAPSHOT = "schema.snapshot"
    SCHEMA_SYNC = "schema.sync"
    HEALTH_CHECK = "health.check"
    BENCH = "bench"

    # Management
    MANAGE_USERS = "manage_users"
    MANAGE_ROLES = "manage_roles"
    MANAGE_API_KEYS = "manage_api_keys"
    MANAGE_WORKSPACES = "manage_workspaces"

    # Audit & Compliance
    AUDIT_READ = "audit.read"
    AUDIT_EXPORT = "audit.export"
    COMPLIANCE_REPORT = "compliance.report"

    # Settings
    CONFIG_READ = "config.read"
    CONFIG_WRITE = "config.write"
    POLICY_MANAGE = "policy.manage"
    BUDGET_MANAGE = "budget.manage"

    # Super
    ADMIN = "admin"


class AuthorizationError(Exception):
    """Raised when a user lacks the required permission."""

    def __init__(self, permission: Permission, resource: str = ""):
        self.permission = permission
        self.resource = resource
        msg = f"Missing permission: {permission.value}"
        if resource:
            msg += f" on resource: {resource}"
        super().__init__(msg)


# ── Predefined role templates ────────────────────────────────────────

_ROLE_TEMPLATES: dict[str, set[Permission]] = {
    "viewer": {
        Permission.ANALYZE,
        Permission.COMPARE,
        Permission.AUDIT_READ,
        Permission.CONFIG_READ,
    },
    "analyst": {
        Permission.ANALYZE,
        Permission.COMPARE,
        Permission.REWRITE,
        Permission.SCHEMA_SNAPSHOT,
        Permission.HEALTH_CHECK,
        Permission.AUDIT_READ,
        Permission.CONFIG_READ,
        Permission.BENCH,
    },
    "developer": {
        Permission.ANALYZE,
        Permission.COMPARE,
        Permission.REWRITE,
        Permission.MIGRATE,
        Permission.SCHEMA_SNAPSHOT,
        Permission.HEALTH_CHECK,
        Permission.BENCH,
        Permission.AUDIT_READ,
        Permission.CONFIG_READ,
        Permission.BUDGET_MANAGE,
    },
    "admin": {
        Permission.ADMIN,
    },
}


@dataclass(frozen=True)
class Role:
    """A role with a set of permissions and optional resource patterns."""
    name: str
    permissions: frozenset[Permission] = field(default_factory=frozenset)
    workspace_id: str = ""
    resource_patterns: tuple[str, ...] = ()  # e.g., ("workspace/*", "plan/*")
    description: str = ""

    @classmethod
    def from_template(cls, template_name: str, workspace_id: str = "") -> "Role":
        """Create a role from a predefined template."""
        perms = _ROLE_TEMPLATES.get(template_name)
        if perms is None:
            raise ValueError(
                f"Unknown role template: {template_name}. "
                f"Available: {', '.join(_ROLE_TEMPLATES.keys())}"
            )
        return cls(
            name=template_name,
            permissions=frozenset(perms),
            workspace_id=workspace_id,
            description=f"Built-in {template_name} role",
        )

    @classmethod
    def custom(
        cls,
        name: str,
        permissions: list[str],
        workspace_id: str = "",
        resource_patterns: list[str] | None = None,
    ) -> "Role":
        """Create a custom role from permission strings."""
        perms = frozenset(Permission(p) for p in permissions)
        return cls(
            name=name,
            permissions=perms,
            workspace_id=workspace_id,
            resource_patterns=tuple(resource_patterns or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "permissions": sorted(p.value for p in self.permissions),
            "workspace_id": self.workspace_id,
            "resource_patterns": list(self.resource_patterns),
            "description": self.description,
        }


class RBACChecker:
    """
    Check permissions against a user's roles.

    Supports:
    - Direct permission checks
    - Admin override (admin can do everything)
    - Resource-pattern matching (fnmatch-style)
    - Workspace scoping
    """

    def __init__(self, user_roles: list[Role], workspace_id: str = ""):
        self._roles = user_roles
        self._workspace_id = workspace_id
        self._permissions = self._compile_permissions()
        self._resource_patterns = self._compile_resource_patterns()

    def _compile_permissions(self) -> set[Permission]:
        """Compile all permissions from all roles."""
        perms: set[Permission] = set()
        for role in self._roles:
            # If workspace-scoped, only include if workspace matches
            if role.workspace_id and role.workspace_id != self._workspace_id:
                continue
            perms.update(role.permissions)
        return perms

    def _compile_resource_patterns(self) -> list[str]:
        """Collect all resource patterns from roles."""
        patterns: list[str] = []
        for role in self._roles:
            if role.workspace_id and role.workspace_id != self._workspace_id:
                continue
            patterns.extend(role.resource_patterns)
        return patterns

    @property
    def is_admin(self) -> bool:
        return Permission.ADMIN in self._permissions

    @property
    def permissions(self) -> set[Permission]:
        return self._permissions.copy()

    def can(self, permission: Permission, resource: str = "") -> bool:
        """
        Check if the user has a permission, optionally on a specific resource.

        Args:
            permission: The permission to check
            resource: Optional resource identifier (e.g., "plan/abc123")

        Returns:
            True if permitted
        """
        # Admin can do everything
        if self.is_admin:
            return True

        # Check direct permission
        if permission not in self._permissions:
            return False

        # Check resource pattern if specified
        if resource and self._resource_patterns:
            return any(
                fnmatch.fnmatch(resource, pattern)
                for pattern in self._resource_patterns
            )

        return True

    def require(self, permission: Permission, resource: str = "") -> None:
        """
        Require a permission, raising AuthorizationError if denied.

        Args:
            permission: The permission to require
            resource: Optional resource identifier

        Raises:
            AuthorizationError: If permission is denied
        """
        if not self.can(permission, resource):
            raise AuthorizationError(permission, resource)

    def can_any(self, *permissions: Permission) -> bool:
        """Check if user has ANY of the given permissions."""
        if self.is_admin:
            return True
        return any(p in self._permissions for p in permissions)

    def can_all(self, *permissions: Permission) -> bool:
        """Check if user has ALL of the given permissions."""
        if self.is_admin:
            return True
        return all(p in self._permissions for p in permissions)

    def describe(self) -> dict[str, Any]:
        """Describe current permissions for debugging/UI."""
        return {
            "roles": [r.to_dict() for r in self._roles],
            "effective_permissions": sorted(p.value for p in self._permissions),
            "is_admin": self.is_admin,
            "workspace_id": self._workspace_id,
            "resource_patterns": self._resource_patterns,
        }
