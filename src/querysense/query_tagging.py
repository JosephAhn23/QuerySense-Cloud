"""
Query Tagging Helpers

Provides ORM and driver integration for adding application context to
PostgreSQL queries, enabling better monitoring in pganalyze, QuerySense,
and pg_stat_statements.

Supports three tagging strategies:
1. application_name — SET application_name for connection-level tagging
2. SQL comments    — Append /* key=value */ comments (marginalia style)
3. GUC variables   — SET myapp.user_id for custom session-level context

Inspired by the CounterPath/pganalyze case study where application_name
was used to correlate queries across services.

Usage:
    # psycopg2
    from querysense.query_tagging import tag_connection
    tag_connection(conn, app="api-server", environment="production")

    # SQLAlchemy
    from querysense.query_tagging import sqlalchemy_tagging_hook
    sqlalchemy_tagging_hook(engine, app="web", version="2.0.0")

    # Comment-based tagging
    from querysense.query_tagging import add_query_comment
    sql = add_query_comment(
        "SELECT * FROM orders WHERE status = 'pending'",
        controller="OrdersController",
        action="index",
    )
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class QueryTag:
    """A key-value tag to attach to queries."""
    key: str
    value: str

    def as_comment(self) -> str:
        safe_key = re.sub(r"[^a-zA-Z0-9_.-]", "", self.key)
        safe_val = self.value.replace("*/", "").replace("/*", "")
        return f"{safe_key}={safe_val}"

    def as_guc(self, namespace: str = "querysense") -> str:
        safe_key = re.sub(r"[^a-zA-Z0-9_]", "", self.key)
        safe_val = self.value.replace("'", "''")
        return f"SET {namespace}.{safe_key} = '{safe_val}'"


def add_query_comment(sql: str, **tags: str) -> str:
    """
    Append a marginalia-style comment to a SQL query.

    This is the safest tagging strategy: it doesn't modify query
    semantics and works with all drivers and connection poolers.

    Example:
        >>> add_query_comment("SELECT 1", app="web", controller="home")
        "SELECT 1 /* app=web,controller=home */"
    """
    if not tags:
        return sql

    parts = [QueryTag(k, v).as_comment() for k, v in tags.items()]
    comment = f"/* {','.join(parts)} */"

    sql_stripped = sql.rstrip().rstrip(";")
    had_semicolon = sql.rstrip().endswith(";")

    return f"{sql_stripped} {comment}" + (";" if had_semicolon else "")


def build_application_name(
    *,
    app: str,
    environment: str = "",
    version: str = "",
    host: str = "",
    pid: str = "",
) -> str:
    """
    Build a structured application_name string.

    Format: app[/environment][/version][@host][:pid]

    Example:
        >>> build_application_name(app="api", environment="prod", version="2.0")
        "api/prod/2.0"
    """
    parts = [app]
    if environment:
        parts.append(environment)
    if version:
        parts.append(version)

    name = "/".join(parts)
    if host:
        name += f"@{host}"
    if pid:
        name += f":{pid}"

    return name[:63]


def tag_connection(
    conn: Any,
    *,
    app: str | None = None,
    environment: str = "",
    version: str = "",
    namespace: str = "querysense",
    **extra_tags: str,
) -> None:
    """
    Tag a database connection with application context.

    Works with psycopg2, psycopg3, and any DB-API 2.0 connection.

    Sets:
    - application_name (if app is provided)
    - Custom GUC variables for each extra tag
    """
    cursor = conn.cursor()
    try:
        if app:
            app_name = build_application_name(
                app=app, environment=environment, version=version,
            )
            safe_name = app_name.replace("'", "''")
            cursor.execute(f"SET application_name = '{safe_name}'")

        for key, value in extra_tags.items():
            tag = QueryTag(key, value)
            cursor.execute(tag.as_guc(namespace))
    finally:
        cursor.close()


def sqlalchemy_tagging_hook(
    engine: Any,
    *,
    app: str = "querysense",
    environment: str = "",
    version: str = "",
    tag_queries: bool = True,
    extra_tags: dict[str, str] | None = None,
) -> None:
    """
    Register SQLAlchemy event hooks for automatic query tagging.

    Hooks into 'connect' and optionally 'before_cursor_execute' events.

    Usage:
        from sqlalchemy import create_engine
        from querysense.query_tagging import sqlalchemy_tagging_hook

        engine = create_engine("postgresql://...")
        sqlalchemy_tagging_hook(engine, app="myapp", environment="prod")
    """
    try:
        from sqlalchemy import event
    except ImportError:
        raise ImportError(
            "SQLAlchemy is required for sqlalchemy_tagging_hook. "
            "Install it with: pip install sqlalchemy"
        )

    app_name = build_application_name(
        app=app, environment=environment, version=version,
    )

    @event.listens_for(engine, "connect")
    def _set_app_name(dbapi_conn: Any, connection_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        safe_name = app_name.replace("'", "''")
        cursor.execute(f"SET application_name = '{safe_name}'")
        if extra_tags:
            for key, value in extra_tags.items():
                tag = QueryTag(key, value)
                cursor.execute(tag.as_guc())
        cursor.close()

    if tag_queries:
        @event.listens_for(engine, "before_cursor_execute")
        def _add_comment(
            conn: Any, cursor: Any, statement: str,
            parameters: Any, context: Any, executemany: bool,
        ) -> tuple[str, Any]:
            tags = {"app": app}
            if environment:
                tags["env"] = environment
            return add_query_comment(statement, **tags), parameters


def django_middleware_class() -> str:
    """
    Returns the source code for a Django middleware class that tags
    database connections with request context.

    Copy this into your Django project:
        # myapp/middleware.py
        <paste the output here>

        # settings.py
        MIDDLEWARE = [
            'myapp.middleware.QuerySenseTaggingMiddleware',
            ...
        ]
    """
    return '''\
"""QuerySense query tagging middleware for Django."""
import threading

from django.db import connection

_request_context = threading.local()


class QuerySenseTaggingMiddleware:
    """Tags database queries with request context for monitoring."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        _request_context.path = request.path
        _request_context.method = request.method
        _request_context.user = getattr(request, "user", None)

        with connection.cursor() as cursor:
            app_name = f"django/{request.method}{request.path}"[:63]
            cursor.execute(
                "SET application_name = %s", [app_name]
            )

        response = self.get_response(request)
        return response
'''


def psycopg_pool_configure() -> str:
    """
    Returns example code for configuring psycopg connection pools
    with automatic tagging.
    """
    return '''\
"""QuerySense tagging for psycopg connection pools."""
from psycopg_pool import ConnectionPool

def configure_pool(dsn: str, app_name: str = "myapp") -> ConnectionPool:
    """Create a tagged connection pool."""

    def configure_conn(conn):
        conn.execute(
            "SET application_name = %s", [app_name]
        )
        conn.execute(
            "SET querysense.pool_id = %s",
            [f"{app_name}-pool"]
        )

    return ConnectionPool(
        dsn,
        min_size=2,
        max_size=20,
        configure=configure_conn,
    )
'''
