"""EXPLAIN plan parsing — PostgreSQL, MySQL, SQL Server, Oracle, DuckDB, SQLite, ClickHouse."""

from querysense.parser.config import DEFAULT_CONFIG, STRICT_CONFIG, ParserConfig
from querysense.parser.models import ExplainOutput, PlanNode
from querysense.parser.parser import ParseError, parse_explain
from querysense.parser.mysql_parser import (
    MySQLExplainOutput,
    MySQLTableAccess,
    MySQLQueryBlock,
    parse_mysql_explain,
    is_mysql_explain,
)
from querysense.parser.multidb import (
    DatabaseEngine,
    detect_engine,
    parse_any,
)

__all__ = [
    # PostgreSQL
    "ExplainOutput",
    "PlanNode",
    "parse_explain",
    "ParseError",
    "ParserConfig",
    "DEFAULT_CONFIG",
    "STRICT_CONFIG",
    # MySQL
    "MySQLExplainOutput",
    "MySQLTableAccess",
    "MySQLQueryBlock",
    "parse_mysql_explain",
    "is_mysql_explain",
    # Multi-database
    "DatabaseEngine",
    "detect_engine",
    "parse_any",
]

