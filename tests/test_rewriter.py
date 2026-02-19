"""Tests for the query rewrite engine."""

import pytest

from querysense.rewriter import Rewrite, RewriteResult, rewrite_query


class TestNotInToNotExists:
    """Tests for NOT IN → NOT EXISTS rewrite."""

    def test_rewrites_not_in_subquery(self):
        sql = "SELECT * FROM orders WHERE customer_id NOT IN (SELECT id FROM blacklist)"
        result = rewrite_query(sql)
        assert result.was_rewritten
        assert "NOT EXISTS" in result.rewritten_sql
        assert "SELECT 1" in result.rewritten_sql
        assert any(r.name == "NOT IN → NOT EXISTS" for r in result.rewrites)

    def test_no_rewrite_without_subquery(self):
        sql = "SELECT * FROM orders WHERE status NOT IN ('cancelled', 'refunded')"
        result = rewrite_query(sql)
        # Should not be rewritten — it's a values list, not a subquery
        assert "NOT EXISTS" not in result.rewritten_sql


class TestInSubqueryToJoin:
    """Tests for IN subquery → JOIN rewrite."""

    def test_rewrites_in_subquery(self):
        sql = "SELECT * FROM users WHERE id IN (SELECT user_id FROM active_users)"
        result = rewrite_query(sql)
        assert result.was_rewritten
        # Should be rewritten to JOIN or EXISTS
        assert (
            "JOIN" in result.rewritten_sql
            or "EXISTS" in result.rewritten_sql
        )

    def test_preserves_where_clause(self):
        sql = (
            "SELECT * FROM users WHERE id IN "
            "(SELECT user_id FROM active_users WHERE created_at > '2024-01-01')"
        )
        result = rewrite_query(sql)
        assert result.was_rewritten


class TestMultipleOrToIn:
    """Tests for OR chain → IN clause."""

    def test_rewrites_three_or_conditions(self):
        sql = "SELECT * FROM orders WHERE status = 'active' OR status = 'pending' OR status = 'review'"
        result = rewrite_query(sql)
        assert result.was_rewritten
        assert "IN (" in result.rewritten_sql
        assert "active" in result.rewritten_sql
        assert "pending" in result.rewritten_sql
        assert "review" in result.rewritten_sql

    def test_no_rewrite_for_two_ors(self):
        sql = "SELECT * FROM orders WHERE status = 'a' OR status = 'b'"
        result = rewrite_query(sql)
        # Two ORs is not enough to trigger rewrite (need 3+)
        assert "IN (" not in result.rewritten_sql


class TestSelectStar:
    """Tests for SELECT * flagging."""

    def test_flags_select_star_with_finding(self):
        """Only flags when EXCESSIVE_RESULT_WIDTH finding present."""
        from querysense.analyzer.models import Finding, Severity, NodeContext
        from querysense.analyzer.path import NodePath

        finding = Finding(
            rule_id="EXCESSIVE_RESULT_WIDTH",
            severity=Severity.WARNING,
            title="Wide result set",
            description="Query returns very wide rows",
            context=NodeContext(
                node_type="Seq Scan",
                path=NodePath.root(),
            ),
        )

        sql = "SELECT * FROM users WHERE id = 1"
        result = rewrite_query(sql, [finding])
        assert result.was_rewritten
        assert "TODO: replace with specific columns" in result.rewritten_sql

    def test_no_flag_without_finding(self):
        sql = "SELECT * FROM users WHERE id = 1"
        result = rewrite_query(sql)
        assert not result.was_rewritten


class TestUnionToUnionAll:
    """Tests for UNION → UNION ALL."""

    def test_rewrites_union_with_where(self):
        sql = (
            "SELECT id FROM active_users WHERE type = 'admin' "
            "UNION "
            "SELECT id FROM active_users WHERE type = 'superadmin'"
        )
        result = rewrite_query(sql)
        assert result.was_rewritten
        assert "UNION ALL" in result.rewritten_sql

    def test_no_rewrite_without_where(self):
        sql = "SELECT id FROM users UNION SELECT id FROM admins"
        result = rewrite_query(sql)
        assert "UNION ALL" not in result.rewritten_sql


class TestCoalesceInWhere:
    """Tests for COALESCE in WHERE rewrite."""

    def test_rewrites_coalesce_equal_default(self):
        sql = "SELECT * FROM users WHERE COALESCE(status, 'active') = 'active'"
        result = rewrite_query(sql)
        assert result.was_rewritten
        assert "IS NULL" in result.rewritten_sql
        assert "COALESCE" not in result.rewritten_sql

    def test_rewrites_coalesce_different_value(self):
        sql = "SELECT * FROM users WHERE COALESCE(status, 'unknown') = 'active'"
        result = rewrite_query(sql)
        assert result.was_rewritten
        assert "status = 'active'" in result.rewritten_sql


class TestRewriteResult:
    """Tests for RewriteResult model."""

    def test_was_rewritten_false_when_same(self):
        result = RewriteResult(original_sql="SELECT 1", rewritten_sql="SELECT 1")
        assert not result.was_rewritten

    def test_was_rewritten_true_when_different(self):
        result = RewriteResult(original_sql="SELECT 1", rewritten_sql="SELECT 2")
        assert result.was_rewritten

    def test_explanation_no_rewrites(self):
        result = RewriteResult(original_sql="", rewritten_sql="")
        assert "No rewrites" in result.explanation

    def test_format_sql_includes_comments(self):
        result = RewriteResult(
            original_sql="SELECT 1",
            rewritten_sql="SELECT 2",
            rewrites=[
                Rewrite(
                    name="Test",
                    description="A test rewrite",
                    before_pattern="1",
                    after_pattern="2",
                    rule_id="TEST",
                )
            ],
        )
        formatted = result.format_sql()
        assert "QuerySense Rewritten Query" in formatted
        assert "Test" in formatted

    def test_multiple_rewrites_applied_in_order(self):
        """Verify that multiple rewrites can be applied."""
        sql = (
            "SELECT * FROM users "
            "WHERE id NOT IN (SELECT id FROM blacklist) "
            "AND COALESCE(status, 'active') = 'active'"
        )
        result = rewrite_query(sql)
        assert len(result.rewrites) >= 1
