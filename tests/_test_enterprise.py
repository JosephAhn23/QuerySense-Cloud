"""Functional tests for rewrite patterns, learning path, and OTel."""

# Test Rewrite Pattern Library
from querysense.rewrite_patterns import RewritePatternLibrary

lib = RewritePatternLibrary()
print(f"Rewrite patterns: {len(lib.patterns)}")

# Test NOT IN detection
sql1 = "SELECT * FROM orders WHERE user_id NOT IN (SELECT id FROM banned_users)"
matches1 = lib.find_matches(sql1)
assert any(m.name == "NOT_IN_TO_NOT_EXISTS" for m in matches1), "Should match NOT IN"
print(f"NOT IN matches: {[m.name for m in matches1]}")

# Test safety validation
for m in matches1:
    if m.name == "NOT_IN_TO_NOT_EXISTS":
        safety = m.validate_safety(sql1)
        assert safety.safe
        print(f"  Safety: safe={safety.safe}, confidence={safety.confidence}")

# Test UNION detection
sql2 = "SELECT id FROM orders UNION SELECT id FROM returns"
matches2 = lib.find_matches(sql2)
assert any(m.name == "UNION_TO_UNION_ALL" for m in matches2)
for m in matches2:
    if m.name == "UNION_TO_UNION_ALL":
        safety = m.validate_safety(sql2)
        print(f"UNION safety: safe={safety.safe}, confidence={safety.confidence}")
        # Different tables => likely safe
        assert safety.safe

# Test SELECT * detection
sql3 = "SELECT * FROM orders"
matches3 = lib.find_matches(sql3)
assert any(m.name == "SELECT_STAR" for m in matches3)

# Test safe matches with minimum threshold
safe = lib.find_safe_matches(sql1, min_safety=0.8)
print(f"Safe matches (>0.8): {len(safe)}")

# Test category filtering
subquery_patterns = lib.get_by_category("subquery")
print(f"Subquery patterns: {len(subquery_patterns)}")
assert len(subquery_patterns) >= 3

print("\nREWRITE PATTERNS: ALL TESTS PASSED")

# Test Learning Path
print("\n" + "=" * 60)
from querysense.learning import generate_learning_path
from types import SimpleNamespace

# Simulate findings
findings = [
    SimpleNamespace(rule_id="SEQ_SCAN_LARGE_TABLE"),
    SimpleNamespace(rule_id="BAD_ROW_ESTIMATE"),
    SimpleNamespace(rule_id="SPILLING_TO_DISK"),
    SimpleNamespace(rule_id="NESTED_LOOP_LARGE_TABLE"),
    SimpleNamespace(rule_id="TABLE_BLOAT"),
]

path = generate_learning_path(findings, user_level="beginner")
print(f"Learning path: {path.total_lessons} lessons, {path.estimated_time_minutes} min")
for lesson in path.lessons:
    print(f"  - {lesson.title} ({lesson.category})")
    assert lesson.concepts
    assert lesson.explanation

assert path.total_lessons >= 4
print("\nLEARNING PATH: ALL TESTS PASSED")

# Test OpenTelemetry tracer (no-op mode)
print("\n" + "=" * 60)
from querysense.otel import QuerySenseTracer

tracer = QuerySenseTracer(enabled=True)

with tracer.trace_analysis(plan_hash="abc123", user_id="u-1") as span:
    span.set_attribute("findings.count", 5)
    span.add_event("analysis_complete", {"duration_ms": 42.5})

spans = tracer.get_spans()
assert len(spans) == 1
assert spans[0].attributes["findings.count"] == 5
print(f"OTel spans: {len(spans)}")
print(f"  Span name: {spans[0].name}")
print(f"  Attributes: {len(spans[0].attributes)}")

# Test exception recording
try:
    with tracer.trace_migration(migration_id="m-1") as span:
        raise ValueError("test error")
except ValueError:
    pass

assert len(tracer.get_spans()) == 2
assert tracer.get_spans()[1].status == "error"
print("  Error recording: works")

print("\nOTEL TRACER: ALL TESTS PASSED")
print("\n" + "=" * 60)
print("ALL ENTERPRISE FEATURES VERIFIED")
