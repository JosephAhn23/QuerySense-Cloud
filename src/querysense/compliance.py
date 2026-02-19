"""
Compliance enforcement engine for QuerySense.

Provides regulation-specific compliance packs (PCI-DSS, HIPAA, SOC2, GDPR, SOX)
with table classification, auto-PII detection, pgAudit validation, and SARIF output.

Usage:
    from querysense.compliance import ComplianceEngine, load_table_classifications

    tables = load_table_classifications(".querysense/tables.yml")
    engine = ComplianceEngine(tables, regulations=["PCI-DSS", "HIPAA"])
    violations = engine.check_query(sql_text, findings)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Data Classification ────────────────────────────────────────────────


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class PIIType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    NAME = "name"
    ADDRESS = "address"
    DOB = "date_of_birth"
    IP_ADDRESS = "ip_address"
    HEALTH_INFO = "health_info"
    FINANCIAL = "financial"
    BIOMETRIC = "biometric"
    GENERIC_PII = "generic_pii"


@dataclass(frozen=True)
class ColumnClassification:
    name: str
    pii: bool = False
    pii_type: PIIType | None = None
    masked: bool = False
    encrypted: bool = False


@dataclass(frozen=True)
class TableClassification:
    name: str
    schema_name: str = "public"
    classification: DataClassification = DataClassification.INTERNAL
    regulations: tuple[str, ...] = ()
    columns: dict[str, ColumnClassification] = field(default_factory=dict)
    description: str = ""
    owner: str = ""

    @property
    def has_pii(self) -> bool:
        return any(c.pii for c in self.columns.values())

    @property
    def pii_columns(self) -> list[str]:
        return [name for name, c in self.columns.items() if c.pii]

    @property
    def is_restricted(self) -> bool:
        return self.classification == DataClassification.RESTRICTED


# ── Compliance Violations ──────────────────────────────────────────────


class ComplianceViolationType(str, Enum):
    SELECT_STAR_PII = "select_star_pii"
    MISSING_WHERE_CLAUSE = "missing_where_clause"
    CROSS_SCHEMA_PII = "cross_schema_pii"
    BULK_PII_EXPORT = "bulk_pii_export"
    UNMASKED_PII_ACCESS = "unmasked_pii_access"
    MISSING_AUDIT_LOG = "missing_audit_log"
    MISSING_ROW_LIMIT = "missing_row_limit"
    DDL_ON_CLASSIFIED = "ddl_on_classified"
    MINIMUM_NECESSARY = "minimum_necessary"
    MISSING_ENCRYPTION = "missing_encryption"


@dataclass(frozen=True)
class ComplianceViolation:
    violation_type: ComplianceViolationType
    regulation: str
    severity: str
    message: str
    table: str = ""
    column: str = ""
    rule_reference: str = ""
    remediation: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_type": self.violation_type.value,
            "regulation": self.regulation,
            "severity": self.severity,
            "message": self.message,
            "table": self.table,
            "column": self.column,
            "rule_reference": self.rule_reference,
            "remediation": self.remediation,
            "details": self.details,
        }

    def to_sarif_result(self) -> dict[str, Any]:
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        return {
            "ruleId": f"querysense/compliance/{self.violation_type.value}",
            "level": level_map.get(self.severity, "warning"),
            "message": {"text": self.message},
            "properties": {
                "regulation": self.regulation,
                "table": self.table,
                "column": self.column,
                "rule_reference": self.rule_reference,
                "remediation": self.remediation,
            },
        }


# ── Regulation Packs ───────────────────────────────────────────────────


def _pci_dss_rules(
    sql: str, tables: dict[str, TableClassification], referenced_tables: list[str],
) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []
    sql_upper = sql.upper()

    for table_name in referenced_tables:
        tc = tables.get(table_name)
        if tc is None or "PCI-DSS" not in tc.regulations:
            continue

        if re.search(r"\bSELECT\s+\*\s", sql_upper) and tc.has_pii:
            non_pii = [c for c in tc.columns if not tc.columns[c].pii]
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.SELECT_STAR_PII,
                regulation="PCI-DSS", severity="critical",
                message=f"SELECT * on cardholder data table '{table_name}' exposes unnecessary columns",
                table=table_name, rule_reference="PCI-DSS 3.4.1",
                remediation=f"Explicitly list required columns: SELECT {', '.join(non_pii)} FROM {table_name}" if non_pii else "Remove SELECT * and list only needed columns",
            ))

        if not re.search(r"\bWHERE\b", sql_upper) and "SELECT" in sql_upper:
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.MISSING_WHERE_CLAUSE,
                regulation="PCI-DSS", severity="high",
                message=f"Query on CHD table '{table_name}' lacks WHERE clause",
                table=table_name, rule_reference="PCI-DSS 7.2.1",
                remediation="Add a WHERE clause to limit data access",
            ))

    return violations


def _hipaa_rules(
    sql: str, tables: dict[str, TableClassification], referenced_tables: list[str],
) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []
    sql_upper = sql.upper()

    for table_name in referenced_tables:
        tc = tables.get(table_name)
        if tc is None or "HIPAA" not in tc.regulations:
            continue

        if re.search(r"\bSELECT\s+\*\s", sql_upper) and tc.has_pii:
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.MINIMUM_NECESSARY,
                regulation="HIPAA", severity="critical",
                message=f"SELECT * on PHI table '{table_name}' violates minimum necessary principle",
                table=table_name, rule_reference="HIPAA 164.502(b)",
                remediation="Select only the specific PHI columns needed for the task",
            ))

        if not re.search(r"\bWHERE\b", sql_upper) and not re.search(r"\bLIMIT\b", sql_upper):
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.BULK_PII_EXPORT,
                regulation="HIPAA", severity="high",
                message=f"Unbounded query on PHI table '{table_name}'",
                table=table_name, rule_reference="HIPAA 164.312(b)",
                remediation="Add WHERE clause and/or LIMIT to restrict PHI access",
            ))

    return violations


def _soc2_rules(
    sql: str, tables: dict[str, TableClassification], referenced_tables: list[str],
) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []
    sql_upper = sql.upper()

    for table_name in referenced_tables:
        tc = tables.get(table_name)
        if tc is None:
            continue

        if tc.is_restricted and re.search(r"\b(ALTER|DROP|TRUNCATE)\s+(TABLE|INDEX)", sql_upper):
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.DDL_ON_CLASSIFIED,
                regulation="SOC2", severity="high",
                message=f"DDL operation on restricted table '{table_name}' requires change management review",
                table=table_name, rule_reference="SOC2 CC8.1",
                remediation="Ensure DDL changes go through change management process",
            ))

    return violations


def _gdpr_rules(
    sql: str, tables: dict[str, TableClassification], referenced_tables: list[str],
) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []
    sql_upper = sql.upper()

    for table_name in referenced_tables:
        tc = tables.get(table_name)
        if tc is None or "GDPR" not in tc.regulations:
            continue

        if re.search(r"\bSELECT\s+\*\s", sql_upper) and tc.has_pii:
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.SELECT_STAR_PII,
                regulation="GDPR", severity="medium",
                message=f"SELECT * on personal data table '{table_name}' may violate data minimization",
                table=table_name, rule_reference="GDPR Article 5(1)(c)",
                remediation="Select only necessary columns to comply with data minimization",
            ))

    return violations


def _sox_rules(
    sql: str, tables: dict[str, TableClassification], referenced_tables: list[str],
) -> list[ComplianceViolation]:
    violations: list[ComplianceViolation] = []
    sql_upper = sql.upper()

    for table_name in referenced_tables:
        tc = tables.get(table_name)
        if tc is None or "SOX" not in tc.regulations:
            continue

        if re.search(r"\b(UPDATE|DELETE|INSERT)\b", sql_upper) and tc.classification in (
            DataClassification.RESTRICTED, DataClassification.CONFIDENTIAL,
        ):
            violations.append(ComplianceViolation(
                violation_type=ComplianceViolationType.MISSING_AUDIT_LOG,
                regulation="SOX", severity="high",
                message=f"Data modification on financial table '{table_name}' must have audit trail",
                table=table_name, rule_reference="SOX Section 302/404",
                remediation="Ensure pgAudit logs all DML on this table",
            ))

    return violations


REGULATION_CHECKERS = {
    "PCI-DSS": _pci_dss_rules,
    "HIPAA": _hipaa_rules,
    "SOC2": _soc2_rules,
    "GDPR": _gdpr_rules,
    "SOX": _sox_rules,
}


class ComplianceEngine:
    def __init__(
        self,
        tables: dict[str, TableClassification] | None = None,
        regulations: list[str] | None = None,
    ) -> None:
        self.tables = tables or {}
        self.regulations = regulations or list(REGULATION_CHECKERS.keys())

    def check_query(
        self, sql: str, referenced_tables: list[str] | None = None,
    ) -> list[ComplianceViolation]:
        if referenced_tables is None:
            referenced_tables = _extract_tables_from_sql(sql)

        violations: list[ComplianceViolation] = []
        for regulation in self.regulations:
            checker = REGULATION_CHECKERS.get(regulation)
            if checker:
                violations.extend(checker(sql, self.tables, referenced_tables))
        return violations

    def check_pgaudit_config(
        self, pgaudit_settings: dict[str, str],
    ) -> list[ComplianceViolation]:
        violations: list[ComplianceViolation] = []
        pgaudit_log = pgaudit_settings.get("pgaudit.log", "none")

        if pgaudit_log == "none":
            for table_name, tc in self.tables.items():
                if tc.is_restricted:
                    violations.append(ComplianceViolation(
                        violation_type=ComplianceViolationType.MISSING_AUDIT_LOG,
                        regulation=tc.regulations[0] if tc.regulations else "SOC2",
                        severity="critical",
                        message=f"pgAudit not enabled — restricted table '{table_name}' has no audit coverage",
                        table=table_name,
                        remediation="Enable pgAudit: ALTER SYSTEM SET pgaudit.log = 'read, write, ddl'",
                    ))
            return violations

        log_categories = set(pgaudit_log.replace(" ", "").split(","))

        if "read" not in log_categories:
            for table_name, tc in self.tables.items():
                if tc.has_pii:
                    for reg in tc.regulations:
                        if reg in ("PCI-DSS", "HIPAA"):
                            violations.append(ComplianceViolation(
                                violation_type=ComplianceViolationType.MISSING_AUDIT_LOG,
                                regulation=reg, severity="high",
                                message=f"pgAudit READ logging not enabled for '{table_name}'",
                                table=table_name,
                                remediation="ALTER SYSTEM SET pgaudit.log = 'read, write, ddl'",
                            ))

        if "write" not in log_categories:
            for table_name, tc in self.tables.items():
                if "SOX" in tc.regulations:
                    violations.append(ComplianceViolation(
                        violation_type=ComplianceViolationType.MISSING_AUDIT_LOG,
                        regulation="SOX", severity="critical",
                        message=f"pgAudit WRITE logging not enabled for '{table_name}'",
                        table=table_name,
                        remediation="ALTER SYSTEM SET pgaudit.log = 'read, write, ddl'",
                    ))

        return violations

    def generate_sarif_report(self, violations: list[ComplianceViolation]) -> dict[str, Any]:
        rules: list[dict[str, Any]] = []
        seen_rules: set[str] = set()

        for v in violations:
            rule_id = f"querysense/compliance/{v.violation_type.value}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "shortDescription": {"text": v.violation_type.value.replace("_", " ").title()},
                    "helpUri": "https://github.com/JosephAhn23/Query-Sense",
                    "properties": {"regulation": v.regulation},
                })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "QuerySense Compliance",
                        "version": "0.5.2",
                        "informationUri": "https://github.com/JosephAhn23/Query-Sense",
                        "rules": rules,
                    }
                },
                "results": [v.to_sarif_result() for v in violations],
            }],
        }


# ── Auto-PII Detection ────────────────────────────────────────────────


PII_COLUMN_PATTERNS: dict[str, PIIType] = {
    r"(?:^|_)(email|e_mail|mail)(?:_|$)": PIIType.EMAIL,
    r"(?:^|_)(phone|mobile|cell|tel|fax)(?:_|$)": PIIType.PHONE,
    r"(?:^|_)(ssn|social_security|sin|national_id)(?:_|$)": PIIType.SSN,
    r"(?:^|_)(card|credit_card|cc_num|card_number|pan)(?:_|$)": PIIType.CREDIT_CARD,
    r"(?:^|_)(first_name|last_name|full_name|given_name|surname|display_name)(?:_|$)": PIIType.NAME,
    r"(?:^|_)(address|street|city|zip|postal|state|country)(?:_|$)": PIIType.ADDRESS,
    r"(?:^|_)(dob|date_of_birth|birth_date|birthday)(?:_|$)": PIIType.DOB,
    r"(?:^|_)(ip_addr|ip_address|remote_addr|client_ip)(?:_|$)": PIIType.IP_ADDRESS,
    r"(?:^|_)(diagnosis|medical|health|prescription|icd_code)(?:_|$)": PIIType.HEALTH_INFO,
    r"(?:^|_)(salary|income|balance|account_num|routing)(?:_|$)": PIIType.FINANCIAL,
    r"(?:^|_)(fingerprint|face_id|retina|voiceprint)(?:_|$)": PIIType.BIOMETRIC,
    r"(?:^|_)(passport|driver_license|license_num)(?:_|$)": PIIType.GENERIC_PII,
}


def detect_pii_columns(column_names: list[str]) -> dict[str, PIIType]:
    detections: dict[str, PIIType] = {}
    for col in column_names:
        col_lower = col.lower()
        for pattern, pii_type in PII_COLUMN_PATTERNS.items():
            if re.search(pattern, col_lower, re.IGNORECASE):
                detections[col] = pii_type
                break
    return detections


# ── Table Classification Loading ───────────────────────────────────────


def load_table_classifications(
    path: str | Path = ".querysense/tables.yml",
) -> dict[str, TableClassification]:
    config_path = Path(path)
    if not config_path.exists():
        logger.debug("No table classification file at %s", path)
        return {}

    try:
        raw = config_path.read_text(encoding="utf-8")
        if config_path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                data = yaml.safe_load(raw)
            except ImportError:
                logger.warning("PyYAML not installed")
                return {}
        else:
            data = json.loads(raw)

        if not isinstance(data, dict):
            return {}
        return _parse_table_classifications(data)
    except Exception as e:
        logger.error("Failed to load table classifications: %s", e)
        return {}


def _parse_table_classifications(data: dict[str, Any]) -> dict[str, TableClassification]:
    tables: dict[str, TableClassification] = {}

    for table_name, table_data in data.get("tables", {}).items():
        if not isinstance(table_data, dict):
            continue

        try:
            classification = DataClassification(table_data.get("classification", "internal").lower())
        except ValueError:
            classification = DataClassification.INTERNAL

        regulations = tuple(table_data.get("regulations", []))
        columns: dict[str, ColumnClassification] = {}

        for col_name, col_data in table_data.get("columns", {}).items():
            if isinstance(col_data, dict):
                pii_type = None
                if pii_type_str := col_data.get("type"):
                    try:
                        pii_type = PIIType(pii_type_str)
                    except ValueError:
                        pass

                columns[col_name] = ColumnClassification(
                    name=col_name,
                    pii=col_data.get("pii", False),
                    pii_type=pii_type,
                    masked=col_data.get("masked", False),
                    encrypted=col_data.get("encrypted", False),
                )

        tables[table_name] = TableClassification(
            name=table_name,
            schema_name=table_data.get("schema", "public"),
            classification=classification,
            regulations=regulations,
            columns=columns,
            description=table_data.get("description", ""),
            owner=table_data.get("owner", ""),
        )

    return tables


def generate_default_tables_config() -> str:
    return """\
# QuerySense Table Classifications
# =================================
# Classify tables by data sensitivity and regulatory requirements.
#
# Classifications: public, internal, confidential, restricted
# Regulations: PCI-DSS, HIPAA, SOC2, GDPR, SOX

tables:
  # Example: Payment card data (PCI-DSS)
  # payments:
  #   classification: restricted
  #   regulations: [PCI-DSS, SOX]
  #   columns:
  #     card_number: { pii: true, type: credit_card }
  #     cardholder_name: { pii: true, type: name }
  #     amount: { pii: false }

  # Example: Patient records (HIPAA)
  # patients:
  #   classification: restricted
  #   regulations: [HIPAA]
  #   columns:
  #     diagnosis: { pii: true, type: health_info }
  #     ssn: { pii: true, type: ssn }

  # Example: User data (GDPR)
  # users:
  #   classification: confidential
  #   regulations: [GDPR]
  #   columns:
  #     email: { pii: true, type: email }
  #     phone: { pii: true, type: phone }
"""


def _extract_tables_from_sql(sql: str) -> list[str]:
    tables: set[str] = set()
    for pattern in [
        r"\bFROM\s+([a-zA-Z_]\w*)", r"\bJOIN\s+([a-zA-Z_]\w*)",
        r"\bUPDATE\s+([a-zA-Z_]\w*)", r"\bINSERT\s+INTO\s+([a-zA-Z_]\w*)",
        r"\bDELETE\s+FROM\s+([a-zA-Z_]\w*)",
    ]:
        for match in re.finditer(pattern, sql, re.IGNORECASE):
            tables.add(match.group(1).split(".")[-1])
    return sorted(tables)
