import pytest
import tempfile
import os
from app.core.domain.models.vulnerability import (
    VulnerabilityFinding,
    SecurityAuditReport,
    FalsePositiveAssessment,
)
from app.core.domain.enum.severity import Severity, Confidence, AssessmentVerdict
from app.infrastructure.gateway.bandit_scanner_impl import BanditScannerGatewayImpl
from app.infrastructure.gateway.gguf_llm_auditor_impl import GgufLlmAuditorGatewayImpl
from app.infrastructure.gateway.sarif_formatter_impl import SarifFormatterGatewayImpl
from app.infrastructure.gateway.ast_context_enricher_impl import AstContextEnricherGatewayImpl
from app.infrastructure.gateway.patch_generator_impl import PatchGeneratorGatewayImpl
from app.core.usecase.run_security_audit_usecase import RunSecurityAuditUseCase
from app.core.usecase.generate_sarif_report_usecase import GenerateSarifReportUseCase


def test_domain_model_creation():
    """Validates default instantiation of VulnerabilityFinding."""
    finding = VulnerabilityFinding(
        test_id="B608",
        issue_text="Hardcoded secret",
        filename="auth.py",
        severity=Severity.HIGH,
    )
    assert finding.finding_id is not None
    assert finding.test_id == "B608"
    assert finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_audit_pipeline_weeds_out_false_positives():
    """Validates that AI evaluation correctly weeds out false positives."""
    scanner_gw = BanditScannerGatewayImpl()
    llm_gw = GgufLlmAuditorGatewayImpl()
    formatter_gw = SarifFormatterGatewayImpl()
    ast_enricher = AstContextEnricherGatewayImpl()
    patch_gen = PatchGeneratorGatewayImpl()

    audit_uc = RunSecurityAuditUseCase(
        scanner_gateway=scanner_gw,
        llm_gateway=llm_gw,
        ast_enricher=ast_enricher,
        patch_generator=patch_gen,
    )
    sarif_uc = GenerateSarifReportUseCase(formatter_gw)

    report = await audit_uc.execute("sample_project")

    assert report.total_raw_findings >= 2
    assert report.confirmed_vulnerabilities >= 1
    assert report.discarded_false_positives >= 1

    sarif = sarif_uc.execute(report)
    assert "$schema" in sarif
    assert "ai-augmented-sast-auditor" in sarif


def test_ast_context_enricher_extracts_function_scope():
    """Validates AST extraction of enclosing function and docstrings."""
    enricher = AstContextEnricherGatewayImpl()

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(
            'class UserRepo:\n'
            '    """Repository for querying users."""\n'
            '    def get_by_id(self, user_id: str):\n'
            '        """Fetches user record."""\n'
            '        query = f"SELECT * FROM users WHERE id = {user_id}"\n'
            '        return query\n'
        )
        temp_path = f.name

    try:
        finding = VulnerabilityFinding(
            test_id="B608",
            issue_text="SQL injection",
            filename=temp_path,
            line_number=5,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"',
        )
        enriched = enricher.enrich(finding)
        assert enriched.enclosing_scope == "FunctionDef:get_by_id"
        assert "Fetches user record." in enriched.ast_context
    finally:
        os.remove(temp_path)


def test_patch_generator_creates_unified_diff():
    """Validates unified diff patch formatting for git apply."""
    generator = PatchGeneratorGatewayImpl()

    finding = VulnerabilityFinding(
        finding_id="find-123",
        test_id="B608",
        filename="app/db/query.py",
        line_number=42,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    )
    assessment = FalsePositiveAssessment(
        finding_id="find-123",
        verdict=AssessmentVerdict.TRUE_POSITIVE,
        reasoning="Raw SQL formatting",
        suggested_fix='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    )
    report = SecurityAuditReport(
        scanned_target="app/db",
        findings=[finding],
        assessments={finding.finding_id: assessment},
    )

    patch_text = generator.generate_unified_patch(report)
    assert "diff --git a/app/db/query.py b/app/db/query.py" in patch_text
    assert "--- a/app/db/query.py" in patch_text
    assert "+++ b/app/db/query.py" in patch_text
    assert "-cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")" in patch_text
    assert "+cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))" in patch_text
