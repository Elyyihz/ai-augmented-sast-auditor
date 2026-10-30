import pytest
from app.core.domain.models.vulnerability import VulnerabilityFinding, SecurityAuditReport
from app.core.domain.enum.severity import Severity, Confidence, AssessmentVerdict
from app.infrastructure.gateway.bandit_scanner_impl import BanditScannerGatewayImpl
from app.infrastructure.gateway.gguf_llm_auditor_impl import GgufLlmAuditorGatewayImpl
from app.infrastructure.gateway.sarif_formatter_impl import SarifFormatterGatewayImpl
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

    audit_uc = RunSecurityAuditUseCase(scanner_gw, llm_gw)
    sarif_uc = GenerateSarifReportUseCase(formatter_gw)

    report = await audit_uc.execute("sample_project")

    assert report.total_raw_findings >= 2
    assert report.confirmed_vulnerabilities >= 1
    assert report.discarded_false_positives >= 1

    sarif = sarif_uc.execute(report)
    assert "$schema" in sarif
    assert "ai-augmented-sast-auditor" in sarif
