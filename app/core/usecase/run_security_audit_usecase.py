import logging
from app.core.domain.models.vulnerability import (
    SecurityAuditReport,
    VulnerabilityFinding,
    FalsePositiveAssessment,
)
from app.core.domain.enum.severity import AssessmentVerdict, Severity
from app.core.domain.gateway.sast_scanner_gateway import SastScannerGateway
from app.core.domain.gateway.llm_auditor_gateway import LlmAuditorGateway

logger = logging.getLogger("sast_auditor.usecase.run_audit")


class RunSecurityAuditUseCase:
    """Executes static analysis scan, delegates to AI evaluation, and aggregates report."""

    def __init__(
        self,
        scanner_gateway: SastScannerGateway,
        llm_gateway: LlmAuditorGateway,
    ):
        """Initializes with scanner and AI auditor ports.

        Args:
            scanner_gateway: Bandit static scanner port.
            llm_gateway: Local GGUF LLM auditor port.
        """
        self.scanner_gateway = scanner_gateway
        self.llm_gateway = llm_gateway

    async def execute(self, target_path: str) -> SecurityAuditReport:
        """Runs audit pipeline over target codebase.

        Args:
            target_path: File or directory path.

        Returns:
            SecurityAuditReport containing raw findings and AI verdicts.
        """
        logger.info("Step started: Launching SAST security scan on path '%s'", target_path)

        raw_findings = await self.scanner_gateway.scan_directory(target_path)
        logger.info("Decision taken: Bandit scanner identified %d candidate findings", len(raw_findings))

        assessments = {}
        confirmed_count = 0
        false_positive_count = 0

        for finding in raw_findings:
            logger.info("Step started: Evaluating finding %s (%s at %s:%d) via local AI model", finding.finding_id, finding.test_id, finding.filename, finding.line_number)
            assessment = await self.llm_gateway.evaluate_finding(finding, finding.code_snippet)
            assessments[finding.finding_id] = assessment

            if assessment.verdict == AssessmentVerdict.TRUE_POSITIVE:
                confirmed_count += 1
                logger.warning("Decision taken: Finding %s confirmed as TRUE POSITIVE: %s", finding.finding_id, assessment.reasoning)
            elif assessment.verdict == AssessmentVerdict.FALSE_POSITIVE:
                false_positive_count += 1
                logger.info("Decision taken: Finding %s dismissed as FALSE POSITIVE: %s", finding.finding_id, assessment.reasoning)
            else:
                confirmed_count += 1
                logger.info("Decision taken: Finding %s flagged for HUMAN REVIEW", finding.finding_id)

        # Calculate composite risk score [0..100]
        risk = min(100.0, float(confirmed_count * 25.0))

        report = SecurityAuditReport(
            scanned_target=target_path,
            total_raw_findings=len(raw_findings),
            confirmed_vulnerabilities=confirmed_count,
            discarded_false_positives=false_positive_count,
            findings=raw_findings,
            assessments=assessments,
            risk_score=risk,
        )

        logger.info(
            "Step concluded: Security audit completed with %d confirmed bugs and %d false positives filtered out (Risk: %.1f)",
            confirmed_count,
            false_positive_count,
            risk,
        )
        return report
