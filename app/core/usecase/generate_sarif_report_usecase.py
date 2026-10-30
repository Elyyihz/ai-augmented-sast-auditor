import logging
from app.core.domain.models.vulnerability import SecurityAuditReport
from app.core.domain.gateway.report_formatter_gateway import ReportFormatterGateway

logger = logging.getLogger("sast_auditor.usecase.sarif")


class GenerateSarifReportUseCase:
    """Formats domain audit report into SARIF format for CI/CD integrations."""

    def __init__(self, formatter_gateway: ReportFormatterGateway):
        """Initializes with formatter port.

        Args:
            formatter_gateway: ReportFormatterGateway port.
        """
        self.formatter_gateway = formatter_gateway

    def execute(self, report: SecurityAuditReport) -> str:
        """Serializes report to SARIF format.

        Args:
            report: SecurityAuditReport entity.

        Returns:
            SARIF JSON string.
        """
        logger.info("Step started: Serializing audit report %s to SARIF standard", report.audit_id)
        sarif_json = self.formatter_gateway.format_sarif(report)
        logger.info("Step concluded: Generated SARIF artifact with %d findings", report.confirmed_vulnerabilities)
        return sarif_json
