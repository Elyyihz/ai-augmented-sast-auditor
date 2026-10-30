from abc import ABC, abstractmethod
from app.core.domain.models.vulnerability import SecurityAuditReport


class ReportFormatterGateway(ABC):
    """Abstract interface defining serialization of audit reports."""

    @abstractmethod
    def format_sarif(self, report: SecurityAuditReport) -> str:
        """Serializes report into OASIS SARIF v2.1.0 JSON format for GitHub Security upload.

        Args:
            report: SecurityAuditReport domain entity.

        Returns:
            SARIF JSON string.
        """
        pass

    @abstractmethod
    def format_markdown(self, report: SecurityAuditReport) -> str:
        """Generates GitHub Actions step summary / PR comment in Markdown.

        Args:
            report: SecurityAuditReport domain entity.

        Returns:
            Markdown formatted string.
        """
        pass
