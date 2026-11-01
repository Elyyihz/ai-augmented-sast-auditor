from abc import ABC, abstractmethod
from app.core.domain.models.vulnerability import SecurityAuditReport, VulnerabilityFinding, FalsePositiveAssessment


class PatchGeneratorGateway(ABC):
    """Abstract interface defining creation of unified diff patch files from remediation proposals."""

    @abstractmethod
    def generate_unified_patch(self, report: SecurityAuditReport) -> str:
        """Constructs unified git patch text format (.patch) for verified vulnerabilities.

        Args:
            report: SecurityAuditReport with confirmed findings and fixes.

        Returns:
            Unified diff formatted string ready for `git apply`.
        """
        pass
