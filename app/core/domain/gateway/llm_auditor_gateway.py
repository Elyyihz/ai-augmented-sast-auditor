from abc import ABC, abstractmethod
from app.core.domain.models.vulnerability import VulnerabilityFinding, FalsePositiveAssessment


class LlmAuditorGateway(ABC):
    """Abstract interface defining AI evaluation of flagged vulnerabilities."""

    @abstractmethod
    async def evaluate_finding(
        self,
        finding: VulnerabilityFinding,
        file_content_context: str
    ) -> FalsePositiveAssessment:
        """Evaluates whether static finding is an exploitable true positive or benign code.

        Args:
            finding: VulnerabilityFinding entity.
            file_content_context: Full source context enclosing the line.

        Returns:
            FalsePositiveAssessment entity with verdict and fix.
        """
        pass
