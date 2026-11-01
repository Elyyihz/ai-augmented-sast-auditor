from abc import ABC, abstractmethod
from app.core.domain.models.vulnerability import VulnerabilityFinding


class AstContextEnricherGateway(ABC):
    """Abstract interface defining AST-level context extraction for code findings."""

    @abstractmethod
    def enrich(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Inspects surrounding AST of the finding file to extract enclosing scope.

        Args:
            finding: Raw VulnerabilityFinding.

        Returns:
            VulnerabilityFinding enriched with enclosing_scope and ast_context.
        """
        pass
