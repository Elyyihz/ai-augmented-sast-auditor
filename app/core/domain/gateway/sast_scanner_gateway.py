from abc import ABC, abstractmethod
from typing import List
from app.core.domain.models.vulnerability import VulnerabilityFinding


class SastScannerGateway(ABC):
    """Abstract interface defining static security analysis execution."""

    @abstractmethod
    async def scan_directory(self, target_path: str) -> List[VulnerabilityFinding]:
        """Runs Bandit security rules over source code tree.

        Args:
            target_path: Directory path to analyze.

        Returns:
            List of detected VulnerabilityFinding entities.
        """
        pass
