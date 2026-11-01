from abc import ABC, abstractmethod
from typing import List, Optional
from app.core.domain.models.vulnerability import VulnerabilityFinding


class SastScannerGateway(ABC):
    """Abstract interface defining static security analysis execution."""

    @abstractmethod
    async def scan_directory(
        self,
        target_path: str,
        diff_mode: bool = False,
        base_ref: Optional[str] = None,
    ) -> List[VulnerabilityFinding]:
        """Runs Bandit security rules over source code tree.

        Args:
            target_path: Directory path to analyze.
            diff_mode: When True, scopes findings to modified git hunks.
            base_ref: Optional git reference for diff comparison (e.g. 'HEAD~1', 'main').

        Returns:
            List of detected VulnerabilityFinding entities.
        """
        pass
