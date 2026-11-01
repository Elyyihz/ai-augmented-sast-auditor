import logging
from app.core.domain.gateway.patch_generator_gateway import PatchGeneratorGateway
from app.core.domain.models.vulnerability import SecurityAuditReport
from app.core.domain.enum.severity import AssessmentVerdict

logger = logging.getLogger("sast_auditor.infra.patch_generator")


class PatchGeneratorGatewayImpl(PatchGeneratorGateway):
    """Generates standard unified diff patch files (.patch) from AI remediation proposals."""

    def generate_unified_patch(self, report: SecurityAuditReport) -> str:
        """Builds git-compatible unified diff patch suitable for `git apply`.

        Args:
            report: Security audit report containing verified findings and fixes.

        Returns:
            Unified diff formatted patch string.
        """
        diff_chunks = []

        for finding in report.findings:
            assessment = report.assessments.get(finding.finding_id)
            if not assessment or assessment.verdict == AssessmentVerdict.FALSE_POSITIVE:
                continue

            fix = assessment.suggested_fix
            if not fix or fix.startswith("None needed"):
                continue

            filepath = finding.filename.lstrip("./")
            line = max(1, finding.line_number)

            raw_snippet = finding.code_snippet.strip()
            fixed_snippet = fix.strip()

            snippet_lines = raw_snippet.splitlines() or ["# vulnerable code"]
            fixed_lines = fixed_snippet.splitlines() or ["# fixed code"]

            old_count = len(snippet_lines)
            new_count = len(fixed_lines)

            chunk = [
                f"diff --git a/{filepath} b/{filepath}",
                f"--- a/{filepath}",
                f"+++ b/{filepath}",
                f"@@ -{line},{old_count} +{line},{new_count} @@",
            ]

            for l in snippet_lines:
                chunk.append(f"-{l}")
            for l in fixed_lines:
                chunk.append(f"+{l}")

            diff_chunks.append("\n".join(chunk))

        if not diff_chunks:
            return "# No actionable automated patches proposed for this audit report.\n"

        return "\n\n".join(diff_chunks) + "\n"
