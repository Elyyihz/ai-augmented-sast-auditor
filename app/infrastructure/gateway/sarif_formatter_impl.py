import json
import logging
from app.core.domain.gateway.report_formatter_gateway import ReportFormatterGateway
from app.core.domain.models.vulnerability import SecurityAuditReport
from app.core.domain.enum.severity import AssessmentVerdict

logger = logging.getLogger("sast_auditor.infra.sarif")


class SarifFormatterGatewayImpl(ReportFormatterGateway):
    """Produces OASIS SARIF v2.1.0 standard and Markdown formats."""

    def format_sarif(self, report: SecurityAuditReport) -> str:
        """Generates standard SARIF document.

        Args:
            report: SecurityAuditReport entity.

        Returns:
            JSON formatted SARIF string.
        """
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ai-augmented-sast-auditor",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/Elyyihz/ai-augmented-sast-auditor",
                            "rules": [],
                        }
                    },
                    "results": [],
                }
            ],
        }

        results = []
        for finding in report.findings:
            assessment = report.assessments.get(finding.finding_id)
            # Only include confirmed True Positives in SARIF alert stream
            if assessment and assessment.verdict == AssessmentVerdict.FALSE_POSITIVE:
                continue

            results.append({
                "ruleId": finding.test_id,
                "level": "error" if finding.severity.value in ["HIGH", "CRITICAL"] else "warning",
                "message": {
                    "text": f"{finding.issue_text} (AI Validation: {assessment.reasoning if assessment else 'Unreviewed'})"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.filename},
                            "region": {"startLine": finding.line_number},
                        }
                    }
                ],
            })

        sarif["runs"][0]["results"] = results
        return json.dumps(sarif, indent=2)

    def format_markdown(self, report: SecurityAuditReport) -> str:
        """Generates GitHub Actions job summary in Markdown.

        Args:
            report: SecurityAuditReport entity.

        Returns:
            Markdown string.
        """
        lines = [
            f"# 🛡️ Relatório de Auditoria SAST Aumentada por IA",
            f"",
            f"- **Alvo Auditado:** `{report.scanned_target}`",
            f"- **Total de Achados Bandit:** `{report.total_raw_findings}`",
            f"- **Vulnerabilidades Confirmadas (True Positives):** `{report.confirmed_vulnerabilities}`",
            f"- **Falsos Positivos Descartados por IA:** `{report.discarded_false_positives}`",
            f"- **Score de Risco:** `{report.risk_score:.1f} / 100`",
            f"",
            f"| Test ID | Arquivo | Linha | Severidade | Veredito IA | Justificativa |",
            f"| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for finding in report.findings:
            assessment = report.assessments.get(finding.finding_id)
            verdict = assessment.verdict.value if assessment else "UNREVIEWED"
            reasoning = assessment.reasoning if assessment else "N/A"
            lines.append(
                f"| `{finding.test_id}` | `{finding.filename}` | {finding.line_number} | {finding.severity.value} | **{verdict}** | {reasoning} |"
            )

        return "\n".join(lines)
