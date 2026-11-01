import ast
import logging
import os
from typing import Optional
from app.core.domain.gateway.ast_context_enricher_gateway import AstContextEnricherGateway
from app.core.domain.models.vulnerability import VulnerabilityFinding

logger = logging.getLogger("sast_auditor.infra.ast_enricher")


class AstContextEnricherGatewayImpl(AstContextEnricherGateway):
    """Enriches vulnerability findings by parsing Python AST and locating enclosing scopes."""

    def enrich(self, finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """Inspects source AST to identify the enclosing function or class.

        Args:
            finding: Raw finding.

        Returns:
            Enriched finding with AST scope and context.
        """
        if not finding.filename or not os.path.exists(finding.filename):
            # Fallback for synthetic / remote findings
            finding.enclosing_scope = "Scope:GlobalOrSynthetic"
            finding.ast_context = (
                f"# Scope context synthetic for {finding.filename}:{finding.line_number}\n"
                f"{finding.code_snippet}"
            )
            return finding

        try:
            with open(finding.filename, "r", encoding="utf-8") as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=finding.filename)
            lines = source_code.splitlines()

            enclosing_node: Optional[ast.AST] = None
            smallest_span = float("inf")

            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = getattr(node, "lineno", 0)
                    end = getattr(node, "end_lineno", start)
                    if start <= finding.line_number <= end:
                        span = end - start
                        if span < smallest_span:
                            smallest_span = span
                            enclosing_node = node

            if enclosing_node:
                kind = type(enclosing_node).__name__
                name = getattr(enclosing_node, "name", "unknown")
                doc = ast.get_docstring(enclosing_node) or "No docstring provided"
                start = getattr(enclosing_node, "lineno", 1)
                end = getattr(enclosing_node, "end_lineno", len(lines))
                scope_code = "\n".join(lines[max(0, start - 1):end])

                finding.enclosing_scope = f"{kind}:{name}"
                finding.ast_context = (
                    f"## Enclosing Scope: {kind} '{name}' (lines {start}-{end})\n"
                    f"## Docstring: {doc}\n"
                    f"## Source:\n{scope_code}"
                )
                logger.debug("Enriched finding %s with AST scope '%s'", finding.finding_id, finding.enclosing_scope)
            else:
                finding.enclosing_scope = "Module:TopLevel"
                finding.ast_context = f"# Module-level statement\n{finding.code_snippet}"

        except Exception as exc:
            logger.warning("Failed AST parsing for %s (%s); retaining raw snippet", finding.filename, exc)
            finding.enclosing_scope = "ParseError:Fallback"
            finding.ast_context = finding.code_snippet

        return finding
