import asyncio
import sys
import argparse
from app.infrastructure.gateway.bandit_scanner_impl import BanditScannerGatewayImpl
from app.infrastructure.gateway.gguf_llm_auditor_impl import GgufLlmAuditorGatewayImpl
from app.infrastructure.gateway.sarif_formatter_impl import SarifFormatterGatewayImpl
from app.infrastructure.gateway.ast_context_enricher_impl import AstContextEnricherGatewayImpl
from app.infrastructure.gateway.patch_generator_impl import PatchGeneratorGatewayImpl
from app.core.usecase.run_security_audit_usecase import RunSecurityAuditUseCase
from app.core.usecase.generate_sarif_report_usecase import GenerateSarifReportUseCase


async def async_main():
    """CLI entry point for running AI-augmented SAST scans."""
    parser = argparse.ArgumentParser(
        description="Auditor de Segurança Estática Aumentado por IA (Bandit + GGUF Local)"
    )
    parser.add_argument("path", nargs="?", default=".", help="Diretório ou arquivo alvo para escaneamento")
    parser.add_argument("--format", choices=["table", "sarif", "markdown"], default="table", help="Formato de saída")
    parser.add_argument("--output", help="Arquivo de destino para relatório (ex: results.sarif)")
    parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="HIGH", help="Gatilho de falha para pipeline CI/CD")
    parser.add_argument("--diff", action="store_true", help="Escaneia apenas linhas modificadas no git diff")
    parser.add_argument("--base-ref", default=None, help="Referência base do git para diff (ex: origin/main, HEAD~1)")
    parser.add_argument("--patch-output", help="Arquivo de destino para patches unificados git (.patch)")
    args = parser.parse_args()

    scanner_gw = BanditScannerGatewayImpl()
    llm_gw = GgufLlmAuditorGatewayImpl()
    formatter_gw = SarifFormatterGatewayImpl()
    ast_enricher = AstContextEnricherGatewayImpl()
    patch_gen = PatchGeneratorGatewayImpl()

    audit_uc = RunSecurityAuditUseCase(
        scanner_gateway=scanner_gw,
        llm_gateway=llm_gw,
        ast_enricher=ast_enricher,
        patch_generator=patch_gen,
    )
    sarif_uc = GenerateSarifReportUseCase(formatter_gw)

    report = await audit_uc.execute(args.path, diff_mode=args.diff, base_ref=args.base_ref)

    if args.format == "sarif":
        output_str = sarif_uc.execute(report)
    elif args.format == "markdown":
        output_str = formatter_gw.format_markdown(report)
    else:
        # Table format
        output_str = (
            f"\n🛡️ [SAST A.I. AUDITOR] Escaneamento Concluído em '{report.scanned_target}'\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Modo Diff: {'ATIVADO' if args.diff else 'DESATIVADO'} | "
            f"Total Analisado: {report.total_raw_findings} | "
            f"Confirmados: {report.confirmed_vulnerabilities} | "
            f"Falsos Positivos: {report.discarded_false_positives}\n"
            f"Score de Risco Global: {report.risk_score:.1f} / 100\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        for f in report.findings:
            a = report.assessments.get(f.finding_id)
            scope_info = f" [{f.enclosing_scope}]" if f.enclosing_scope else ""
            output_str += (
                f"\n[{f.severity.value}] {f.test_id} at {f.filename}:{f.line_number}{scope_info}\n"
                f"   Descrição: {f.issue_text}\n"
                f"   Veredito IA: {a.verdict.value if a else 'N/A'}\n"
                f"   Justificativa: {a.reasoning if a else 'N/A'}\n"
                f"   Correção Sugerida: {a.suggested_fix if a else 'N/A'}\n"
            )

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Relatório salvo com sucesso em '{args.output}'")
    else:
        print(output_str)

    if args.patch_output:
        patch_str = patch_gen.generate_unified_patch(report)
        with open(args.patch_output, "w", encoding="utf-8") as f:
            f.write(patch_str)
        print(f"Patches de remediação unificados salvos em '{args.patch_output}'")

    # Check CI failure exit code
    has_high_confirmed = any(
        f.severity.value in ["HIGH", "CRITICAL"] and report.assessments.get(f.finding_id).verdict.value == "TRUE_POSITIVE"
        for f in report.findings
    )

    if args.fail_on in ["HIGH", "CRITICAL"] and has_high_confirmed:
        print("❌ Pipeline interrompido: Vulnerabilidade crítica/alta confirmada por IA encontrada.")
        sys.exit(1)


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
