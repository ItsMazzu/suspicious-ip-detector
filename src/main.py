"""
main.py — Ponto de entrada do SIEM Simulator.

Modos de uso:
  1. Análise de CSV  : python -m src.main [--csv caminho/para/arquivo.csv]
  2. IP único        : python -m src.main --ip 1.2.3.4 [--attempts N]
  3. Ajuda           : python -m src.main --help

Exemplos:
  python -m src.main
  python -m src.main --csv data/test_ips.csv
  python -m src.main --ip 8.8.8.8
  python -m src.main --ip 185.220.101.45 --attempts 200
"""

import argparse
import os
import sys

from src.detector.ip_analyzer import analyze_from_csv, analyze_single_ip
from src.report.reporter import print_result, print_summary
from src.utils.logger import setup_logger
from src.utils.validator import validate_ip

logger = setup_logger("main")

_DEFAULT_CSV = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "test_ips.csv"
)

_BANNER = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║        SIEM SIMULATOR — Detector de IPs & Ameaças        ║
  ║              Projeto de Estudo — Cibersegurança          ║
  ╚══════════════════════════════════════════════════════════╝
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem-simulator",
        description="Detector de IPs com geolocalização e análise de ameaças.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python -m src.main\n"
            "  python -m src.main --csv data/test_ips.csv\n"
            "  python -m src.main --ip 185.220.101.45 --attempts 300\n"
        ),
    )
    parser.add_argument(
        "--ip",
        metavar="ENDEREÇO",
        type=str,
        help="Analisar um único endereço IP (IPv4 ou IPv6)",
    )
    parser.add_argument(
        "--attempts",
        metavar="N",
        type=int,
        default=1,
        help="Número de tentativas para o --ip informado (padrão: 1)",
    )
    parser.add_argument(
        "--csv",
        metavar="ARQUIVO",
        type=str,
        default=_DEFAULT_CSV,
        help=f"Caminho para o CSV de eventos (padrão: {_DEFAULT_CSV})",
    )
    return parser


def _run_single(ip: str, attempts: int) -> None:
    """Analisa um único IP e exibe o resultado."""
    if not validate_ip(ip):
        print(f"\n  ❌  IP inválido: '{ip}'\n")
        sys.exit(1)

    print(f"\n  🔍  Analisando IP: {ip}  (tentativas: {attempts})\n")
    result = analyze_single_ip(ip, attempts)
    if result:
        print_result(result)
    else:
        print("  Não foi possível concluir a análise.")
        sys.exit(1)


def _run_csv(filepath: str) -> None:
    """Analisa todos os eventos do CSV e exibe resultados + resumo."""
    abs_path = os.path.abspath(filepath)
    print(f"\n  📂  Arquivo CSV : {abs_path}")
    print(f"  🔍  Iniciando análise...\n")

    results = analyze_from_csv(filepath)

    if not results:
        print("  ⚠  Nenhum evento válido encontrado no arquivo CSV.\n")
        sys.exit(1)

    for result in results:
        print_result(result)

    print_summary(results)


def main() -> None:
    print(_BANNER)
    parser = _build_parser()
    args   = parser.parse_args()

    if args.ip:
        _run_single(args.ip, args.attempts)
    else:
        _run_csv(args.csv)


if __name__ == "__main__":
    main()
