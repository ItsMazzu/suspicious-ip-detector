"""
SIEM Simulator — Sistema de análise de segurança de IPs.

Detecta padrões de ataque (brute force, SQL injection, varredura de portas, etc.)
e calcula pontuação de ameaça com geolocalização.

Módulos principais:
  - detector: Pipeline de análise (geo, classificação, pontuação)
  - models: Estruturas de dados (eventos, resultados, enums)
  - report: Apresentação dos resultados
  - utils: Validação, sanitização, logging

Uso:
  from src.detector import analyze_single_ip, analyze_from_csv
  from src.models import AccessEvent, ThreatLevel
  from src.report import print_result, print_summary
  from src.utils import validate_ip, setup_logger
"""

from src.detector import (
    analyze_from_csv,
    analyze_single_ip,
    calculate_threat_score,
    classify_attack,
    get_geo_info,
    get_recommendations,
    get_threat_level,
)
from src.models import (
    AccessEvent,
    AnalysisResult,
    AttackType,
    GeoInfo,
    ThreatLevel,
)
from src.report import print_result, print_summary
from src.utils import (
    is_loopback,
    is_private_ip,
    sanitize_string,
    sanitize_username,
    setup_logger,
    validate_ip,
    validate_port,
)

__version__ = "1.0.0"

__all__ = [
    # Detectors
    "get_geo_info",
    "classify_attack",
    "calculate_threat_score",
    "get_threat_level",
    "get_recommendations",
    "analyze_single_ip",
    "analyze_from_csv",
    # Models
    "ThreatLevel",
    "AttackType",
    "GeoInfo",
    "AccessEvent",
    "AnalysisResult",
    # Report
    "print_result",
    "print_summary",
    # Utils
    "validate_ip",
    "is_private_ip",
    "is_loopback",
    "validate_port",
    "sanitize_string",
    "sanitize_username",
    "setup_logger",
]
