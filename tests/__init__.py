"""
tests — Suite de testes unitários do SIEM Simulator.

Cobertura:
  - utils/validator.py: Validação de IP, porta, sanitização
  - detector/attack_classifier.py: Classificação de tipos de ataque
  - detector/threat_scorer.py: Pontuação e níveis de ameaça
  - detector/ip_analyzer.py: Parser CSV e pipeline completo

Helpers:
  - make_event: Factory para criar AccessEvent de teste

Executar testes:
  python -m pytest tests/ -v
  python -m pytest tests/ --cov=src
  python -m unittest discover tests/ -v
"""

import os
import sys
from datetime import datetime

# Garante que o pacote src está no path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.models.event import AccessEvent


def make_event(
    ip: str = "1.2.3.4",
    attempts: int = 1,
    ports: list = None,
    users: list = None,
    success: bool = False,
    payload: str = "",
) -> AccessEvent:
    """
    Factory para criar um AccessEvent de teste.

    Parâmetros
    ----------
    ip : endereço IP (padrão: 1.2.3.4)
    attempts : número de tentativas
    ports : lista de portas testadas
    users : lista de usernames testados
    success : se o ataque foi bem-sucedido
    payload : amostra de payload (para detectar injeções)

    Retorna
    -------
    AccessEvent com timestamp atual
    """
    return AccessEvent(
        ip=ip,
        timestamp=datetime.now(),
        attempts=attempts,
        ports_tried=ports or [],
        usernames_tried=users or [],
        success=success,
        payload_sample=payload,
    )


__all__ = [
    "make_event",
]
