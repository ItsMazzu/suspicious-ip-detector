# 🛡️ SIEM Simulator — Detector de IPs & Ameaças

> Projeto de estudo em Python focado em **cibersegurança**, simulando um componente
> central de um sistema SIEM: detecção de IPs maliciosos com geolocalização,
> pontuação de ameaças e classificação de tipos de ataque.

---

## 📋 Índice

- [Visão Geral](#-visão-geral)
- [Funcionalidades](#-funcionalidades)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Arquitetura & Pipeline](#-arquitetura--pipeline)
- [Instalação](#-instalação)
- [Como Usar](#-como-usar)
- [Formato do CSV](#-formato-do-csv)
- [Sistema de Pontuação](#-sistema-de-pontuação)
- [Tipos de Ataque Detectados](#-tipos-de-ataque-detectados)
- [Segurança & Integridade](#-segurança--integridade)
- [Testes](#-testes)
- [Tecnologias](#-tecnologias)
- [Aviso Legal](#-aviso-legal)

---

## 🔍 Visão Geral

O **SIEM Simulator** é uma aplicação de linha de comando que replica a lógica de um
componente de detecção de intrusões presente em sistemas SIEM reais (como Splunk,
Elastic Security e IBM QRadar).

Dado um arquivo CSV com eventos de acesso ou um IP avulso, o sistema:

1. **Geolocaliza** o IP (país, cidade, ISP, coordenadas)
2. **Classifica** o tipo de ataque mais provável
3. **Pontua** o nível de ameaça de 0 a 100
4. **Detecta** se houve intrusão bem-sucedida
5. **Recomenda** ações de mitigação específicas

---

## ✅ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 🌍 Geolocalização | País, região, cidade, ISP, organização e coordenadas via ip-api.com |
| 📊 Pontuação de Ameaça | Score 0–100 por múltiplos fatores ponderados |
| 🔴 Níveis de Ameaça | LOW / MEDIUM / HIGH / CRITICAL com barra visual |
| 🕵️ Classificação de Ataque | 8 tipos detectados com cascata de regras |
| 🚨 Detecção de Intrusão | Flag explícita se o atacante obteve acesso |
| 🗂️ Análise em Lote | Lê arquivos CSV com múltiplos eventos |
| 📝 Logs Rotativos | Arquivo de log diário com rotação de 5 MB |
| 🧪 Testes Unitários | 25+ casos cobrindo todos os módulos |
| 🔒 Validação de Entrada | Toda entrada externa é validada e sanitizada |

---

## 📁 Estrutura do Projeto

```
siem-simulator/
│
├── src/                          # Pacote principal
│   ├── __init__.py
│   ├── main.py                   # Ponto de entrada (CLI)
│   │
│   ├── models/
│   │   ├── __init__.py
│   │   └── event.py              # Dataclasses: AccessEvent, AnalysisResult, GeoInfo
│   │                             # Enums: ThreatLevel, AttackType
│   │
│   ├── detector/
│   │   ├── __init__.py
│   │   ├── geo_locator.py        # Geolocalização via ip-api.com
│   │   ├── attack_classifier.py  # Classificação do tipo de ataque
│   │   ├── threat_scorer.py      # Motor de pontuação + recomendações
│   │   └── ip_analyzer.py        # Orquestrador: parser CSV + pipeline
│   │
│   ├── report/
│   │   ├── __init__.py
│   │   └── reporter.py           # Exibição colorida no terminal
│   │
│   └── utils/
│       ├── __init__.py
│       ├── logger.py             # Logger com rotação de arquivos
│       └── validator.py          # Validação e sanitização de entradas
│
├── data/
│   ├── test_ips.csv              # 14 eventos de teste (todos os tipos de ataque)
│   └── logs/                     # Logs gerados em runtime (ignorado pelo git)
│
├── tests/
│   ├── __init__.py
│   └── test_analyzer.py          # Testes unitários (25+ casos)
│
├── .env.example                  # Template de variáveis de ambiente
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🏗️ Arquitetura & Pipeline

```
CSV / IP avulso
      │
      ▼
┌─────────────────┐
│   ip_analyzer   │  ← Parser CSV com validação linha a linha
│  (orquestrador) │
└────────┬────────┘
         │  AccessEvent (validado)
         ▼
┌─────────────────┐
│  geo_locator    │  ← ip-api.com (GET com timeout + fallback para privados)
└────────┬────────┘
         │  GeoInfo
         ▼
┌──────────────────────┐
│  attack_classifier   │  ← Cascata de regras (payload → DoS → PortScan → ...)
└────────┬─────────────┘
         │  AttackType
         ▼
┌──────────────────────┐
│   threat_scorer      │  ← Score ponderado + ThreatLevel + recomendações
└────────┬─────────────┘
         │  AnalysisResult
         ▼
┌──────────────────────┐
│     reporter         │  ← Card colorido no terminal + painel de resumo
└──────────────────────┘
```

---

## ⚙️ Instalação

**Pré-requisitos:** Python 3.9+

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/siem-simulator.git
cd siem-simulator

# 2. Crie e ative um ambiente virtual
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Copie o arquivo de configuração
cp .env.example .env
```

---

## 🚀 Como Usar

### Analisar o CSV de teste (padrão)

```bash
python -m src.main
```

### Analisar um CSV personalizado

```bash
python -m src.main --csv caminho/para/seu/arquivo.csv
```

### Analisar um único IP

```bash
python -m src.main --ip 185.220.101.45
```

### IP único com número de tentativas

```bash
python -m src.main --ip 89.248.167.131 --attempts 300
```

### Ajuda

```bash
python -m src.main --help
```

### Exemplo de saída

```
  ════════════════════════════════════════════════════════════════════
  ⛔  SIEM SIMULATOR — ANÁLISE DE IP
  ────────────────────────────────────────────────────────────────────
  IP Analisado        : 185.220.101.45
  Data / Hora         : 10/06/2024  08:10:00
  País                : Germany
  Região / Cidade     : Bavaria, Nuremberg
  ISP                 : Chaos Computer Club e.V.
  Organização         : Tor exit node
  Coordenadas         : 49.4478, 11.0683
  Fuso Horário        : Europe/Berlin
  ────────────────────────────────────────────────────────────────────
  Pontuação           :  97/100  [████████████████████]
  Nível de Ameaça     : ⛔ CRITICAL
  Tipo de Ataque      : Força Bruta
  Intrusão no Sistema : Não detectada
  ════════════════════════════════════════════════════════════════════
```

---

## 📄 Formato do CSV

O arquivo CSV deve ter as seguintes colunas (header obrigatório):

| Coluna | Tipo | Obrigatório | Descrição |
|---|---|---|---|
| `ip` | string | ✅ | Endereço IPv4 ou IPv6 |
| `timestamp` | datetime | ✅ | Formato: `YYYY-MM-DD HH:MM:SS` |
| `attempts` | inteiro | ✅ | Número de tentativas consecutivas |
| `ports_tried` | string | ❌ | Portas separadas por `\|` (ex: `22\|80\|443`) |
| `usernames_tried` | string | ❌ | Usuários separados por `\|` (ex: `root\|admin`) |
| `success` | bool | ❌ | `true`/`false` — se o atacante obteve acesso |
| `user_agent` | string | ❌ | Cabeçalho User-Agent da requisição |
| `payload_sample` | string | ❌ | Amostra do payload (para detecção de SQLi) |

**Exemplo de linha:**
```csv
185.220.101.45,2024-06-10 08:10:00,280,22,root|admin|ubuntu,false,python-requests/2.31.0,
```

---

## 📊 Sistema de Pontuação

O score de ameaça (0–100) é calculado somando fatores ponderados:

| Fator | Pontos Máx. | Condição |
|---|---|---|
| Volume de tentativas | 40 | Escalonado: 3→5→10→20→30→40 |
| Tipo de ataque | 40 | Baseado no AttackType classificado |
| IP em blacklist | 25 | IP presente na lista de ameaças conhecidas |
| Intrusão bem-sucedida | 20 | Campo `success = true` |
| Payload malicioso | 15 | Campo `payload_sample` preenchido |
| ISP/Org suspeito | 10 | Palavras-chave: vpn, tor, proxy, hosting... |
| Variedade de portas | 10 | >5 portas: +5pts / >20 portas: +10pts |
| Variedade de usuários | 10 | >5 usuários: +5pts / >15 usuários: +10pts |
| IP privado (desconto) | −10 | Reduz score para eventos de rede interna |

**Níveis de ameaça por faixa:**

| Score | Nível | Ícone |
|---|---|---|
| 0 – 29 | LOW | 🟢 |
| 30 – 54 | MEDIUM | 🟡 |
| 55 – 79 | HIGH | 🔴 |
| 80 – 100 | CRITICAL | ⛔ |

---

## 🕵️ Tipos de Ataque Detectados

| Tipo | Condição de Detecção | Prioridade |
|---|---|---|
| **SQL Injection** | Payload com padrões SQLi conhecidos | 1ª (mais alta) |
| **Tentativa de DoS** | ≥ 500 tentativas | 2ª |
| **Varredura de Portas** | ≥ 10 portas distintas testadas | 3ª |
| **Credential Stuffing** | ≥ 10 usuários distintos + ≥ 20 tentativas | 4ª |
| **Ataque de Dicionário** | ≥ 50 tentativas + ≤ 3 usuários distintos | 5ª |
| **Força Bruta** | ≥ 10 tentativas + ≤ 2 usuários | 6ª |
| **Comportamento Suspeito** | ≥ 5 tentativas sem padrão claro | 7ª |
| **Acesso Normal** | Sem padrão anômalo | 8ª (padrão) |

---

## 🔒 Segurança & Integridade

O projeto foi desenvolvido seguindo práticas de **Secure Coding** desde a concepção:

### Validação de Entrada ("Never Trust Input")
- Todo IP é validado com `ipaddress.ip_address()` antes de qualquer uso
- Portas fora do range `0–65535` são descartadas silenciosamente
- Strings passam por sanitização (remoção de caracteres de controle + limite de tamanho)
- Usernames são normalizados para o padrão POSIX (apenas `[a-zA-Z0-9._\-@]`)

### Proteção contra Injeção
- Nenhuma concatenação de strings em queries externas
- Payloads de usuário nunca são interpolados em comandos do sistema
- Padrões de SQLi detectados e sinalizados, nunca executados

### Comunicação Externa Segura
- IPs privados/reservados **não são enviados** para APIs externas
- Timeout fixo em todas as requisições HTTP (evita bloqueio de thread)
- Falhas de rede tratadas com graceful degradation (sem crash)

### Logs Seguros
- Logs em arquivo com rotação automática (máx. 5 MB, 5 backups)
- Nenhum dado sensível (senhas, payloads completos) gravado em log
- Console mostra apenas `WARNING+` para evitar vazamento de dados

### Configuração
- Credenciais em variáveis de ambiente (`.env`), nunca hardcoded
- `.env` e `data/logs/` no `.gitignore`

---

## 🧪 Testes

```bash
# Executar todos os testes
python -m pytest tests/ -v

# Ou com unittest nativo
python -m unittest discover tests/ -v
```

**Cobertura dos testes:**

| Módulo | Cenários testados |
|---|---|
| `validator.py` | IPs válidos, inválidos, privados; portas; sanitização |
| `attack_classifier.py` | Todos os 8 tipos de ataque + casos de borda |
| `threat_scorer.py` | Score para cada fator; cap em 100; limiares de ThreatLevel |
| `ip_analyzer.py` | CSV válido, IP inválido, portas, bool variants, arquivo inexistente |

---

## 🛠️ Tecnologias

| Biblioteca | Versão | Uso |
|---|---|---|
| `requests` | ≥ 2.31 | Requisições HTTP para ip-api.com |
| `colorama` | ≥ 0.4.6 | Cores ANSI portáveis no terminal |
| `pytest` | ≥ 7.4 | Framework de testes (opcional) |
| `ruff` | ≥ 0.4 | Linter estático (dev) |
| `mypy` | ≥ 1.8 | Type checking (dev) |

Bibliotecas padrão utilizadas: `ipaddress`, `csv`, `dataclasses`,
`datetime`, `enum`, `logging`, `argparse`, `os`, `re`, `typing`.

---

## ⚠️ Aviso Legal

Este projeto é **exclusivamente para fins educacionais**.

- Os IPs presentes em `test_ips.csv` são endereços públicos documentados
  em relatórios de segurança, listas de exit nodes Tor e scanners conhecidos.
- Nenhum scanner, exploit ou ferramenta de ataque real está incluído.
- O uso das técnicas aqui estudadas contra sistemas sem autorização explícita
  é **ilegal** em praticamente todas as jurisdições (Brasil: Lei 12.737/2012 —
  Lei Carolina Dieckmann; Lei 14.155/2021).
- O autor não se responsabiliza pelo uso indevido deste material.

---

> Desenvolvido como material de estudo para a disciplina de **Cibersegurança**.
> Inspirado na arquitetura de SIEMs como Elastic Security, Splunk e IBM QRadar.
