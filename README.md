# 🛡️ IP & Threat Detector

> A Python study project focused on **cybersecurity**, simulating a core component
> of a SIEM system: malicious IP detection with geolocation,
> threat scoring, and attack type classification.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Project Structure](#-project-structure)
- [Architecture & Pipeline](#-architecture--pipeline)
- [Installation](#-installation)
- [Usage](#-usage)
- [CSV Format](#-csv-format)
- [Scoring System](#-scoring-system)
- [Detected Attack Types](#-detected-attack-types)
- [Security & Integrity](#-security--integrity)
- [Tests](#-tests)
- [Technologies](#-technologies)
- [Legal Notice](#-legal-notice)

---

## 🔍 Overview

**SIEM Simulator** is a command-line application that replicates the logic of an
intrusion detection component found in real SIEM systems (such as Splunk,
Elastic Security, and IBM QRadar).

Given a CSV file with access events or a single IP address, the system:

1. **Geolocates** the IP (country, city, ISP, coordinates)
2. **Classifies** the most likely attack type
3. **Scores** the threat level from 0 to 100
4. **Detects** whether a successful intrusion occurred
5. **Recommends** specific mitigation actions

---

## ✅ Features

| Feature | Description |
|---|---|
| 🌍 Geolocation | Country, region, city, ISP, organization, and coordinates via ip-api.com |
| 📊 Threat Scoring | Score 0–100 based on multiple weighted factors |
| 🔴 Threat Levels | LOW / MEDIUM / HIGH / CRITICAL with visual bar |
| 🕵️ Attack Classification | 8 detected types via cascading rules |
| 🚨 Intrusion Detection | Explicit flag if the attacker gained access |
| 🗂️ Batch Analysis | Reads CSV files with multiple events |
| 📝 Rotating Logs | Daily log file with 5 MB rotation |
| 🧪 Unit Tests | 25+ cases covering all modules |
| 🔒 Input Validation | All external input is validated and sanitized |

---

## 📁 Project Structure
siem-simulator/
│
├── src/                          # Main package
│   ├── init.py
│   ├── main.py                   # Entry point (CLI)
│   │
│   ├── models/
│   │   ├── init.py
│   │   └── event.py              # Dataclasses: AccessEvent, AnalysisResult, GeoInfo
│   │                             # Enums: ThreatLevel, AttackType
│   │
│   ├── detector/
│   │   ├── init.py
│   │   ├── geo_locator.py        # Geolocation via ip-api.com
│   │   ├── attack_classifier.py  # Attack type classification
│   │   ├── threat_scorer.py      # Scoring engine + recommendations
│   │   └── ip_analyzer.py        # Orchestrator: CSV parser + pipeline
│   │
│   ├── report/
│   │   ├── init.py
│   │   └── reporter.py           # Colored terminal display
│   │
│   └── utils/
│       ├── init.py
│       ├── logger.py             # Logger with file rotation
│       └── validator.py          # Input validation and sanitization
│
├── data/
│   ├── test_ips.csv              # 14 test events (all attack types)
│   └── logs/                     # Runtime-generated logs (git-ignored)
│
├── tests/
│   ├── init.py
│   └── test_analyzer.py          # Unit tests (25+ cases)
│
├── .env.example                  # Environment variables template
├── .gitignore
├── requirements.txt
└── README.md

---

## 🏗️ Architecture & Pipeline

CSV / single IP
│
▼
┌─────────────────┐
│   ip_analyzer   │  ← CSV parser with per-row validation
│  (orchestrator) │
└────────┬────────┘
│  AccessEvent (validated)
▼
┌─────────────────┐
│  geo_locator    │  ← ip-api.com (GET with timeout + fallback for private IPs)
└────────┬────────┘
│  GeoInfo
▼
┌──────────────────────┐
│  attack_classifier   │  ← Cascading rules (payload → DoS → PortScan → ...)
└────────┬─────────────┘
│  AttackType
▼
┌──────────────────────┐
│   threat_scorer      │  ← Weighted score + ThreatLevel + recommendations
└────────┬─────────────┘
│  AnalysisResult
▼
┌──────────────────────┐
│     reporter         │  ← Colored terminal card + summary panel
└──────────────────────┘

---

## ⚙️ Installation

**Requirements:** Python 3.9+
```bash
# 1. Clone the repository
git clone https://github.com/your-username/siem-simulator.git
cd siem-simulator

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy the configuration file
cp .env.example .env
```

---

## 🚀 Usage

### Analyze the default test CSV
```bash
python -m src.main
```

### Analyze a custom CSV
```bash
python -m src.main --csv path/to/your/file.csv
```

### Analyze a single IP
```bash
python -m src.main --ip 185.220.101.45
```

### Single IP with attempt count
```bash
python -m src.main --ip 89.248.167.131 --attempts 300
```

### Help
```bash
python -m src.main --help
```

### Sample output
════════════════════════════════════════════════════════════════════
⛔  SIEM SIMULATOR — IP ANALYSIS
────────────────────────────────────────────────────────────────────
Analyzed IP         : 185.220.101.45
Date / Time         : 06/10/2024  08:10:00
Country             : Germany
Region / City       : Bavaria, Nuremberg
ISP                 : Chaos Computer Club e.V.
Organization        : Tor exit node
Coordinates         : 49.4478, 11.0683
Time Zone           : Europe/Berlin
────────────────────────────────────────────────────────────────────
Score               :  97/100  [████████████████████]
Threat Level        : ⛔ CRITICAL
Attack Type         : Brute Force
System Intrusion    : Not detected
════════════════════════════════════════════════════════════════════

---

## 📄 CSV Format

The CSV file must contain the following columns (header required):

| Column | Type | Required | Description |
|---|---|---|---|
| `ip` | string | ✅ | IPv4 or IPv6 address |
| `timestamp` | datetime | ✅ | Format: `YYYY-MM-DD HH:MM:SS` |
| `attempts` | integer | ✅ | Number of consecutive attempts |
| `ports_tried` | string | ❌ | Pipe-separated ports (e.g. `22\|80\|443`) |
| `usernames_tried` | string | ❌ | Pipe-separated usernames (e.g. `root\|admin`) |
| `success` | bool | ❌ | `true`/`false` — whether the attacker gained access |
| `user_agent` | string | ❌ | Request User-Agent header |
| `payload_sample` | string | ❌ | Payload sample (for SQLi detection) |

**Example row:**
```csv
185.220.101.45,2024-06-10 08:10:00,280,22,root|admin|ubuntu,false,python-requests/2.31.0,
```

---

## 📊 Scoring System

The threat score (0–100) is calculated by summing weighted factors:

| Factor | Max Points | Condition |
|---|---|---|
| Attempt volume | 40 | Scaled: 3→5→10→20→30→40 |
| Attack type | 40 | Based on classified AttackType |
| IP in blacklist | 25 | IP found in known threat list |
| Successful intrusion | 20 | `success = true` field |
| Malicious payload | 15 | `payload_sample` field is set |
| Suspicious ISP/Org | 10 | Keywords: vpn, tor, proxy, hosting... |
| Port variety | 10 | >5 ports: +5pts / >20 ports: +10pts |
| Username variety | 10 | >5 usernames: +5pts / >15 usernames: +10pts |
| Private IP (discount) | −10 | Reduces score for internal network events |

**Threat levels by range:**

| Score | Level | Icon |
|---|---|---|
| 0 – 29 | LOW | 🟢 |
| 30 – 54 | MEDIUM | 🟡 |
| 55 – 79 | HIGH | 🔴 |
| 80 – 100 | CRITICAL | ⛔ |

---

## 🕵️ Detected Attack Types

| Type | Detection Condition | Priority |
|---|---|---|
| **SQL Injection** | Payload with known SQLi patterns | 1st (highest) |
| **DoS Attempt** | ≥ 500 attempts | 2nd |
| **Port Scanning** | ≥ 10 distinct ports tested | 3rd |
| **Credential Stuffing** | ≥ 10 distinct usernames + ≥ 20 attempts | 4th |
| **Dictionary Attack** | ≥ 50 attempts + ≤ 3 distinct usernames | 5th |
| **Brute Force** | ≥ 10 attempts + ≤ 2 usernames | 6th |
| **Suspicious Behavior** | ≥ 5 attempts with no clear pattern | 7th |
| **Normal Access** | No anomalous pattern detected | 8th (default) |

---

## 🔒 Security & Integrity

This project was built following **Secure Coding** practices from the ground up:

### Input Validation ("Never Trust Input")
- Every IP is validated with `ipaddress.ip_address()` before any use
- Ports outside the `0–65535` range are silently discarded
- Strings go through sanitization (control character removal + size limit)
- Usernames are normalized to POSIX standard (only `[a-zA-Z0-9._\-@]`)

### Injection Protection
- No string concatenation in external queries
- User payloads are never interpolated into system commands
- SQLi patterns are detected and flagged, never executed

### Secure External Communication
- Private/reserved IPs are **not sent** to external APIs
- Fixed timeout on all HTTP requests (prevents thread blocking)
- Network failures handled with graceful degradation (no crash)

### Secure Logging
- File-based logs with automatic rotation (max 5 MB, 5 backups)
- No sensitive data (passwords, full payloads) written to logs
- Console displays only `WARNING+` to prevent data leakage

### Configuration
- Credentials stored in environment variables (`.env`), never hardcoded
- `.env` and `data/logs/` listed in `.gitignore`

---

## 🧪 Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Or with native unittest
python -m unittest discover tests/ -v
```

**Test coverage:**

| Module | Tested Scenarios |
|---|---|
| `validator.py` | Valid, invalid, private IPs; ports; sanitization |
| `attack_classifier.py` | All 8 attack types + edge cases |
| `threat_scorer.py` | Score for each factor; cap at 100; ThreatLevel thresholds |
| `ip_analyzer.py` | Valid CSV, invalid IP, ports, bool variants, missing file |

---

## 🛠️ Technologies

| Library | Version | Usage |
|---|---|---|
| `requests` | ≥ 2.31 | HTTP requests to ip-api.com |
| `colorama` | ≥ 0.4.6 | Portable ANSI colors in the terminal |
| `pytest` | ≥ 7.4 | Testing framework (optional) |
| `ruff` | ≥ 0.4 | Static linter (dev) |
| `mypy` | ≥ 1.8 | Type checking (dev) |

Standard library modules used: `ipaddress`, `csv`, `dataclasses`,
`datetime`, `enum`, `logging`, `argparse`, `os`, `re`, `typing`.

---

## ⚠️ Legal Notice

This project is **for educational purposes only**.

- The IPs in `test_ips.csv` are public addresses documented
  in security reports, Tor exit node lists, and known scanners.
- No real scanner, exploit, or attack tool is included.
- Using the techniques studied here against systems without explicit
  authorization is **illegal** in virtually all jurisdictions.
- The author is not responsible for any misuse of this material.

---

> Developed as study material for a **Cybersecurity** course.
> Inspired by the architecture of SIEMs such as Elastic Security, Splunk, and IBM QRadar.
