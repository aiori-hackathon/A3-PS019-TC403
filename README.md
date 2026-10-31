# PrivLens (PS-019)
**PII Discovery & Privacy Evidence Inventory Engine**

**Category:** Cyber Security / Privacy Engineering
**Team Name:** Synapse
**Live Project:** [https://privylens.onrender.com/](https://privylens.onrender.com/)
**Deliverable PDF:** [Proposed-structure-hackathon.pdf](deliverables.pdf)
**Pseudocode Snippet:** [docs/PSEUDOCODE_SNIPPET.md](docs/PSEUDOCODE_SNIPPET.md)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Framework](https://img.shields.io/badge/Framework-Flask-black) ![Tests](https://img.shields.io/badge/Tests-12%20unit%20tests-brightgreen)

---

## 1. Executive Summary & Challenge

PrivLens is a cybersecurity and privacy engineering tool that scans structured datasets (CSV & SQL), discovers Personally Identifiable Information (PII) across 5 predefined data classes, links candidate fields to declared business purposes and retention schedules, produces an actionable evidence inventory, and rigorously reports per-class Precision and Recall.

**Key Capabilities**

- **Multi-Source Support:** Inspects synthetic CSV spreadsheets, structured SQL databases (SQLite), and user-uploaded custom files.
- **Upload & Scan (CSV & SQL DB):** Drag-and-drop or select external `.csv` spreadsheets and `.db` / `.sqlite` databases directly from the Web UI or CLI to profile candidate personal data.
- **5 Official PS-019 Personal Data Classes:**
  - **PID:** Personal identity (name, date of birth, gender, age).
  - **CNT:** Contact information (email address, phone number).
  - **GID:** Government identifiers (Aadhaar, PAN, passport, voter ID, driving licence numbers).
  - **FIN:** Financial information (bank account number, IFSC, card number, UPI ID).
  - **LOC:** Location / address (postal address, PIN code, geo-coordinates).
  - Fields matching none of these are classified as *"not personal data"*.
- **Configurable Evidence Checklist:** Rules defined in declarative YAML (`config/detection_rules.yaml`) combining header heuristics, regex patterns, checksum algorithms, and sample match ratios.
- **RoPA Purpose & Retention Mapping:** Maps discovered fields against declared governance metadata (`config/governance_registry.yaml`).
- **Evidence Gap Detection:** Flags unregistered shadow data, missing business purposes, and missing retention policies with human-actionable recommendations.
- **Benchmark Evaluation:** Evaluates discovery performance against a ground-truth dataset (`datasets/ground_truth.json`) with per-class Precision, Recall, and F1-Score.
- **Interactive Web Dashboard:** Single-page dashboard with Chart.js analytics, filterable inventory table, evidence inspector modal, real-time rule sandbox, and Dark / Light mode toggle.

---

## 2. Key Requirements & Boundary Compliance

| Requirement | Implementation in PrivLens | Verification Status |
|---|---|---|
| Structured Data Sources | CSV spreadsheets and SQLite databases (`.db`, `.sqlite`, `.sqlite3`), synthetic and user-uploaded | Verified |
| 5 Personal Data Classes | PID, CNT, GID, FIN, LOC; everything else labelled "not personal data" | Verified (per-class P/R/F1 reported) |
| Configurable Evidence Checklist | Declarative YAML rules: header heuristics, regex, checksum validators (e.g. Luhn), sample match ratios | Configured & Tested |
| Purpose & Retention Mapping | Governance metadata linker driven by `governance_registry.yaml` | Verified |
| Evidence Gap Detection | Flags shadow data, missing purposes, missing retention schedules, with recommendations | Verified |
| Quantified Evaluation Metrics | Per-class Precision, Recall, F1-Score, confusion counts (TP / FP / FN) | Fully quantified |
| Reporting & Export | PDF, Markdown and JSON reports from the CLI and the dashboard | Verified |
| Automated Testing | 12 unit tests across validators, scanners, governance mapping, uploads and metrics | Passing |
| No Legal Determinations | Evidence compilation only; no lawful-basis decisions, no cross-border transfer inference | Boundary respected |

---

## 3. Architecture & Discovery Pipeline

```
[Data Source: CSV file / SQLite database / Web or CLI upload]
            │
            ▼
[Scanner Engine]
   - csv_scanner: CSV file profiler
   - sql_scanner: SQLite schema & tuple profiler
            │
            ▼
[Rule Matcher]  (config/detection_rules.yaml)
   - Header heuristics
   - Regex patterns
   - Checksum algorithms (Luhn, IPv4 validator)
   - Sample match ratios
            │
            ▼
[Classification into 5 Data Classes]
   - PID · CNT · GID · FIN · LOC · (not personal data)
            │
            ▼
[Governance Mapper]  (config/governance_registry.yaml)
   - Links fields to declared purposes, retention schedules, data owners
   - Detects evidence gaps: shadow data, missing purpose, missing retention
            │
            ▼
[Benchmark Evaluator]  (datasets/ground_truth.json)
   - Per-class Precision, Recall, F1-Score
            │
            ▼
[Reporters & Web Dashboard]
   - JSON / Markdown / PDF reports
   - Flask REST API + interactive dashboard
```

---

## 4. Experimental Evaluation & Benchmark Results

Evaluate the scanner's detection accuracy against the manually labelled ground-truth benchmark:

```bash
python cli.py evaluate --export
```

**Per-Class Precision & Recall Evaluation Benchmark**

| Code | Data Class Name | TP | FP | FN | Precision | Recall | F1-Score |
|---|---|---|---|---|---|---|---|
| PID | Personal identity | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| CNT | Contact information | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| GID | Government identifiers | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| FIN | Financial information | 8 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| LOC | Location / address | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |

**Mathematical Summary Metrics:**

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1-Score = 2 × Precision × Recall / (Precision + Recall)
- **Overall Metrics:** Macro Precision: 100.0% | Macro Recall: 100.0% | Macro F1: 100.0%
- **Evaluated:** 44 fields (29 personal data fields + 15 not personal data fields)

---

## 5. Repository Structure

```
airio sample/
├── config/
│   ├── detection_rules.yaml      # Configurable detection rules & thresholds for 5 classes
│   └── governance_registry.yaml   # Declared purposes, retention schedules, data owners
├── datasets/
│   ├── synthetic/                 # Synthetic CSV files & SQLite database
│   │   ├── customer_signups.csv
│   │   ├── support_tickets_export.csv
│   │   ├── marketing_leads_unindexed.csv
│   │   └── enterprise_data.db
│   ├── ground_truth.json          # Manually labelled benchmark for evaluation
│   └── generate_datasets.py       # Deterministic synthetic data generator script
├── docs/
│   └── PSEUDOCODE_SNIPPET.md      # Pseudocode snippet & mentor briefing
├── privlens/
│   ├── models.py                  # Dataclasses: DiscoveredField, InventoryItem, Metric, etc.
│   ├── scanner/
│   │   ├── engine.py              # Scanner orchestrator
│   │   ├── csv_scanner.py         # CSV file profiler
│   │   ├── sql_scanner.py         # SQLite schema & tuple profiler
│   │   └── rule_matcher.py        # Configurable regex, Luhn checksum, IPv4 validator
│   ├── governance/
│   │   └── mapper.py              # Governance metadata linker & gap analyzer
│   ├── evaluation/
│   │   └── metrics.py             # Precision, Recall, F1, confusion matrix calculator
│   └── reporters/
│       ├── json_reporter.py       # JSON export
│       ├── markdown_reporter.py   # Markdown technical report generator
│       └── pdf_reporter.py        # PDF audit report generator
├── web/
│   ├── app.py                     # Flask REST API server
│   ├── static/
│   │   ├── js/app.js              # Single-page application logic & Chart.js controllers
│   │   └── css/custom.css         # Styling enhancements
│   └── templates/
│       └── index.html             # High-quality Tailwind UI dashboard
├── cli.py                         # Rich command line interface
├── tests/
│   ├── test_rules.py              # Rule matcher & validator unit tests
│   ├── test_scanners.py           # CSV and SQL scanner unit tests
│   ├── test_governance.py         # Governance mapping & gap unit tests
│   ├── test_evaluation.py         # Precision/Recall benchmark unit tests
│   └── test_upload.py             # File upload unit tests
├── reports/
│   ├── inventory_report.md        # Generated technical evidence report
│   └── inventory_report.json      # Generated structured technical inventory
├── TECHNICAL_REPORT.md            # In-depth architectural & methodology report
├── requirements.txt
└── README.md
```

---

## 6. How to Run the Demonstration

### Option A: Live Web Dashboard (no install)

Open **[https://privylens.onrender.com/](https://privylens.onrender.com/)** in any modern browser.

> The app is hosted on a free tier, so the first load after a period of inactivity can take 30-50 seconds to wake up.

### Option B: Run the Web Dashboard Locally

**Prerequisites:** Python 3.10+ and a modern web browser (Chrome, Edge, Firefox, Safari).

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate datasets & ground truth (create or refresh synthetic data)
python cli.py generate-data

# 3. Launch the dashboard
python cli.py serve --port 5000
```

Open `http://127.0.0.1:5000` in your browser.

*(Note: dependencies are flask, flask-cors, pandas, pyyaml, rich, pytest)*

**Dashboard Features:**

- **Overview:** Executive summary KPI cards, class distribution doughnut chart, governance status pie chart.
- **Upload & Scan:** Click the "Upload & Scan" button in the navbar to drag-and-drop any external CSV spreadsheet (`.csv`) or SQLite database (`.db`, `.sqlite`, `.sqlite3`). Choose whether to append to or replace the current inventory.
- **Data Inventory:** Interactive searchable and filterable table with one-click "Inspect" button showing triggered rules, match ratios, and masked sample values.
- **Evidence Gaps:** Action checklist highlighting shadow PII, missing declared purposes, and missing retention limits.
- **Benchmark Evaluation:** Interactive Chart.js bar chart comparing Precision, Recall, and F1 across all classes.
- **Rule Sandbox:** Live interactive playground to test custom column headers and sample cell values against detection rules in real-time.
- **Report Export:** One-click download of PDF Audit Reports, Markdown Reports, and JSON technical inventories.
- **Dark & Light Mode:** Toggle button in the navbar switching between Dark mode and Light mode with browser localStorage persistence.

### Option C: Run via CLI

**Run the data discovery scanner** (scan all data assets, profile candidate personal data, link governance policies, and identify evidence gaps):

```bash
python cli.py scan --export
```

Outputs a rich colored terminal table and saves formatted reports in `reports/inventory_report.md`, `reports/inventory_report.pdf`, and `reports/inventory_report.json`.

**Run the benchmark Precision/Recall evaluation:**

```bash
python cli.py evaluate --export
```

**Upload & scan a custom file via CLI:**

```bash
# Scan a custom CSV file
python cli.py scan --path uploads/my_customers.csv

# Scan a custom SQLite database file
python cli.py scan --path uploads/my_database.db
```

**Run the automated test suite:**

```bash
python -m unittest discover tests
```

Runs all 12 unit tests across validators, scanners, governance mapping, file uploads, and metrics calculation.

---

## 7. Deliverable Submission Checklist

- [x] **Working Prototype:** Deployed live at [https://privylens.onrender.com/](https://privylens.onrender.com/)
- [x] **5 Personal Data Classes:** PID, CNT, GID, FIN, LOC implemented and benchmarked
- [x] **Purpose & Retention Mapping + Evidence Gaps:** Implemented via governance registry
- [x] **Empirical Metrics:** Per-class Precision, Recall and F1-Score quantified
- [x] **Automated Tests:** 12 unit tests included
- [x] **Private GitHub Repository:** (repository link)(https://github.com/aiori-hackathon/A3-PS019-TC403)
- [x] **Deliverable PDF:** [deliverables.pdf](deliverables.pdf) uploaded at repository root
- [x] **Prototype Demonstration & Pseudocode Snippet:** [docs/PSEUDOCODE_SNIPPET.md](docs/PSEUDOCODE_SNIPPET.md)

---

## Legal Boundary & Privacy Engineering Disclaimer

PrivLens is designed specifically as a technical discovery and evidence compilation tool for human privacy officers, compliance auditors, and data stewards.

- It does **NOT** make automated lawful-basis decisions (e.g., assessing whether processing is justified under Consent Art. 6(1)(a) vs. Legitimate Interests Art. 6(1)(f)).
- It does **NOT** infer universal cross-border data transfer flows without verified network telemetry.
- All technical findings represent empirical observations to assist human decision-making and RoPA maintenance.
