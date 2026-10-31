# PrivLens: Pseudocode Snippet & Mentor Briefing

**Project:** PrivLens (PS-019), PII Discovery & Privacy Evidence Inventory Engine
**Live Project:** [https://privylens.onrender.com/](https://privylens.onrender.com/)

This document summarises the core logic of PrivLens in language-neutral pseudocode. It mirrors the implementation in `privlens/scanner/`, `privlens/governance/` and `privlens/evaluation/`.

---

## 1. End-to-End Pipeline

```
FUNCTION run_privlens(target_path):

    # --- Stage 1: Discovery ---
    discovered_fields = ScannerEngine.scan_path(target_path)

    # --- Stage 2: Governance linking & gap detection ---
    inventory = GovernanceMapper.map_all(discovered_fields)

    # --- Stage 3: Benchmark evaluation ---
    evaluation = BenchmarkEvaluator.evaluate(discovered_fields)

    # --- Stage 4: Reporting ---
    export JSON / Markdown / PDF reports from (inventory, evaluation)
    serve dashboard and REST API from (inventory, evaluation)

    RETURN inventory, evaluation
```

---

## 2. Scanner Engine: Source Routing

```
FUNCTION scan_path(target_path):
    results = []

    IF target_path is a file:
        IF extension == ".csv":
            results += CSVScanner.scan_file(target_path)
        ELSE IF extension IN (".db", ".sqlite", ".sqlite3"):
            results += SQLScanner.scan_sqlite(target_path)

    ELSE IF target_path is a directory:
        results += CSVScanner.scan_directory(target_path)      # every .csv, recursively
        FOR each database file found under target_path:
            results += SQLScanner.scan_sqlite(database_file)

    RETURN results
```

---

## 3. Column Profiling (CSV and SQLite)

```
FUNCTION scan_file(csv_path):                      # CSVScanner
    table = read_csv(csv_path)
    fields = []

    FOR each column IN table:
        samples = first SAMPLE_LIMIT (100) non-null values of column

        (is_pii, class_id, class_name, confidence, evidence, masked_preview)
            = RuleMatcher.evaluate_column(column.name, samples)

        fields.append(DiscoveredField(
            source, column.name, data_type,
            total_records, non_null_records,
            is_pii, class_id, class_name,
            confidence, evidence, masked_preview))

    RETURN fields


FUNCTION scan_sqlite(db_path):                     # SQLScanner
    fields = []
    FOR each user table IN database (excluding sqlite_* internals):
        total_rows = COUNT(*) of table
        sample_rows = SELECT * FROM table LIMIT SAMPLE_LIMIT

        FOR each column IN table schema:
            samples = non-null values of column from sample_rows
            non_null_count = COUNT(column) of table

            (is_pii, class_id, ...) = RuleMatcher.evaluate_column(column.name, samples)
            fields.append(DiscoveredField(..., table_name = table, ...))
    RETURN fields
```

---

## 4. Rule Matcher: the Evidence Checklist (core logic)

Each rule in `config/detection_rules.yaml` combines **header patterns**, **value patterns**, an optional **checksum validator** and a minimum **sample match ratio**.

```
CONSTANTS (from detection_rules.yaml):
    MIN_NON_EMPTY      = 3       # need at least 3 values to profile reliably
    RULE_TRIGGER       = 0.35    # minimum rule score to record as evidence
    CLASS_CUTOFF       = 0.50    # minimum score to classify as personal data

FUNCTION evaluate_column(column_name, samples):

    values = samples without nulls or blanks
    IF count(values) < MIN_NON_EMPTY:
        RETURN (not personal data, no evidence)

    evidence_list = []
    class_scores  = {}                       # best score per data class

    FOR each rule IN detection_rules:

        # 1. Header heuristic
        header_matched = ANY(rule.header_patterns matches column_name)

        # 2. Value patterns + checksum validators
        value_matches = 0
        FOR each v IN values:
            IF ANY(rule.value_patterns matches v):
                IF rule.validator is set:
                    ok = run validator(v)    # luhn_checksum | valid_aadhaar
                                             # | valid_ipv4 | valid_geo_coords
                ELSE:
                    ok = TRUE
                IF ok: value_matches += 1

        match_ratio   = value_matches / count(values)
        value_matched = match_ratio >= rule.min_sample_match_ratio

        # 3. Weighted score
        IF header_matched AND value_matched:
            score = header_weight + value_weight * match_ratio
        ELSE IF header_matched AND match_ratio >= 0.10:
            score = header_weight * 0.90 + value_weight * match_ratio
        ELSE IF header_matched:
            score = header_weight * 0.70
        ELSE IF value_matched:
            score = value_weight * match_ratio
        ELSE:
            score = 0

        score = MIN(1.0, ROUND(score, 3))

        # 4. Record evidence if strong enough
        IF score >= RULE_TRIGGER:
            evidence_list.append(EvidenceItem(
                rule, header_matched, value_matched,
                value_matches, count(values), match_ratio, score))
            class_scores[rule.class] = MAX(class_scores[rule.class], score)

    # 5. Final classification
    IF class_scores is not empty:
        best_class = class with highest score
        IF class_scores[best_class] >= CLASS_CUTOFF:
            preview = mask(first 4 values)           # privacy-safe samples
            RETURN (personal data, best_class, score, evidence_list, preview)

    RETURN (not personal data, low-confidence evidence only)
```

### Checksum validators used as evidence

```
FUNCTION luhn_checksum(value):                # card numbers
    digits = strip spaces/dashes; require 13..19 digits
    total = 0
    FOR each digit from right to left, with index i:
        IF i is odd:
            d = digit * 2
            IF d > 9: d = d - 9
            total += d
        ELSE:
            total += digit
    RETURN (total MOD 10 == 0)

FUNCTION valid_aadhaar(value):                # 12 digits, first digit not 0 or 1
FUNCTION valid_geo_coords(value):             # "lat, lon" within [-90, 90] and [-180, 180]
FUNCTION valid_ipv4(value):                   # valid, non-loopback, non-multicast
```

### Masking (sample values are never shown raw)

```
FUNCTION mask(value):
    email    -> first char + "***" + last char of prefix, domain kept
    Aadhaar  -> "XXXX-XXXX-" + last 4 digits
    PAN      -> first 2 + "***" + last 2
    card/IBAN-> first 4 + "-****-****-" + last 4
    other    -> first 2 + "***" + last 2
```

---

## 5. Governance Mapper: Purpose, Retention & Evidence Gaps

```
FUNCTION map_field(field):

    key       = source_name (+ ":" + table_name for SQL)
    field_id  = key + "::" + column_name
    entry     = governance_registry[key][column_name]       # may be missing
    gaps      = []

    IF entry is missing:
        status = "UNREGISTERED"
        IF field.is_candidate_pii:
            gaps.append(UNREGISTERED_SHADOW_DATA, severity = CRITICAL,
                        action = "Verify necessity with data owner; register purpose
                                  and retention in RoPA, or minimise / decommission")

    ELSE:
        purpose   = entry.purpose_id
        retention = entry.retention_period_months
        status    = entry.status

        IF field.is_candidate_pii:
            IF purpose is empty:
                gaps.append(MISSING_PURPOSE, severity = HIGH,
                            action = "Assign and validate a declared business purpose")
            IF retention is empty OR retention <= 0:
                gaps.append(MISSING_RETENTION, severity = HIGH,
                            action = "Define retention schedule and disposal trigger")

    RETURN InventoryItem(field_id, field, governance_metadata, gaps,
                         disclaimer = "Technical evidence only; requires human privacy review")
```

---

## 6. Benchmark Evaluation: Per-Class Precision & Recall

```
FUNCTION evaluate(discovered_fields):

    stats = { class: {TP:0, FP:0, FN:0, TN:0} for class IN (PID, CNT, GID, FIN, LOC) }

    FOR each field IN discovered_fields:
        truth = ground_truth.lookup(source, table, column)
        IF truth is missing: CONTINUE

        true_class = truth.class            # or "not personal data"
        pred_class = field.class IF field.is_candidate_pii ELSE "not personal data"

        FOR each class c:
            IF true_class == c AND pred_class == c:  stats[c].TP += 1
            ELSE IF pred_class == c:                 stats[c].FP += 1
            ELSE IF true_class == c:                 stats[c].FN += 1
            ELSE:                                    stats[c].TN += 1

    # Ground-truth fields the scanner never reached count as false negatives
    FOR each ground-truth PII field not scanned:
        stats[its class].FN += 1

    FOR each class c:
        precision = TP / (TP + FP)
        recall    = TP / (TP + FN)
        f1        = 2 * precision * recall / (precision + recall)

    macro_P / macro_R / macro_F1 = mean of per-class values
    micro_P / micro_R / micro_F1 = computed from summed TP, FP, FN

    RETURN per-class metrics, macro/micro averages, confusion details
```

---

## 7. Mentor Briefing

**Problem.** Organisations store personal data across spreadsheets and databases that are not all documented. Privacy officers need technical evidence of *where* personal data lives and whether each field has a declared purpose and retention schedule.

**Approach.** PrivLens profiles every column of CSV and SQLite sources, scores it against a configurable rule checklist (header heuristic + regex + checksum + sample match ratio), assigns one of five data classes (PID, CNT, GID, FIN, LOC) or "not personal data", then cross-checks each field against the governance registry to surface evidence gaps.

**Why it is explainable.** Every classification carries its evidence: which rule fired, whether the header and values matched, the sample match ratio, and which validator confirmed it. Nothing is a black-box prediction.

**Why it is measurable.** Results are compared against a manually labelled ground truth with per-class Precision, Recall and F1, plus macro and micro averages.

**Privacy by design.** Sample values shown in evidence are masked, and only up to 100 values per column are profiled.

**Boundary.** PrivLens compiles technical evidence for human review. It does not make lawful-basis decisions and does not infer cross-border data transfers.

**Possible future work.** Additional file formats and database engines, more locale-specific identifiers, and rule tuning from reviewer feedback.
