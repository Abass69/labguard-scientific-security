# Dataset card

## Provenance and intended use

Generated entirely by `labguard.research.generate(seed=42)` for a controlled security experiment. No real users, institutions, laboratory samples, patient data, network captures or attack traffic are included. Synthetic dataset distribution is licensed with this project. No external download is needed.

The seed-42 dataset contains 19,336 events, aggregated into 720 non-overlapping user/15-minute windows over 60 simulated days starting January 1, 2026 UTC. There are 12 repeated fictional users and two project labels. Each user has exactly one active window per day; inactive windows are absent. These are independently generated telemetry records, not an end-to-end replay through the access-control application. The application and simulator share the event schema and feature aggregator. Production-like throughput and causal policy enforcement are not inferred from this dataset.

## Files and schema

`events.jsonl`: one JSON object per event.

| Field | Meaning |
|---|---|
| ts | Unix seconds, UTC |
| actor | Fictional user identifier |
| action | read, write, export or login |
| outcome | allow or deny |
| project | food-a or food-b |
| records | Number of records accessed; zero for denied events |

`windows.csv`: user/window identifier, derived features and experimental metadata.

| Field | Meaning / model usage |
|---|---|
| actor | Group identifier, excluded from features |
| bucket | Floor of timestamp / 900, excluded |
| requests | Count of all events in window |
| denials | Count of all denied events |
| failed_logins | Denied login count |
| exports | Successful export event count |
| records | Sum of records accessed, including repeated records |
| off_hours | 1 outside 07:00–19:00 UTC, otherwise 0 |
| day | Simulated day 0–59, excluded |
| split | train / calibration / test, excluded |
| scenario | Generator scenario, excluded |
| label | 1 injected anomaly, 0 benign, excluded |

## Generation and splits

Ordinary activity has Poisson(15)+3 events per window. Base action probabilities are read 70%, write 20%, export 4%, login 6%; base denial probability is 2.5%. Seven percent of windows are scheduled at 01:00, 03:00 or 21:00; otherwise the start hour is sampled from 08:00–17:00. Probabilities are modeling assumptions, not empirical laboratory estimates.

A 12% conditional chance creates legitimate batch work, increasing event and export counts. In the test period, an 18% chance first selects an anomalous scenario uniformly among login burst, scope probe, bulk export and quiet misuse. Legitimate batch selection applies only when an anomaly was not selected. Exact branch order and distributions are executable in the generator.

- Days 0–29: 360 normal/legitimate-batch training windows.
- Days 30–39: 120 normal/legitimate-batch calibration windows.
- Days 40–59: 240 test windows, 47 anomalous for seed 42.

Chronological splitting prevents window overlap and future score calibration, but users repeat across splits. This is not a test of generalization to unseen users or laboratories. No attack labels are used for training or threshold choice. Labels are scenario assignments, not analyst-adjudicated truth; quiet misuse deliberately uses the ordinary event distribution.

## Quality and reproducibility

No missing values are generated. Counts are nonnegative, denied events have zero records, and labels and scenario fields are excluded from model features. Tests check deterministic regeneration, unique window identifiers, split ordering and independence of fitting from test feature changes. The raw SHA-256 is recorded in `results/metrics.json`. Generator changes define a new benchmark version and must not silently reuse the old reported metrics.

## Limits

Small sample size, fixed users, simplistic independent daily workloads, elevated anomaly prevalence, no network/device features, no sample identifiers in telemetry, no seasonality or shift in the main benchmark, and no linkage to real compliance policies. Off-hours does not mean malicious. Bulk work can be legitimate; low-volume misuse can be invisible. Treat results as a feasibility exercise and a source of falsifiable research questions.
