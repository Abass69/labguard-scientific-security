# Model card

**Purpose:** rank unusual synthetic user/15-minute activity for human review. Never automatically punish users or infer guilt.

**Model:** scikit-learn Isolation Forest, 200 trees, max_samples=256, random_state=42, one worker, other parameters at installed defaults. Fitted exclusively on 360 training windows. Six unscaled numerical features: requests, denials, failed logins, exports, records, off_hours. Larger negative `score_samples` values indicate greater anomaly. No identity, timestamps, scenarios or labels are features. No hyperparameter search was performed.

**Threshold:** 95th percentile (`method='higher'`) of 120 benign calibration-window scores; alert when score is strictly greater. This nominal calibration budget is not a guarantee of a 5% false-positive rate on future data.

**Baseline:** alert on at least 5 failed logins OR at least 10 denials OR (at least 8 successful exports AND at least 60 records accessed). Rules are hand-written simulation assumptions. They are not calibrated to the same false-positive budget as Isolation Forest, so the comparison is descriptive rather than an operating-point-matched superiority claim.

**Evaluation:** fixed chronological holdout; confusion counts, precision, recall, F1, benign false-positive rate, average precision (AP) and ROC AUC. AP summarizes the ranking precision-recall curve; it is not trapezoidal PR area. Five simulator seeds assess sensitivity while the model seed stays fixed. The optional 500-resample window bootstrap percentile interval is descriptive: repeated users violate independence and it does not measure real-world uncertainty.

**Failure modes:** benign batch exports resemble misuse; ordinary-looking misuse is invisible to these aggregate features. An attacker who stays within the learned workload may evade detection. Concept drift, compromised instruments, admin compromise and network attacks are not evaluated. Reference-trained live audit scoring uses the same aggregator but an unmatched workload distribution. Do not interpret those scores as calibrated probabilities or real-lab validation.

**Deployment status:** offline sandbox only, with no persistent model pickle. The live scoring command refits from the reference CSV, avoiding untrusted pickle loading. Verify dataset provenance if replacing the CSV. No real data validation or external model audit has been performed.
