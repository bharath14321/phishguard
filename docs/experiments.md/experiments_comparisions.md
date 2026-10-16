# AI-Powered Multi-Layer Phishing Detection

## Machine Learning Experiment Record

---

## Experiment 001 — URL-Based Binary Classification

### Objective

Evaluate whether basic lexical URL features can distinguish between benign and malicious URLs.

The experiment establishes a baseline before adding:

* Domain intelligence
* DNS/IP analysis
* Email analysis
* Webpage analysis
* Attachment analysis
* Malware behavioral analysis
* Threat intelligence

---

## Dataset

**Dataset file:**

`data/processed/url_features.csv`

**Total usable samples:**

641,108

### Binary classes

| Label | Meaning   | Samples |
| ----: | --------- | ------: |
|     0 | Benign    | 428,080 |
|     1 | Malicious | 213,028 |

### Train/Test Split

| Dataset  | Samples | Percentage |
| -------- | ------: | ---------: |
| Training | 512,886 |        80% |
| Testing  | 128,222 |        20% |

Configuration:

```text
test_size = 0.20
random_state = 42
stratify = y
```

The same split methodology is used for all three baseline models to make the comparison fair.

---

# URL Feature Set

All three baseline models use the same 14 URL features.

|  # | Feature                    | Description                                     |
| -: | -------------------------- | ----------------------------------------------- |
|  1 | `url_length`               | Total length of the URL                         |
|  2 | `hostname_length`          | Length of the hostname                          |
|  3 | `path_length`              | Length of the URL path                          |
|  4 | `query_length`             | Length of the query string                      |
|  5 | `dot_count`                | Number of dots in the URL                       |
|  6 | `hyphen_count`             | Number of hyphens                               |
|  7 | `digit_count`              | Number of numerical characters                  |
|  8 | `special_char_count`       | Number of special characters                    |
|  9 | `subdomain_count`          | Number of detected subdomain components         |
| 10 | `contains_ip`              | Whether the URL contains an IP address          |
| 11 | `uses_https`               | Whether HTTPS is used                           |
| 12 | `contains_at`              | Whether `@` appears in the URL                  |
| 13 | `contains_double_slash`    | Whether suspicious double-slash patterns appear |
| 14 | `suspicious_keyword_count` | Number of suspicious keywords detected          |

### Excluded from model features

The following columns are intentionally excluded from `X`:

```text
url
type
binary_label
multiclass_label
```

`type`, `binary_label`, and `multiclass_label` contain label information and must not be supplied to the model because that would cause data leakage.

---

# Model 1 — Logistic Regression

### Purpose

Establish a simple linear baseline.

### Configuration

```text
Model: Logistic Regression
Scaling: StandardScaler
Class weighting: balanced
max_iter: 1000
random_state: 42
```

### Results

| Metric    | Result |
| --------- | -----: |
| Accuracy  | 75.99% |
| Precision | 62.24% |
| Recall    | 70.57% |
| F1 Score  | 66.14% |

### Confusion Matrix

```text
                  Predicted
                Benign  Malicious

Actual Benign    67371    18245
Actual Malicious 12538    30068
```

### Observations

The model provides a useful baseline but has relatively low precision and F1 compared with the tree-based models.

It misses 12,538 malicious URLs in the test set.

---

# Model 2 — Random Forest

### Purpose

Test a nonlinear ensemble model using the same 14 URL features.

### Configuration

```text
Model: Random Forest
n_estimators: 200
class_weight: balanced
random_state: 42
n_jobs: -1
```

### Results

| Metric    | Result |
| --------- | -----: |
| Accuracy  | 91.08% |
| Precision | 85.17% |
| Recall    | 88.59% |
| F1 Score  | 86.85% |

### Confusion Matrix

```text
                  Predicted
                Benign  Malicious

Actual Benign    79044     6572
Actual Malicious  4860    37746
```

### Observations

Random Forest substantially improves the baseline results.

It detects 37,746 malicious URLs and misses 4,860 malicious URLs in the test set.

The model captures nonlinear relationships between URL characteristics that Logistic Regression cannot represent as effectively.

---

# Model 3 — XGBoost

### Purpose

Evaluate gradient-boosted decision trees against the Logistic Regression and Random Forest baselines.

### Configuration

```text
Model: XGBoost
n_estimators: 300
max_depth: 8
learning_rate: 0.1
subsample: 0.8
colsample_bytree: 0.8
objective: binary:logistic
eval_metric: logloss
random_state: 42
n_jobs: -1
```

### Results

| Metric    | Result |
| --------- | -----: |
| Accuracy  | 90.58% |
| Precision | 89.03% |
| Recall    | 81.73% |
| F1 Score  | 85.22% |

### Confusion Matrix

```text
                  Predicted
                Benign  Malicious

Actual Benign    81325     4291
Actual Malicious  7784    34822
```

### Observations

XGBoost produces the highest precision among the three baseline models.

However, its recall is lower than Random Forest, meaning it misses more malicious URLs in this experiment.

---

# Model Comparison

| Model               | Accuracy | Precision | Recall |     F1 |
| ------------------- | -------: | --------: | -----: | -----: |
| Logistic Regression |   75.99% |    62.24% | 70.57% | 66.14% |
| Random Forest       |   91.08% |    85.17% | 88.59% | 86.85% |
| XGBoost             |   90.58% |    89.03% | 81.73% | 85.22% |

### Interpretation

The three models show different behavior.

Logistic Regression provides the simplest baseline.

Random Forest provides the highest recall and F1 score in this experiment.

XGBoost provides the highest precision but lower recall than Random Forest.

These results should not be interpreted as proving that one algorithm is universally superior. They apply to this dataset, feature set, preprocessing procedure, and test configuration.

External evaluation on a separate dataset is required to investigate generalization.

---

# Feature Importance — Initial Analysis

Random Forest feature importance was calculated using the model's `feature_importances_` attribute.

Initial result:

| Feature                    | Importance |
| -------------------------- | ---------: |
| `path_length`              |   0.199130 |
| `dot_count`                |   0.135077 |
| `hostname_length`          |   0.115984 |
| `subdomain_count`          |   0.101652 |
| `special_char_count`       |   0.098119 |
| `url_length`               |   0.092637 |
| `digit_count`              |   0.079195 |
| `query_length`             |   0.056247 |
| `hyphen_count`             |   0.041842 |
| `uses_https`               |   0.040238 |
| `contains_ip`              |   0.020940 |
| `suspicious_keyword_count` |   0.017207 |
| `contains_at`              |   0.000894 |

`contains_double_slash` was missing from this initial output and must be verified before this table is treated as final.

### Important interpretation

Feature importance indicates how useful a feature was to the trained model for this dataset.

It does **not** prove that a feature independently causes malicious behavior.

For stronger explainability, later experiments will use:

* Permutation importance
* SHAP
* Individual prediction explanations

---

# Experiment Limitations

The current experiment uses only lexical URL features.

It does not yet analyze:

* Domain age
* DNS records
* IP reputation
* ASN
* WHOIS information
* Redirect chains
* Webpage HTML
* JavaScript
* Forms
* Email headers
* Sender authentication
* Attachments
* Office macros
* Malware behavior
* Threat intelligence

Therefore, the current detector should be considered a **URL-only baseline**, not the final phishing detection system.

---

# Planned Experiments

## Experiment 002 — Feature Importance

Analyze the contribution of individual URL features using:

* Random Forest importance
* Permutation importance
* SHAP

## Experiment 003 — Error Analysis

Investigate:

* False positives
* False negatives

Determine which URL patterns cause incorrect predictions.

## Experiment 004 — Adversarial URL Testing

Test transformations such as:

* URL encoding
* Subdomain manipulation
* Typosquatting
* Long random paths
* Suspicious keyword insertion
* IP-based URLs
* Redirect URLs
* Homograph/IDN techniques

## Experiment 005 — External Dataset Evaluation

Evaluate the trained models on Dataset 2 from a different source or collection methodology.

Dataset 2 must not be mixed into training.

This experiment will measure external generalization.

## Experiment 006 — Domain/DNS Intelligence

Add:

* DNS records
* IP information
* ASN
* Domain characteristics
* Reputation signals

## Experiment 007 — Email Analysis

Add:

* Email headers
* Sender/domain mismatch
* SPF
* DKIM
* DMARC
* Reply-To analysis
* Authentication results
* NLP/social-engineering signals

## Experiment 008 — Webpage Analysis

Add:

* HTML analysis
* Forms
* Password fields
* iframes
* JavaScript
* External resources
* Form submission destinations
* Redirect chains

## Experiment 009 — Attachment Analysis

Add:

* MIME type
* Magic bytes
* File hashes
* Embedded URLs
* Office macros
* Static malware indicators

## Experiment 010 — Behavioral Malware Analysis

Add isolated sandbox telemetry:

* Processes
* Files
* Registry
* Network connections
* DNS
* PowerShell
* Persistence mechanisms

## Experiment 011 — Multi-Layer Risk Model

Combine:

```text
URL Model
   +
Domain Model
   +
Email Model
   +
Web Model
   +
Attachment/Malware Model
   +
Threat Intelligence
        ↓
Risk Aggregator
        ↓
Final Risk Score
```

---

# Reproducibility

All baseline experiments currently use:

```text
Dataset:
data/processed/url_features.csv

Random seed:
42

Test size:
20%

Stratification:
Enabled

Feature count:
14

Classification:
Binary

0 = Benign
1 = Malicious
```

Future experiments should record their dataset, features, parameters, random seed, metrics, and limitations in this document.
## Error Analysis

Random Forest produced 11,432 classification errors on the test set.

- False positives: 6,572
- False negatives: 4,860

### False Negative Analysis

The false negatives were distributed across multiple malicious categories:

- Phishing: 3,166
- Defacement: 1,458
- Malware: 236

Examples of missed malicious URLs included URLs with relatively ordinary lexical structures as well as URLs containing suspicious-looking paths.

This indicates that URL lexical features alone are insufficient for reliably identifying all malicious URLs.

Potential missing signals include:

- Domain reputation
- Domain age
- DNS characteristics
- IP and ASN information
- Brand/domain mismatch
- Redirect behavior
- Final destination
- Webpage HTML characteristics
- Login/password forms
- External resource relationships
- Threat-intelligence information

### False Positive Analysis

The model produced 6,572 false positives.

Examples included legitimate URLs from domains such as:

- Wikipedia
- Reuters
- Yahoo
- FlightAware

Some benign URLs contained terms or structures that can appear in malicious URLs, such as login-related words, payment-related terms, long paths, or unusual URL structures.

This demonstrates that suspicious lexical characteristics should not automatically be treated as proof of maliciousness.

### Research Finding

The error analysis demonstrates a limitation of the URL-only baseline:

> Lexical URL features are useful for detecting suspicious URLs, but they do not provide sufficient contextual information to reliably distinguish all benign and malicious URLs.

Therefore, the next stage of the system will add domain, DNS, IP/ASN, reputation, and redirect intelligence before incorporating webpage, email, attachment, and behavioral signals.
## Adversarial URL Testing

A controlled adversarial experiment was performed using 20 benign
and 20 malicious URLs. Each URL was subjected to seven controlled
transformations.

| Transformation | Prediction changes | Change rate |
|---|---:|---:|
| Deeper subdomain | 9/20 | 45% |
| Added subdomain | 7/20 | 35% |
| Case changed | 5/20 | 25% |
| Encoded path | 4/20 | 20% |
| Added fragment | 3/20 | 15% |
| Added path | 3/20 | 15% |
| Added query | 3/20 | 15% |

The highest prediction-change rates occurred for transformations
that modified subdomain depth. This is consistent with the model
using features such as subdomain count, dot count, hostname length,
and URL length.

The case-change experiment also produced prediction changes,
which requires additional investigation into case sensitivity
within feature extraction, particularly suspicious keyword detection.

Prediction changes alone do not establish incorrect classification;
therefore, the direction of each prediction change and the change
in malicious probability must be analyzed separately.
