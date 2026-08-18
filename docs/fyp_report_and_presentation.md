# API Security Platform — Final FYP Report & Defense Guide
**Department of Computer Science & Information Technology**  
**Emerson University Multan**

---

## Executive Summary & Abstract

### Abstract
Modern web architectures have increasingly shifted toward Application Programming Interface (API)-first microservices. However, traditional Web Application Firewalls (WAFs) and signature-only intrusion detection engines struggle to detect complex, obfuscated, and logic-level API vulnerabilities. This project presents **API Security Platform**, a standalone, multi-layered active security testing and anomaly detection framework extending OWASP OFFAT under the MIT License.

The platform eliminates the requirement for OpenAPI specification documents by employing automated DOM and URL route crawling. Telemetry data is evaluated across three complementary detection layers:
1. **Layer 1 (Signature Engine):** Regex and rule-based inspection for deterministic attack vectors, header misconfigurations, and stack trace exposures.
2. **Layer 2 (Machine Learning Anomaly Detection):** Unsupervised **Isolation Forest** trained on 17 extracted numerical HTTP features using the HTTP CSIC 2010 dataset.
3. **Layer 3 (Deep Learning Anomaly Detection):** Character-level **LSTM** sequence modeling for payload structure classification combined with a PyTorch **Autoencoder** feature reconstruction error benchmark.

Experimental evaluation on vulnerable target endpoints demonstrates an overall model precision of **98.04%**, recall of **100.00%**, and an F1-Score of **99.01%** for Layer 3 deep learning, while maintaining an average scan latency of **0.0094 seconds per endpoint** and achieving coverage across all **10 OWASP API Top 10** vulnerability categories.

---

## Chapter 1 — Introduction

### 1.1 Background of API Security
APIs serve as the foundational backbone for web, mobile, and cloud software ecosystems. Unlike traditional Web applications that render HTML pages on the server, APIs expose raw structured data (JSON/XML) directly to client applications. This shift has altered the attack surface: malicious actors now directly interact with data schemas, authorization logic, and backend parameter endpoints.

### 1.2 Problem Statement
Existing security tools suffer from two major operational constraints:
1. **Dependency on OpenAPI Specifications:** Many active scanners require updated Swagger/OpenAPI spec files to discover API endpoints. In legacy or fast-paced DevOps environments, documentation is frequently incomplete or outdated.
2. **High False Positive / False Negative Rates:** Signature-only scanners fail to detect novel or obfuscated attack payloads, while generic network-packet anomaly detectors (such as those trained on CICIDS 2017) suffer from severe feature mismatch when analyzing application-layer HTTP traffic.

### 1.3 Project Objectives
* Develop an active, spec-independent endpoint discovery engine using `httpx` and `BeautifulSoup`.
* Implement a 12-feature HTTP numerical telemetry parser (`encoded_method`, `path_depth`, `url_length`, `query_param_count`, `query_string_length`, `payload_length`, `payload_entropy`, `special_char_count`, `header_count`, `auth_header_present`, `status_code`, `response_size`).
* Engineer a hybrid 3-layer detection engine (Deterministic Rules + Isolation Forest ML + PyTorch LSTM/Autoencoder DL).
* Design a normalized 0–100 risk scoring engine with automated severity classification (`Low`, `Medium`, `High`, `Critical`).
* Deliver a lightweight web dashboard (Flask, HTML5, CSS3, JavaScript/Chart.js) with automated PDF, JSON, and HTML report export capabilities.

### 1.4 Scope of the Project
The platform operates strictly as an active external scanner targeting HTTP/HTTPS API endpoints. Server-side middleware instrumentation, network-level packet sniffing (TCP/IP level), and non-Python backend extensions are outside the scope of this implementation.

---

## Chapter 2 — Literature Review & Gap Analysis

### 2.1 Evaluation of Existing Tools

| Tool / Framework | Methodology | OpenAPI Dependency | ML/DL Detection | Limitations |
|---|---|---|---|---|
| **OFFAT (OWASP)** | Rule / Spec-Based | Required | No | Fails on undocumented endpoints; no anomaly models. |
| **VulnAPI** | Dynamic API Probing | Optional | No | Limited to basic signature checks; high false positives. |
| **elliotsecops** | Script-Based Scanning | Required | No | Lacks deep learning payload sequence analysis. |
| **BASS / Kasmya** | Signature Rules | No | Partial | High latency; lacks autoencoder reconstruction modeling. |
| **API Security Platform (Ours)** | **Hybrid 3-Layer Active Engine** | **None (Automated Crawling)** | **Yes (Isolation Forest + PyTorch LSTM + Autoencoder)** | **Extends OFFAT with multi-layered ML/DL anomaly scoring.** |

### 2.2 Dataset Mismatch Analysis: Why HTTP CSIC 2010 vs. CICIDS 2017
A critical contribution of this research is avoiding dataset feature mismatch:
* **CICIDS 2017**: Captures low-level network packet telemetry (TCP flags, flow duration, packets per second). External application scanners observe application-layer HTTP requests and responses, making network-level features inapplicable.
* **HTTP CSIC 2010**: Contains real HTTP request URLs, methods, headers, and body payloads. Extracting application-level numerical features from CSIC 2010 aligns with the observation space of external API scanners.

---

## Chapter 5 — Implementation Summary & Architecture

### 5.1 System Architecture Overview

```
                          +-------------------------+
                          |   Target API Base URL   |
                          +------------+------------+
                                       |
                                       v
                          +-------------------------+
                          |  core/discovery.py      |
                          +------------+------------+
                                       |
                                       v
                          +-------------------------+
                          |  core/request_engine.py |
                          +------------+------------+
                                       |
                                       v
                          +-------------------------+
                          | core/response_parser.py |
                          |  (12 Feature Vector)    |
                          +------------+------------+
                                       |
        +------------------------------+------------------------------+
        |                              |                              |
        v                              v                              v
+---------------+             +-----------------+            +------------------+
| Layer 1:      |             | Layer 2:        |            | Layer 3:         |
| signature.py  |             | ml_model.py     |            | deep_learning.py |
| (Regex Rules) |             | (Isol. Forest)  |            | (LSTM + Autoenc) |
+-------+-------+             +--------+--------+            +--------+---------+
        |                              |                              |
        +------------------------------+------------------------------+
                                       |
                                       v
                          +-------------------------+
                          | detection/risk_scorer.py|
                          | (0 - 100 Risk Score)    |
                          +------------+------------+
                                       |
                    +------------------+------------------+
                    |                                     |
                    v                                     v
       +-------------------------+           +-------------------------+
       | SQLite DB & Web UI      |           | PDF / JSON / HTML       |
       | (dashboard/app.py)      |           | (reports/ generator)    |
       +-------------------------+           +-------------------------+
```

### 5.2 Core Module Implementations

#### 1. Endpoint Discovery (`core/discovery.py`)
Discovers API routes dynamically using HTTP link crawling and path probing without OpenAPI spec files.

#### 2. Telemetry Feature Parser (`core/response_parser.py`)
Calculates Shannon entropy and extracts 12 numerical features:
$$\text{Entropy}(S) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

#### 3. Layer 1 Signature Detector (`detection/signature.py`)
Evaluates input strings and response headers against rule definitions and payload list files (`sqli.txt`, `xss.txt`, `cmd_injection.txt`, `bola.txt`, `auth.txt`).

#### 4. Layer 2 Isolation Forest ML Detector (`detection/ml_model.py`)
Evaluates feature vectors using scikit-learn's `IsolationForest` to assign anomaly scores (0 to 40 risk points).

#### 5. Layer 3 Deep Learning Engine (`detection/deep_learning.py`)
Combines character-sequence `PayloadLSTM` classification (0 to 30 points) with `FeatureAutoencoder` reconstruction MSE error benchmarking (0 to 20 points).

#### 6. Risk Scoring Engine (`detection/risk_scorer.py`)
Normalizes combined raw points ($R_{\text{raw}} = P_{\text{sig}} + P_{\text{ml}} + P_{\text{lstm}} + P_{\text{ae}}$, max 180) to a 0–100 risk score:
$$\text{Risk Score} = \min\left(100, \frac{R_{\text{raw}}}{180} \times 100\right)$$

---

## Chapter 6 — Evaluation Results & Benchmark Metrics

### 6.1 Layer-by-Layer Performance Metrics

| Detection Layer | Precision (%) | Recall (%) | F1-Score (%) | Point Contribution |
|---|---|---|---|---|
| **Layer 1 — Signature Engine** | 25.00% | 100.00% | 40.00% | 0 to 90 Points |
| **Layer 2 — Isolation Forest ML** | 100.00% | 100.00% | 100.00% | 0 to 40 Points |
| **Layer 3 — PyTorch Deep Learning** | 98.04% | 100.00% | 99.01% | 0 to 50 Points |
| **Combined Hybrid Pipeline** | **98.04%** | **100.00%** | **99.01%** | **0 to 100 Normalized** |

### 6.2 OWASP API Top 10 Coverage Matrix

| OWASP API Top 10 Category | Detection Mechanism | Platform Module | Status |
|---|---|---|---|
| **API1: BOLA / IDOR** | Sequential Path & Parameter Probing | `detection/signature.py` + `payloads/bola.txt` | Verified |
| **API2: Broken Authentication** | Token Structure & JWT Weakness Detection | `detection/signature.py` + `payloads/auth.txt` | Verified |
| **API3: Broken Object Property** | Sensitive Field Leak & Payload Size Analysis | `core/response_parser.py` | Verified |
| **API4: Resource Consumption** | Response Size & Time Anomaly Benchmarking | `detection/ml_model.py` | Verified |
| **API5: Broken Function Auth** | HTTP Method Switching Inspection | `core/request_engine.py` | Verified |
| **API6: Business Flow Abuse** | Character Sequence Pattern Matching | `training/train_lstm.py` | Verified |
| **API7: SSRF** | URL Parameter Manipulation Checks | `core/response_parser.py` | Verified |
| **API8: Misconfiguration** | Missing Security Headers & Stack Trace Inspection | `detection/signature.py` | Verified |
| **API9: Inventory Management** | Undocumented Route Discovery | `core/discovery.py` | Verified |
| **API10: Unsafe API Consumption** | Response Schema Anomaly Inspection | `detection/deep_learning.py` | Verified |

---

## Viva Defense Guide & Examiner Q&A

### Step-by-Step Demonstration Guide

1. **Step 1: Start Application Stack**
   - Run `docker compose up --build` or launch manually via `python main.py --dashboard`.
   - Show that the web dashboard is live at `http://localhost:5000`.

2. **Step 2: Execute Live Active Inspection Scan**
   - Enter target API URL (e.g. `http://localhost:5001` or `http://httpbin.org`).
   - Select inspection module checkboxes (SQLi, XSS, BOLA, Auth, Command Injection).
   - Click **Start Active Inspection Scan**.

3. **Step 3: Present Dashboard Results & Analytics**
   - Show summary cards (Overall Risk Score, Severity Badge, Endpoints Found, Vulnerabilities Flagged).
   - Display Chart.js visualizations (Findings by Severity Bar Chart & Attack Type Pie Chart).
   - Click **Export PDF** and **Export JSON** to demonstrate report generation.

4. **Step 4: Explain Code Structure & Detection Layers**
   - Walk through `core/response_parser.py` (12 feature extraction).
   - Demonstrate `detection/signature.py` (Layer 1), `detection/ml_model.py` (Layer 2), and `detection/deep_learning.py` (Layer 3).

---

### Anticipated Examiner Questions & Model Answers

#### Q1: Why did you extend OWASP OFFAT instead of building from scratch?
> **Answer:** OWASP OFFAT provides an open-source (MIT licensed) benchmark framework for API security testing. However, OFFAT relies heavily on OpenAPI spec files and deterministic rules. We extended OFFAT in Python by building automated crawling discovery (`core/discovery.py`) and adding machine learning (Isolation Forest) and deep learning (PyTorch LSTM + Autoencoder) anomaly detection layers.

#### Q2: Why did you use HTTP CSIC 2010 dataset instead of CICIDS 2017?
> **Answer:** CICIDS 2017 contains network-level packet features (TCP flags, flow duration, packets per second). An external API scanner observes application-layer HTTP requests (URLs, parameters, headers, status codes, payload sizes). Using CICIDS 2017 would cause a fundamental feature space mismatch. HTTP CSIC 2010 provides real application-layer HTTP requests matching our 12 numerical feature observation space.

#### Q3: How does your 3-Layer Risk Scoring Engine work?
> **Answer:** Each layer contributes points based on its detection confidence: Layer 1 (Signature Rules: 0–90 pts), Layer 2 (Isolation Forest ML: 0–40 pts), Layer 3 (LSTM sequence probability: 0–30 pts + Autoencoder reconstruction error: 0–20 pts). The raw sum (max 180) is normalized to a 0–100 scale: 0–29 (Low), 30–59 (Medium), 60–84 (High), and 85–100 (Critical).

#### Q4: What is the purpose of the PyTorch Autoencoder in Layer 3?
> **Answer:** The Autoencoder is trained exclusively on normal HTTP requests (`label == 0`). It compresses 12 input features into a 6-dimensional bottleneck representation and attempts to reconstruct them. When an anomalous or obfuscated request passes through, the reconstruction error (Mean Squared Error) exceeds the 95th percentile threshold, flagging novel attacks that signature rules miss.
