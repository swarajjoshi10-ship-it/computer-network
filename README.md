# 🛡️ 5G Network Intrusion Detection & Automated Defense System

**An End-to-End 3GPP 5G Core (UPF/NWDAF) Intrusion Detection, Protocol Auditing, and Cisco Packet Tracer Defense Pipeline**

This project delivers an applied Computer Networks capstone case study implementing real-time network flow extraction, machine-learning-driven threat intelligence (NWDAF), SHAP protocol explainability, and automated network defense synthesis (**Cisco IOS Extended ACLs, Linux iptables, and Snort/Suricata signatures**).

<p align="center">
  <img src="https://img.shields.io/badge/Cisco_Packet_Tracer-2911_Router-049fd9?style=for-the-badge&logo=cisco&logoColor=white" alt="Cisco Packet Tracer">
  <img src="https://img.shields.io/badge/3GPP_5G_Core-UPF_%2F_NWDAF-005A9C?style=for-the-badge" alt="5G Core">
  <img src="https://img.shields.io/badge/Network_Security-Firewall_%26_ACL-DC3545?style=for-the-badge" alt="Network Security">
  <img src="https://img.shields.io/badge/Protocols-L2_to_L4_Dissection-28A745?style=for-the-badge" alt="Network Protocols">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
</p>

---

## 📑 Table of Contents

- [Computer Networks Architecture](#-computer-networks-architecture)
- [Project Objectives](#-project-objectives)
- [Computer Networks Tech Stack & Topic Matrix](#-computer-networks-tech-stack--topic-matrix)
- [Pipeline & Toolchain](#-pipeline--toolchain)
- [Repository Structure](#-repository-structure)
- [Cisco Packet Tracer Demonstration](#-cisco-packet-tracer-demonstration)
- [Live UPF Real-Time Monitor](#-live-upf-real-time-monitor)
- [Visualizations](#-visualizations)
- [Running the System](#-running-the-system)

---

## 🌐 Computer Networks Architecture

In accordance with **3GPP Release 16 / 17 Standards**, network operations are partitioned into the high-speed **Data Plane** and the **Analytics / Management Plane**:

```text
 ============================================================================================
  DATA PLANE (User Plane / Traffic Flow) - Modeled in Cisco Packet Tracer & Scapy
 ============================================================================================
   [Legitimate UE] ──┐
   (10.0.1.10)       │ GigabitEthernet0/0/0
                     ▼
             [5G gNodeB Switch] ──► [5G UPF Router (Cisco 2911)] ──► [5G Core Server]
                     ▲              (GigabitEthernet0/0/1)           (10.0.3.100 - Web/SSH)
   [Attacker UE]   ──┘                      │
   (10.0.1.99 - SYNScan / DoS)              │ Ingress Telemetry / Packet Flows
                                            ▼
 ============================================================================================
  ANALYTICS & CONTROL PLANE (Python NWDAF Engine + Mitigation)
 ============================================================================================
   ┌────────────────────────────────────────────────────────────────────────────────────────┐
   │ 1. WIRE / PCAP LAYER (`pcap_flow_analyzer.py`)                                         │
   │    Sniffs raw packets, parses IP/TCP headers (TTL, Flags, Window size, Flow Rate).     │
   ├────────────────────────────────────────────────────────────────────────────────────────┤
   │ 2. INTELLIGENT DETECTION (`phase1` to `phase3`)                                        │
   │    Preprocesses flow metrics, handles class imbalance, classifies attacks (XGBoost/RF).│
   ├────────────────────────────────────────────────────────────────────────────────────────┤
   │ 3. PROTOCOL AUDITING (`phase4_explainability.py`)                                      │
   │    SHAP stability audit identifies RFC-level protocol violations (e.g., sTtl, State).  │
   ├────────────────────────────────────────────────────────────────────────────────────────┤
   │ 4. ENFORCEMENT ENGINE (`network_defense_exporter.py`)                                  │
   │    Synthesizes rules into:                                                             │
   │    • Cisco IOS Extended ACLs (`cisco_defense.ios`) -> Pasted into Packet Tracer Router│
   │    • Linux Netfilter (`iptables_rules.sh`)         -> For Linux UPF hosts              │
   │    • Snort/Suricata Signatures (`suricata_5g.rules`)-> For Network Edge NIDS           │
   └────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Project Objectives

- **Wire-Level Dissection:** Parse raw binary PCAP frames across Ethernet (L2), IPv4 (L3), and TCP/UDP (L4).
- **Flow Feature Extraction:** Reassemble packets into bidirectional 5-tuples and compute statistical flow metrics (`sTtl`, `Dur`, `Rate`, `sMeanPktSz`, `State`).
- **Class Imbalance Mitigation:** Address rare attack frequency in telecom data using Cost-Sensitive Weighting and SMOTE/ADASYN.
- **Protocol Anomaly Auditing:** Use SHAP cross-fold audits to uncover RFC-level protocol deviations (e.g., low TTLs and half-open TCP SYN scans).
- **Automated Network Defense:** Compile ML decision rules into active **Cisco IOS Extended ACLs**, **Linux iptables**, and **Snort signatures**.
- **Interactive UPF Emulation:** Monitor live traffic streams at the 5G UPF edge with sub-millisecond classification overhead (< 0.1ms).

---

## 📂 Repository Structure

```text
5G-Network-Intrusion-Detection-/
│
├── cisco_packet_tracer_guide.md       # Step-by-step Cisco Packet Tracer topology & setup guide
├── cisco_defense.ios                  # Auto-generated Cisco IOS CLI Extended Access Control List
├── iptables_rules.sh                  # Auto-generated Linux Netfilter firewall enforcement script
├── suricata_5g.rules                  # Auto-generated Snort/Suricata IDS/IPS signature rules
│
├── pcap_flow_analyzer.py              # Pure Python L2-L4 binary PCAP packet dissector & flow extractor
├── live_upf_ids.py                    # Real-time 5G UPF terminal telemetry & intrusion monitor
├── network_defense_exporter.py        # Compiles ML/SHAP rules into Cisco, iptables, & Snort rules
│
├── phase1_ingestion.py                # Data loading, cleaning, and leakage prevention
├── phase2_imbalance.py                # Cost-sensitive & SMOTE class imbalance handling
├── phase3_models.py                   # Model training (Random Forest, XGBoost, MLP)
├── phase4_explainability.py           # SHAP stability cross-fold audit (Jaccard metric)
├── phase5_mitigation.py               # Attack decision tree extractor & collateral drop evaluation
├── phase6_visuals.py                  # Generates publication-grade ROC & SHAP curves
│
├── roc_curve.png                      # ROC curve visualization (AUC = 0.8740 without leakage)
├── shap_bar_chart.png                 # Global feature importance plot
├── shap_summary_beeswarm.png          # Directional SHAP feature beeswarm plot
└── .gitignore
```

### Key Tool Descriptions

| File | Purpose | Computer Networks Topic |
| :--- | :--- | :--- |
| `cisco_defense.ios` | Generated Cisco CLI configuration | **Cisco IOS Extended ACLs & Ingress Filtering** |
| `pcap_flow_analyzer.py` | Binary packet parser & flow builder | **OSI L2 Ethernet, L3 IPv4 (TTL), L4 TCP Handshake** |
| `live_upf_ids.py` | Real-time 5G UPF telemetry monitor | **3GPP 5G NWDAF & URLLC Latency Monitoring** |
| `network_defense_exporter.py`| Defense compiler | **Automated Firewall & NIDS Rule Generation** |
| `cisco_packet_tracer_guide.md`| Lab topology guide | **Cisco Packet Tracer Router/Switch/Server Simulation** |

---

## 📊 Visualizations

### 1. ROC Curve

**File:** `roc_curve.png`

![ROC Curve](roc_curve.png)

The Receiver Operating Characteristic (ROC) curve illustrates the relationship between the true positive rate and false positive rate across classification thresholds.

### 2. SHAP Feature Importance

**File:** `shap_bar_chart.png`

![SHAP Feature Importance](shap_bar_chart.png)

The SHAP bar chart summarizes feature importance based on SHAP values, helping identify which input features contribute to model predictions.

### 3. SHAP Summary Beeswarm Plot

**File:** `shap_summary_beeswarm.png`

![SHAP Summary Beeswarm Plot](shap_summary_beeswarm.png)

The beeswarm plot displays the distribution of feature contributions across predictions, helping illustrate how feature values influence model outputs.

---

## 🧰 Technology Stack

| Technology | Application |
|---|---|
| Python | Core implementation |
| Pandas | Data manipulation and preprocessing |
| NumPy | Numerical operations |
| Scikit-learn | Machine learning and evaluation |
| TensorFlow / Keras | Deep learning, if used by the implementation |
| SHAP | Model explainability |
| Matplotlib / Seaborn | Data visualization, where used |

The exact dependencies depend on the libraries imported by the individual scripts.

---

## 🚀 Installation and Setup

### Prerequisites

- Python installed on your system.
- Git installed on your system.
- Access to the required dataset.
- The Python dependencies used by the project.

### Step 1: Clone the Repository

```bash
git clone https://github.com/NAKAIT777/5G-Network-Intrusion-Detection-.git
cd 5G-Network-Intrusion-Detection-
```

### Step 2: Create a Virtual Environment

**Windows**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

If the repository contains a `requirements.txt` file:

```bash
pip install -r requirements.txt
```

Otherwise, install the required packages individually. For example:

```bash
pip install pandas numpy scikit-learn matplotlib seaborn shap tensorflow
```

Install only the libraries required by your implementation and use compatible package versions.

---

## ▶️ Running the Pipeline

Run the scripts from the repository's root directory, following the intended execution order.

**Phase 1 — Data Ingestion and Preprocessing**

```bash
python phase1_ingestion.py
```

**Phase 2 — Class Imbalance Handling**

```bash
python phase2_imbalance.py
```

**Phase 3 — Model Training and Comparison**

```bash
python phase3_models.py
```

**Phase 4 — Explainable AI**

```bash
python phase4_explainability.py
```

**Phase 5 — Threat Mitigation & Defense Generation**

```bash
python phase5_mitigation.py
```

**Phase 6 — Visualization Generation**

```bash
python phase6_visuals.py
```

---

## 🛠️ Running the Computer Networks Demonstrations

### 1. Raw PCAP Binary Packet Dissector & Flow Extractor
Dissects binary packets down to Layer 2 Ethernet, Layer 3 IPv4 (TTL), and Layer 4 TCP/UDP flags and computes 5G-NIDD flow metrics:

```bash
python pcap_flow_analyzer.py
```

### 2. Multi-Platform Network Defense Compiler
Compiles SHAP rules into **Cisco IOS Extended ACLs**, **Linux Netfilter (iptables)**, and **Snort/Suricata** rules:

```bash
python network_defense_exporter.py
```
*Outputs:*
* `cisco_defense.ios` (Ready to paste into Cisco 2911 Router in Packet Tracer)
* `iptables_rules.sh` (Ready to deploy on Linux edge gateways)
* `suricata_5g.rules` (Importable into Snort / Suricata)

### 3. Live 5G UPF Real-Time Intrusion Monitor
Streams live simulated flows through the 5G Core N3/N6 interface, verifying sub-millisecond detection and SLA compliance:

```bash
python live_upf_ids.py 20
```

### 4. Cisco Packet Tracer Simulation Lab
Follow the full step-by-step setup in [cisco_packet_tracer_guide.md](cisco_packet_tracer_guide.md) to build the 5G topology, configure router interfaces, apply the generated ACLs, and verify dropped attack packets in Simulation Mode.

> **Note:** Each phase may depend on data or outputs generated by earlier phases. Verify the input paths and execution order defined in the scripts before running the complete pipeline.

---

## 📁 Dataset Requirements

The project uses `Combined.csv` as its primary dataset, as described in the project configuration.

Because the dataset exceeds GitHub's file size limit, it is excluded through `.gitignore`.

Before running the pipeline:

1. Obtain the dataset from its authorized source.
2. Place `Combined.csv` in the location expected by `phase1_ingestion.py`.
3. Verify that the dataset columns and format match the preprocessing logic.
4. Confirm that the file is accessible before executing the pipeline.

**Important:** The dataset is not included in this repository. Add the dataset source or instructions for obtaining access if permitted.

---

## 🔮 Future Enhancements

- **Real-Time Intrusion Detection:** Integrate network traffic streaming for continuous monitoring.
- **Advanced Deep Learning Models:** Explore LSTM and Transformer-based architectures for temporal attack pattern analysis.
- **Interactive Monitoring Dashboard:** Visualize detection results, traffic patterns, and model performance through a dashboard.
- **Enhanced Evaluation:** Compare models using precision, recall, F1-score, confusion matrices, and other suitable metrics.
- **Automated Alerting:** Explore integrations that notify operators about suspicious network activity.
- **Deployment:** Evaluate the pipeline in realistic test environments to understand its practical limitations.

---

## ⚠️ Disclaimer

This project is intended for educational and research purposes. Its effectiveness depends on the dataset, preprocessing methods, model configuration, and evaluation methodology. The system should be thoroughly validated before any consideration for operational network security use.

---

<p align="center">
  <b>🛡️ Machine Learning for 5G Network Security</b>
  <br>
  <sub>Detect • Analyze • Explain • Improve</sub>
</p>
