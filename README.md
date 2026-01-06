# 🛡️ CyberSentinel

### AI-Powered Network Intrusion Detection System (NIDS)

**CyberSentinel** is a Streamlit-based web application for real-time
network intrusion detection using machine learning. It classifies
network traffic as **benign or malicious** using a **Random Forest
classifier** and provides an interactive SOC-style dashboard with visual
analytics, logs, and alerting mechanisms.

------------------------------------------------------------------------

## ✨ Key Features

-   **AI-Based Intrusion Detection**\
    Real-time classification of network traffic using ML models

-   **Multi-Class Attack Detection**\
    Supports detection of attacks such as DDoS, Port Scan, Brute Force,
    etc.

-   **Confidence Scoring**\
    Displays probability-based prediction confidence

-   **Interactive SOC Dashboard**\
    Live traffic visualization, attack distribution, and confusion
    matrix

-   **Alerting System**\
    In-app alerts with optional SMTP email notifications

-   **Logging & Export**\
    Filterable detection logs with export support

-   **Traffic Simulation**\
    Built-in synthetic traffic generator for testing and demos

-   **Model Retraining**\
    Train models on-demand using sample or real datasets

------------------------------------------------------------------------

## 📁 Project Structure

    CyberSentinel/
    │
    ├── nids_main.py        # Main Streamlit application
    ├── requirements.txt   # Python dependencies
    ├── data/              # Sample datasets
    ├── model/             # Trained ML models
    ├── logs/              # Detection logs
    └── config/            # SMTP / alert configuration

------------------------------------------------------------------------

## 🚀 Quick Start

### Prerequisites

-   Python 3.8 or higher\
-   pip\
-   Git

### Installation & Setup

``` bash
git clone https://github.com/yourusername/CyberSentinel.git
cd CyberSentinel
python -m venv venv
```

Activate virtual environment:

**Linux / macOS**

``` bash
source venv/bin/activate
```

**Windows**

``` powershell
.\venv\Scripts\Activate.ps1
```

Install dependencies:

``` bash
pip install -r requirements.txt
```

Run the application:

``` bash
streamlit run nids_main.py
```

Access the app at:\
👉 http://localhost:8501

------------------------------------------------------------------------

## 🏋️ Training & Usage

-   Train the model via **Sidebar → Train Model Now**
-   Load CIC-IDS2017 dataset or generate synthetic traffic
-   Monitor:
    -   Live traffic metrics
    -   Attack classification results
    -   Detection logs and alerts
-   Export logs for offline analysis

------------------------------------------------------------------------

## ⚠️ Troubleshooting

-   **Streamlit not found**

    ``` bash
    python -m streamlit run nids_main.py
    ```

-   **Module import errors**

    ``` bash
    pip install -r requirements.txt
    ```

-   **Email alerts not working**

    -   Verify SMTP credentials in `config/`
    -   Ensure correct mail server settings

------------------------------------------------------------------------

## 🔮 Roadmap

-   Persistent database integration for logs\
-   Advanced ML models (XGBoost, Neural Networks)\
-   Real-time PCAP traffic capture\
-   REST API & SIEM integration\
-   Explainable AI (SHAP / LIME)

------------------------------------------------------------------------

## 📄 License

This project is licensed under the **MIT License**.

⚠️ **Disclaimer:**\
This system is intended for **educational and research purposes only**.\
Ensure proper authorization before monitoring real network traffic.
