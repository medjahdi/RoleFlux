# 🚀 MASTER PROJECT CONTEXT: RoleFlux (Cloud Detection & Response)

## 1. 👤 Developer Profile & Career Context
*   **Name:** Mohamed Medjahdi
*   **Role:** Cyber Security Engineer (SOC, OffSec, Automation) based in Algeria.
*   **Target Goal:** Securing 100% remote Senior B2B Contracts & achieving Google Developer Expert (GDE) status in Cloud Security / Machine Learning.
*   **Background:** 
    *   Extensive SOC experience across 30+ enterprise environments (SIEM, Threat Hunting, Incident Response).
    *   Offensive Security & Penetration Testing.
    *   Low-level systems engineering (Engineered a custom Linux OS from scratch - *Fennec OS*).
    *   Python/Bash security automation (Creator of *PhishGuard*, an AI-powered Threat Intel tool, and *OmniScan*, a Go-based infra scanner).
*   **The Narrative:** My profile bridges the gap between low-level OS mechanics, offensive security, and modern cloud-native defense. I build production-grade security engineering platforms, not just basic scripts.

---

## 2. 🛡️ The Project: RoleFlux
**Tagline:** AI-Powered GCP Cloud Detection & Response (CDR) Platform.

### The Core Problem
Enterprise Security Operations Centers (SOCs) suffer from massive alert fatigue. When a cloud administrator makes an IAM change in Google Cloud (e.g., granting `roles/owner`), GCP generates a massive, unreadable JSON Audit Log. Analysts either ignore these logs or spend hours parsing them manually, leading to missed privilege escalation attacks.

Current open-source tools (like Prowler or Checkov) are *static* scanners. There is a lack of real-time, event-driven, serverless Cloud Detection & Response (CDR) tools for GCP.

### The Solution (RoleFlux)
A 100% serverless, event-driven CDR platform deployed via Terraform. It intercepts real-time IAM changes, runs them through a deterministic Python detection engine, maps them to MITRE ATT&CK, and then uses Vertex AI (Gemini) as a virtual SOC analyst to write a human-readable investigation report sent directly to Slack.

---

## 3. 🧠 Architectural Philosophy (CRITICAL)
**"Detection Engine First, Gemini Second."**
RoleFlux is NOT just an "AI Wrapper" that sends raw logs to Gemini and asks "Is this bad?" (which causes hallucinations and proves nothing to recruiters). 

Instead, it follows a strict Security Engineering pipeline:
1.  **Deterministic Rules:** The Python engine first evaluates the log against hardcoded SOC rules (e.g., `External Principal + Production Project + Owner Role = CRITICAL`).
2.  **Risk Scoring:** The engine generates a numeric Risk Score (0-100) based on Identity Risk, Privilege Risk, and Resource Criticality.
3.  **MITRE Mapping:** The engine maps the event to specific MITRE ATT&CK techniques (e.g., `T1098 - Account Manipulation`).
4.  **AI Investigation (Gemini):** ONLY THEN is the structured output (Risk Score, MITRE mapping, extracted actors) passed to Gemini. Gemini's job is purely to synthesize this structured data into a concise, human-readable SOC Incident Report with recommended response actions.

---

## 4. ⚙️ Technical Architecture & Stack
*   **Language:** Python 3.11+
*   **Infrastructure as Code:** Terraform
*   **Cloud Provider:** Google Cloud Platform (GCP)
*   **The Serverless Pipeline:**
    *   **GCP Cloud Audit Logs:** Captures Admin Activity.
    *   **Log Router Sink:** Filters for IAM events (e.g., `SetIamPolicy`) to reduce noise.
    *   **Cloud Pub/Sub:** Acts as the event bus/shock absorber.
    *   **Cloud Functions (Python):** The compute layer housing the Detection Engine and AI logic.
    *   **Vertex AI (Gemini Flash):** The LLM generating structured JSON investigation reports.
    *   **Slack Webhook:** The final alerting destination.

---

## 5. 📁 Target Repository Structure
We are building this to enterprise standards to impress recruiters and the GDE committee. The repo must look like a professional security product.

```text
RoleFlux/
├── terraform/               # IaC to deploy Pub/Sub, Log Sinks, Cloud Functions
├── src/
│   ├── main.py              # Cloud Function entry point
│   ├── detection/           # Deterministic rules (risk scoring, MITRE mapping)
│   ├── ai/                  # Vertex AI / Gemini integration
│   ├── models/              # Pydantic data models for structured JSON
│   └── alerting/            # Slack webhook formatting
├── tests/                   # Unit tests for the detection engine
├── attack-simulator/        # Python scripts to generate fake attacks (Purple Teaming)
├── requirements.txt
└── README.md
```

---

## 6. 🚀 Phase 1 Goal (The Immediate Request)
We are currently in Phase 1 (V1). 
Our immediate goal is to scaffold the project structure and build the foundational **Detection Engine** (the deterministic Python logic) and the **Attack Simulator** (so we can generate fake JSON Audit Logs locally without needing to spin up GCP just yet). We want to test the pipeline locally first before writing the Terraform.
