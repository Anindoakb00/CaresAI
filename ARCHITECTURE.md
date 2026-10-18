# CareShield AI Architecture

## Overview & Datathon Track Alignment
CareShield AI is built for **IBM Z Datathon 2026 — Theme 2: AI Secured: Innovation Without Exposure**. It delivers runtime patient data access governance by pairing structured predictive anomaly detection with generative LLM reasoning, deployed natively on an IBM LinuxONE (s390x) mainframe instance.

## System Topology

```mermaid
flowchart LR
  Browser[React TypeScript UI] -->|HttpOnly Cookie + CSRF| API[FastAPI Gateway]
  API --> Auth[RBAC & Care-Team Policy]
  API --> Audit[Access Event Pipeline]
  Audit --> RuleEngine[Deterministic Risk Engine]
  Audit --> IsoForest[scikit-learn IsolationForest]
  RuleEngine --> AlertEngine[Alert & Incident Manager]
  IsoForest --> AlertEngine
  AlertEngine --> Granite[IBM Granite 3.0 LLM Reasoning]
  Granite --> DB[(SQLite / PostgreSQL)]
  API --> ExportGate[Export Policy Gate]
```