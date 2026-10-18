# CareShield AI — Demo & Pitch Script

## 1. Team & Project Introduction (0:00 - 0:30)
- "Hello, we are presenting CareShield AI for the IBM Z Datathon 2026, competing in Theme 2: AI Secured."
- **Team Roles**:
  - Full-Stack & Mainframe Deployment: Lead Machine Learning Engineer & Cloud Architect.
  - Security Architecture & Models: Backend AI Systems Engineer.
- **Beneficiary Population**: Directly targets 5,000+ mid-sized regional hospital networks and healthcare providers managing over 25 million sensitive electronic health records (EHR) who face regulatory compliance exposure under HIPAA.

## 2. Live LinuxONE Environment (0:30 - 1:00)
- "Our entire solution is running live on an IBM LinuxONE Community Cloud s390x mainframe instance at 148.100.98.173."
- [Show terminal / system status endpoint]: Point out the live s390x environment, FastAPI health response, and active hybrid AI stack.

## 3. Scenario Demonstration: Suspicious Mass Access & IBM Granite (1:00 - 2:00)
- Execute the **Suspicious Mass Access** scenario.
- Highlight the **Predictive Model**: scikit-learn IsolationForest flags the unusual query pattern and metadata spike.
- Highlight **IBM Granite LLM Reasoning**: Show the incident alert card. Explain how IBM Granite takes the numeric anomaly score and metadata signals to author an explainable security narrative in plain English for the analyst.

## 4. Scenario Demonstration: Unauthorized Export Block (2:00 - 2:40)
- Execute the **Unauthorized Export** scenario (simulated exfiltration).
- Demonstrate the zero-trust application gate stopping the export with a null payload and raising a critical incident.

## 5. Summary & Technical Impact (2:40 - 3:00)
- "By coupling scikit-learn predictive detection with IBM Granite generative reasoning on LinuxONE's enterprise architecture, CareShield AI proves that healthcare can achieve zero-trust patient data security with complete AI explainability.