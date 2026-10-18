# CareShield AI

**A Zero-Trust Patient Data Privacy Monitor built for the IBM Z Datathon 2026 (Theme 2: AI Secured)**

CareShield AI is an enterprise-grade security dashboard designed to detect, explain, and mitigate unauthorized access to sensitive healthcare records. By combining machine learning anomaly detection with generative AI reasoning, the system provides security teams with real-time, explainable alerts. The entire application is deployed on an **IBM LinuxONE (s390x)** mainframe environment to ensure maximum data sovereignty and uptime.

## 🚀 Live Demo & Submission Links

* **Live Dashboard:** `[http://148.100.98.173:5173](http://148.100.98.173:5173)` *(Requires active IBM Community Cloud VPN/access)*
* **API Documentation:** `[http://148.100.98.173:8000/docs](http://148.100.98.173:8000/docs)`
* **Demo Video:** `[Insert YouTube Link Here]`

---

## 🧠 Architecture & Tech Stack

This project uses a dual-stack architecture deployed natively on IBM infrastructure.

**Infrastructure:**

* **IBM LinuxONE Community Cloud:** Hosted natively on `s390x` architecture.
* **OS:** Ubuntu Linux (s390x)

**Artificial Intelligence:**

* **Anomaly Detection:** `scikit-learn` (IsolationForest) - Evaluates access logs in real-time to detect mass-access anomalies or exfiltration attempts.
* **Generative Explainability:** **IBM Granite 3.0** (via Hugging Face) - Translates raw anomaly data into human-readable, contextual security alerts for compliance teams.

**Backend:**

* **Framework:** FastAPI (Python 3)
* **Server:** Uvicorn

**Frontend:**

* **Framework:** React 18, Vite, TypeScript
* **Styling:** Tailwind CSS, Lucide React (Icons)

---

## ⚡ Key Features

1. **Real-Time Threat Detection:** Simulates and detects normal, suspicious, and unauthorized data export events using an Isolation Forest model.
2. **Generative Reasoning:** Leverages IBM's Granite LLM to generate plain-text summaries explaining *why* an event was flagged (e.g., "User accessed 50 records in 2 seconds, which deviates from standard baseline").
3. **Interactive Security Dashboard:** A clean, responsive React interface that polls the mainframe backend for live system health and active threat alerts.
4. **Mainframe Native:** Fully built, tested, and deployed on `s390x` architecture, demonstrating the seamless integration of modern AI web stacks with IBM LinuxONE.

---

## 🛠️ Setup & Installation

If you wish to run this project locally or deploy it to your own LinuxONE instance, follow these steps.

### Prerequisites

* Python 3.9+
* Node.js & npm
* Git

### 1. Backend Setup (FastAPI)

```bash
# Navigate to the backend directory
cd backend

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the backend server (runs on port 8000)
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000

```

### 2. Frontend Setup (React/Vite)

```bash
# Navigate to the frontend directory (in a new terminal)
cd frontend

# Install dependencies
npm install

# Configure the environment
# Create a .env file and add your backend IP:
# VITE_API_URL=http://<YOUR_LINUXONE_IP>:8000

# Start the development server (runs on port 5173)
npm run dev -- --host 0.0.0.0

```

### 3. Firewall Configuration (LinuxONE)

Ensure the required ports are open to access the application remotely:

```bash
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 5173 -j ACCEPT

```

---

## 👥 Author

* **Anindo Kumar Biswas**
* **Submission:** IBM Z Datathon 2026
