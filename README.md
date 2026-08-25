# 🛡️ LARP: AI-Driven EDR / XDR Manager

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![React](https://img.shields.io/badge/frontend-React-61DAFB?logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)

**LARP (LAN Active Response Platform)** is an advanced, lightweight Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR) management system. It is designed to monitor LAN environments, detect anomalous behaviors using intelligent risk scoring, and execute automated active responses (such as network isolation) to prevent ransomware and lateral movement.

Unlike traditional signature-based antiviruses, this system focuses on **Behavioral Anomaly Detection** (e.g., unusual parent-child process relationships, LOLBins abuse, credential dumping attempts, and C2 beaconing) to minimize false positives and maximize threat hunting efficiency.

---

## ✨ Key Features

- **🧠 Behavioral Anomaly Detection:** Identifies threats based on TTPs (Tactics, Techniques, and Procedures) such as abnormal CPU spikes, unauthorized process injections, and malicious registry modifications.
- **⚡ Automated Active Response:** Dynamically isolates compromised agents based on a multi-factor Risk Score mechanism.
- **🌳 Interactive Process Tree:** Visualizes the complete execution hierarchy of endpoints, allowing admins to pinpoint root causes and terminate (SIGKILL) malicious processes remotely.
- **🕸️ Network Topology & Flow Analysis:** Maps LAN connections, tracks active bandwidth, and detects lateral movement or C2 communication.
- **🔔 Real-time Notifications & Telegram Integration:** Delivers instant alerts with interactive inline buttons (e.g., "Isolate", "Ignore") directly to Telegram.
- **📄 Automated Monthly Reporting:** Generates comprehensive PDF reports summarizing network health, blocked IPs, and resolved incidents.
- **🛡️ Whitelisting & Threat Intel:** Reduces false positives by maintaining robust process/agent whitelists and integrating with external Threat Intelligence feeds.

---

## 📸 Screenshots

*(Replace the placeholder links below with your actual image URLs)*

### 1. Centralized Dashboard
*Overview of network health, active agents, and recent critical alerts.*
![Dashboard Preview](![alt text](asset/dashboard.png))

### 2. Process Tree & Root Cause Analysis
*Deep dive into host processes, highlighting suspicious parent-child activities.*
![Process Tree Preview]([ĐƯỜNG-DẪN-ẢNH-PROCESS-TREE-CỦA-BẠN])

### 3. Risk Assessment & Auto-Isolation
*Multi-factor risk scoring engine evaluating threats before triggering automated isolation.*
![Risk Assessment Preview]([ĐƯỜNG-DẪN-ẢNH-RISK-ASSESSMENT-CỦA-BẠN])

### 4. Network Topology 
*Live visualization of active agent connections and network flows.*
![Network Topology Preview]([ĐƯỜNG-DẪN-ẢNH-NETWORK-TOPOLOGY-CỦA-BẠN])

---

## 🗺️ System Modules

The platform includes a comprehensive web interface divided into the following modules:

*   **`/` (Dashboard):** High-level metrics and system overview.
*   **`/agents`:** Manage, monitor, and deploy lightweight endpoint agents.
*   **`/alerts` & `/incidents`:** Track real-time security alerts and manage the incident response lifecycle.
*   **`/process`:** Inspect complete execution tree hierarchies of target machines.
*   **`/network`:** Visualize LAN topology and track suspicious network flows.
*   **`/risk`:** Configure and monitor the Behavioral Risk Assessment engine.
*   **`/threat-intel` & `/rules/detection`:** Manage IoCs, YARA rules, and custom detection logic.
*   **`/commands`:** Dispatch and track manual execution commands sent to agents.
*   **`/whitelist`:** Define safe processes and trusted endpoints to prevent false positive isolations.
*   **`/notifications` & `/reports`:** Configure Telegram webhooks and generate PDF security reports.
*   **`/attack`:** Built-in Attack Simulation tool to validate defense mechanisms and rules.
*   **`/settings`:** Global system configurations.

---

## 🚀 Getting Started

### Prerequisites
Make sure you have [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) installed on your machine.

### Installation & Run

Setting up the entire environment (Backend, Frontend, and Database) is incredibly straightforward using Docker.

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/your-repo-name.git
   cd your-repo-name
   ```

---

## 🧪 Threat & Malware Simulation Testing

You can trigger on-demand malware behavioral simulations inside any agent container (e.g. `client1`, `client2`, `attacker`) to test the system's dynamic Risk Assessment Engine and automated isolation mechanisms:

```bash
# 1. Ransomware Simulation (creates fake encrypted files, opens port 4444, background process)
docker compose exec client1 bash /app/malware_sim/ransomware_sim.sh &

# 2. Backdoor Listener Simulation (opens backdoor socket on port 5555)
docker compose exec client1 bash /app/malware_sim/backdoor_sim.sh

# 3. Credential Dumping Simulation (simulates accessing sensitive files / dumps mock LSASS memory)
docker compose exec client1 bash /app/malware_sim/credential_dump_sim.sh

# 4. Lateral Movement SMB Scan Simulation (scans internal agents on SMB port 445)
docker compose exec client1 bash /app/malware_sim/lateral_movement_sim.sh

# 5. C2 Beaconing Simulation (sends periodic beaconing requests to C2 endpoints)
docker compose exec client1 bash /app/malware_sim/c2_communication_sim.sh
```