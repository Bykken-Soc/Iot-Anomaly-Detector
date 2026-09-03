# IoT Anomaly Detector: Security Suite, EDR & SOAR Engine

A real-time cybersecurity telemetry monitoring platform, Security Information and Event Management (SIEM) dashboard, and autonomous remediation (SOAR) tool designed to monitor, audit, and secure IoT endpoints and containers over SSH.

---

## Table of Contents

* [Key Features]
* [System Architecture]
* [Prerequisites]
* [Installation & Setup]
* [Simulating an IoT Endpoint (Docker)]
* [Running the Application]
* [Dashboard Usage]
* [Simulating Attacks & Testing SOAR]
* [Troubleshooting]

---

## Key Features

* Real-Time Telemetry & Hardware Auditing: Polls CPU utilization (`/proc/stat` or `top`) and network packet flow (`/proc/net/dev`) asynchronously without freezing the user interface.


* Automated Device Provisioning (DevOps Bootstrap): Automatically connects to newly registered devices via SSH to deploy and verify the open-source ClamAV antivirus engine[cite: 3].
* Operating System Integrity Mapping: Audits critical system configurations, including shadow passwords (`/etc/shadow`), user identities (`/etc/passwd`), system kernels, and host routing descriptors (`/etc/hosts`) for rootkit signatures.


* Integrated SIEM Logs Engine: Tracks security events locally per device and aggregates logs globally with interactive, multi-select severity/status filters using vectorized Pandas filtering.


* Autonomous Remediation Orchestration (SOAR): Detects insecure file permissions or unauthorized network route insertions and automatically restores secure baselines (e.g., executing `chmod 600 /etc/shadow` and purging malicious redirect lines)[cite: 1, 3].
* Interactive Web Terminal: Secure live shell execution channel built directly into the dashboard for administrative containment and incident response.



---

## System Architecture

* Frontend / UI: Streamlit (with reactive `@st.fragment` routines)[cite: 1, 3].
* Data Processing: Pandas (vectorized log filtering) & NumPy.

* Remote Security Protocol: Paramiko (SSHv2 encrypted transport).

* Perimeter Sniffing (Optional): Scapy[cite: 2].
* Persistent Storage: JSON disk-backed database (`inventario.json`).

---

## Prerequisites

Ensure your system meets the following requirements before running the suite:

* Operating System: Windows 10/11, macOS, or Linux.
* Python: Python 3.10, 3.11, or 3.12 installed.
* Docker Desktop: Installed and running (if simulating virtual IoT devices locally).

---

## Installation & Setup

1. Clone or download the project files into a dedicated workspace folder:
```bash
cd "path/to/your/project-folder"

```

2. Install all required Python packages** using PowerShell or your preferred terminal:
```bash
pip install streamlit pandas numpy paramiko scapy

```

##  Simulating an IoT Endpoint (Docker)

To test the security suite locally, deploy a persistent, SSH-enabled Ubuntu container that acts as an edge IoT device (e.g., a smart camera or sensor).

### Step 1: Remove any conflicting containers

```bash
docker rm -f nuevo_nodo_iot

```

### Step 2: Deploy the persistent container

Run the following unified command in PowerShell or Terminal to spin up the container, enable SSH, and keep the service running in the foreground:

```bash
docker run -d --name nuevo_nodo_iot -p 2223:22 ubuntu:latest sh -c "apt-get update && apt-get install -y openssh-server && mkdir /var/run/sshd && ssh-keygen -A && echo 'root:secret' | chpasswd && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && /usr/sbin/sshd -D"

```

### Step 3: Verify the container status

```bash
docker ps

```

Confirm that the status shows `Up` and maps port `0.0.0.0:2223->22/tcp`.

---

## Running the Application

Launch the Streamlit dashboard on a dedicated port to prevent browser caching conflicts:

```bash
python -m streamlit run detector_total.py 

```

Once executed, open your browser and navigate to:

```text
http://localhost:8502

```

## Dashboard Usage

### 1. Register a Device

In the sidebar under **Register new device**, input the node details:

* Device name / ID: `Camara_Seguridad_02`
* Network IP address: `127.0.0.1`
* SSH port: `2223` (or `2222` if running on the default Docker port)*
* SSH username: `root`
* SSH password: `secret`
* Device profile: Select `Camera / Streaming (High traffic)` or `Smart Sensor`
* Click Save to inventory. The automated provisioning engine will connect via SSH and install ClamAV on the node[cite: 3].



### 2. Monitor Telemetry

* Telemetry and network security: Inspect real-time network throughput (pps) and CPU utilization charts alongside instant AI health diagnostics.


* SIEM incident logs center: Review alerts categorized as *Low*, *High*, *Critical*, or *Emergency*[cite: 2]. Use the multi-select filters to isolate specific security vectors.


* Host infrastructure checker: Run manual audits or launch a **ClamAV Antivirus Scan** against specific directories like `/tmp`[cite: 3].
* Interactive live terminal: Issue commands directly to the node shell (e.g., `ss -an`, `top`, or `ls -la`).


##  Troubleshooting

* **Blank Screen / Static Asset Preload Errors:**
* Perform a hard refresh in your browser with `Ctrl + F5`.
* Launch Streamlit on an alternate port using `--server.port=8502` or open the app in an Incognito window.


* **Connection Timeout to Docker:**
* Ensure Docker Desktop is active.
* Verify the container is running with `docker ps`.
* Ensure host keys exist on the target by running:
```bash
docker exec -it nuevo_nodo_iot ssh-keygen -A

```




* **No `netstat` available inside container:**
* Modern stripped Linux containers use `ss` instead. Run `ss -an` or `ss -tpn` in the interactive terminal to inspect open sockets.
