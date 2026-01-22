# AI Agent for Cyber Deception

This repository contains an autonomous multi-agent system designed for **Dynamic Honeynet Management**. Based on the research "Towards Autonomous Cyber Deception," the system uses AI agents to monitor network traffic via Suricata IDS, infer attacker progress, and dynamically adjust host exposure to maximize threat intelligence while minimizing risk.

## Quick Start

Follow these steps to deploy the lab environment and run the autonomous agent.

### 1. Launch the Core Infrastructure

Deploy the firewall (IDS/IPS) and the attacker simulation environment.

**Start the Attacker and Firewall:**

```bash
# Launch the Attacker Container
cd Benchmark/attackerContainer
docker-compose up -d

# Launch the Firewall/IDS Container
cd ../firewallContainer
docker-compose up -d

```

### 2. Deploy Vulnerable Targets

Use the deployment scripts to populate the internal network with vulnerable services and decoys.

```bash
# Deploy all vulnerable containers and decoys
cd ../deploy
bash all_exploitables.sh

```

### 3. Execute Benchmarks

To evaluate system performance (inference accuracy and engagement efficiency), run the automated benchmarking suite using the jupyter notebook
```
graph.ipynb
```
## Repository Structure

* **`MultiAgent/`**: The core AI reasoning engine.
* `src/nodes/`: Agents for network analysis, exploitation inference, and exposure management.
* `src/benchmark/`: Scripts for running automated simulations and performance reporting.


* **`Benchmark/`**: The containerized lab environment.
* `attackerContainer/`: Automated scripts simulating real-world RCE exploits (CVE-2021-22205, etc.).
* `firewallContainer/`: Suricata-based monitoring and routing.
* `vulnerableContainers/`: A library of target services and deception decoys.
* `deploy/`: Orchestration scripts for network setup.



## Prerequisites

* **Docker & Docker Compose**
* **Python 3.9+**
* **API Configuration**: Add `.env` in the `MultiAgent/` directory and add your LLM API keys (e.g., OpenAI).

---

*Developed as part of the thesis: "Towards Autonomous Cyber Deception: An AI Agent for Dynamic Honeynet Management." (https://webthesis.biblio.polito.it/38697/)*


