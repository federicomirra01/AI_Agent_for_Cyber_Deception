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

## Key Components & Locations

* **AI Prompts**: Located in `MultiAgent/src/nodes/prompts.py`. These define the reasoning logic for the Attack Inference and Exposure Management nodes.

* **Attack PoCs**: Located in `Benchmark/attackerContainer/scripts/`. This directory contains the automated exploit scripts (e.g., exploit_gitlab.py for CVE-2021-22205).

* **IDS Alerts**: Suricata logs are generated in `Benchmark/firewallContainer/log/suricata/eve.json`. The AI agent consumes an aggregated version of these JSON alerts to trigger reasoning cycles.
Example: 

```
{"timestamp":"2026-02-08T18:21:57.697544+0100","flow_id":2075460149639207,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.100.2","src_port":35510,"dest_ip":"172.20.0.3","dest_port":8080,"proto":"TCP","ip_v":4,"pkt_src":"wire/pcap","community_id":"1:nOz9JtfMYGuPraWR+Hxaenu+Uvc=","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2016953,"rev":5,"signature":"ET EXPLOIT Apache Struts Possible OGNL Java Exec In URI","category":"Attempted User Privilege Gain","severity":1,"metadata":{"confidence":["Medium"],"created_at":["2013_05_31"],"signature_severity":["Major"],"tag":["Description_Generated_By_Proofpoint_Nexus"],"updated_at":["2024_03_06"]}},"ts_progress":"request_complete","tc_progress":"response_complete","http":{"hostname":"172.20.0.3","http_port":8080,"url":"/struts2-showcase/%24%7B%0A%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27bash%20shell.sh%27%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23a.getInputStream%28%29%29%29%7D/actionChain1.action","http_user_agent":"python-requests/2.32.5","http_method":"GET","protocol":"HTTP/1.1","status":302,"redirect":"/struts2-showcase//register2.action","length":0},"app_proto":"http","direction":"to_server","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":1059,"bytes_toclient":326,"start":"2026-02-08T18:21:51.679838+0100","src_ip":"192.168.100.2","dest_ip":"172.20.0.3","src_port":35510,"dest_port":8080},"payload_length":787,"payload_printable":"GET /struts2-showcase/%24%7B%0A%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23ct%3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr%3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou%3D%23cr.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ou.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23a%3D%40java.lang.Runtime%40getRuntime%28%29.exec%28%27bash%20shell.sh%27%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23a.getInputStream%28%29%29%29%7D/actionChain1.action HTTP/1.1\r\nHost: 172.20.0.3:8080\r\nUser-Agent: python-requests/2.32.5\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n","stream":1,"packet":"Mn/6IStGjt9rddSTCABFAAA0NGBAAD8GNqLAqGQCrBQAA4q2H5Dk/50qnruPjIAQAD/Q6AAAAQEICsWnolsZQ+yg","packet_info":{"linktype":1,"linktype_name":"EN10MB"}}
```

* **Vulnerable Assets**: The environment emulates real-world targets from VulnHub. Information about the attacks are located in `Benchmark/vulnerableContainers/vulnerable`. Vulnerable assets for which the attack PoC has been implemented include:

* * **GitLab Pre-Auth Remote Command Execution (CVE-2021-22205)**

* * **Struts2 S2-057 Remote Code Execution Vulnerablity (CVE-2018-11776)**

* * **Docker Remote API Unauthorized Access Leads to Remote Code Execution**

* * **PHP XDebug Remote Debugging Code Execution**

## Repository Structure

* **`MultiAgent/`**: The core AI reasoning engine.
* * `src/nodes/`: Agents for network analysis, exploitation inference, and exposure management.
* * `src/benchmark/`: Scripts for running automated simulations and performance reporting.


* **`Benchmark/`**: The containerized lab environment.
* * `attackerContainer/`: Automated scripts simulating real-world RCE exploits (CVE-2021-22205, etc.).
* * `firewallContainer/`: Suricata-based monitoring and routing.
* * `vulnerableContainers/`: A library of target services and deception decoys.
* `deploy/`: Orchestration scripts for network setup.


## Prerequisites

* **Docker & Docker Compose**
* **Python 3.9+**
* **API Configuration**: Add `.env` in the `MultiAgent/` directory and add your LLM API keys (e.g., OpenAI).

---

*Developed as part of the thesis: "Towards Autonomous Cyber Deception: An AI Agent for Dynamic Honeynet Management." (https://webthesis.biblio.polito.it/38697/)*


