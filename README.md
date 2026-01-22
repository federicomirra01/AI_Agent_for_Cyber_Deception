AI Agent for Cyber Deception: Dynamic Honeynet Management

This repository contains the source code and benchmarking infrastructure for an autonomous AI-driven system designed to manage dynamic honeynets. Based on the thesis "Towards Autonomous Cyber Deception: An AI Agent for Dynamic Honeynet Management", the project aims to replace static host exposure with an adaptive, agentic architecture that maximizes threat intelligence gain.
Project Overview

Traditional honeypots are often static and easily bypassed by sophisticated attackers. This system utilizes a multi-agent AI architecture to autonomously:

    Analyze Traffic: Processes real-time Intrusion Detection System (IDS) alerts from Suricata to understand attacker intent.

    Infer Attack Graphs: Accurately maps out compromised hosts and exploited services with up to 96% accuracy.

    Shape the Attack Surface: Dynamically adjusts host exposure and deploys decoys based on the attacker's progress to sustain engagement.

    Optimize Resources: Minimizes unnecessary exposure of vulnerable services while maximizing information gain.

Repository Structure

The repository is organized into two main sub-systems:
1. MultiAgent System (/MultiAgent)

The core reasoning engine built using Python and orchestration frameworks like LangGraph.

    src/nodes/: Individual agents responsible for network gathering, exposure management, and exploitation inference.

    src/prompts/: Instructions and reasoning logic for the AI agents.

    src/benchmark/: Tools to run simulations and collect performance metrics such as Exposure Efficiency.

2. Benchmarking Environment (/Benchmark)

A containerized infrastructure to simulate real-world attacks.

    firewallContainer/: A Suricata-based IPS that serves as the "eyes" of the system, providing alerts to the agents.

    attackerContainer/: Automated scripts that execute Proof of Concepts (PoCs) for known CVEs (e.g., Struts, GitLab, Docker RCE).

    vulnerableContainers/: A library of vulnerable targets and deception decoys (CVE-2018-12613, CVE-2021-22205, etc.) used to populate the simulation network.

    deploy/: Scripts for initializing, restarting, and cleaning up the simulation environment.

Technology Stack

    Logic & Orchestration: Python, LangGraph, LangChain.

    Virtualization: Docker & Docker Compose.

    Security Monitoring: Suricata IDS/IPS.

    Attacker Simulation: Python-based PoC exploits for various CVEs.

Getting Started

    Environment Setup: Ensure Docker and Python 3.x are installed.

    Infrastructure Initialization: Use scripts in Benchmark/deploy/ to start the firewall and target network.

    Agent Activation: Run the multi-agent graph located in MultiAgent/src/graph.py to begin autonomous monitoring and management.

    Benchmarking: Execute MultiAgent/src/benchmark/benchmark.py to run automated attack scenarios and generate reports.
