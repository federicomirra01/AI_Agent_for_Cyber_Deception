#!/bin/bash

# Removing gateway and attacker container
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/attackerContainer && docker compose down -v && sudo /home/federico/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/attackerContainer/cleanup_logs.sh && docker compose up -d
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/firewallContainer && docker compose down -v && docker compose up -d

# removing vulnerable containers
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/vulnerable/xdebug-rce && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/vulnerable/docker/unauthorized-rce && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/vulnerable/struts2/s2-057 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/vulnerable/gitlab/CVE-2021-22205 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/decoys/activemq/CVE-2015-5254 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/decoys/bash/CVE-2014-6271 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/decoys/CVE-2013-4547 && docker compose down -v
cd ~/Desktop/Thesis/AI_Agent_for_Cyber_Deception/Benchmark/vulnerableContainers/decoys/CVE-2024-36401 && docker compose down -v
