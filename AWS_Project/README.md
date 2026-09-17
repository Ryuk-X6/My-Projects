#AWS Cloud-Native Threat Detection & SOAR Pipeline

An automated, serverless Threat Detection and Incident Response (SOAR) pipeline hosted on AWS. This system continuously monitors incoming SSH authentication logs, extracts unauthorized access attempts, enriches attacker IP addresses using real-time threat intelligence APIs, and dispatches structured alert cards to Discord.

---

## 📐 Architecture Diagram
             [ Local Machine / Attacker ]
                 (SSH Failed Attempt)
                          │
                          ▼ 
    ┌──────────────────────────────────────────────┐
    │     AWS EC2 Instance (Amazon Linux 2023)     │
    │  ───► Logged locally via secure.log          │
    │  ───► Collected by CloudWatch Unified Agent  │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────┐
    │  AWS CloudWatch Log Group:                   │
    │  📁 /aws/ec2/SSH-Auth-Logs                   │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼ 
           (Subscription Filter: "Failed password")
    ┌──────────────────────────────────────────────┐
    │     AWS Lambda: SOAR-Threat-Detector         │
    ├──────────────────────────────────────────────┤
    │  ⚙️  1. Decompress Base64 / GZIP Payload     │
    │  🔍  2. Extract Attacker IPv4 Address        │
    │  🌐  3. Query AbuseIPDB Threat Intel API v2  │
    │  📦  4. Format & Send Webhook Alert          │
    └──────────────────────┬───────────────────────┘
                           │
                           ▼ 
                    (JSON HTTPS POST)
    ┌──────────────────────────────────────────────┐
    │      Discord / Slack Notification Channel    │
    │  📢  Real-time SecOps Threat Alert Issued    │
    └──────────────────────────────────────────────┘
## ✨ Key Features

* **Real-time Log Streaming**: Uses `rsyslog` rules and `amazon-cloudwatch-agent` to forward authentication events directly to CloudWatch Logs.
* **Serverless Event-Driven Trigger**: CloudWatch Log Subscription Filters invoke AWS Lambda instantly upon log generation.
* **Payload Parsing & Decompression**: Decodes Base64 and decompresses GZIP log batches directly in Python.
* **Threat Intelligence Enrichment**: Queries **AbuseIPDB API v2** to retrieve real-time abuse confidence scores, ISP info, and country codes.
* **Automated Alerting**: Generates styled, color-coded embed notification cards sent via Webhooks.

---

## 🛠️ Tech Stack & Services

* **Cloud Services**: AWS EC2, AWS CloudWatch Logs, AWS Lambda, AWS IAM
* **Operating System**: Amazon Linux 2023
* **Programming Language**: Python 3.12 (Standard libraries: `urllib`, `gzip`, `json`, `base64`)
* **Logging Protocols**: `rsyslog`, AWS CloudWatch Agent
* **APIs & Webhooks**: AbuseIPDB API v2, Discord Webhooks

---

## 📁 Directory Structure

```text
AWS-project/
├── .gitignore              # Excludes sensitive keys, tokens, and env files
├── README.md               # Project documentation
├── src/
│   └── lambda_function.py  # AWS Lambda Python script
└── config/
    ├── cloudwatch-agent.json # AWS CloudWatch Unified Agent configuration
    └── rsyslog-sshd.conf     # System rsyslog routing rule
