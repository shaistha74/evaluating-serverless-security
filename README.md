Evaluating the Effectiveness of Terraform-Deployed AWS Serverless Architecture for Threat Detection and Compliance Automation

Project Description
This project investigates and evaluates a serverless AWS security architecture, deployed via Terraform, to detect threats and enforce compliance automatically. With the growing adoption of serverless computing, traditional security mechanisms fall short in identifying and remediating dynamic cloud threats. This research aims to fill this gap by integrating AWS-native services such as Lambda, CloudTrail, GuardDuty, AWS Config, SNS, and Security Hub in a Terraform-driven pipeline.

Core Focus:
Real-time threat detection using AWS-native tools.

Auto-remediation of misconfigurations and malicious activities.

Compliance validation using AWS Config.

Comparative evaluation against:

A traditional server-based AWS setup (deployed via CLI and Terraform).

Lavi et al. (2024)’s model that focuses only on detection, not remediation.

Objectives
1.Design and deploy a Terraform-based serverless AWS architecture for real-time security monitoring.

2.Simulate benign and malicious Lambda functions for threat testing.

3.Test against CloudGoat and AWS GuardDuty Tester scenarios including:
a.Privilege escalation
b.SSRF
c.Resource abuse

Compare:

1.Detection accuracy
2.Auto-remediation speed
3.Compliance enforcement
4.Deployment effort (manual vs automated)

Demonstrate advantages of Infrastructure as Code (IaC) for secure, scalable cloud deployments.

Architecture Overview
Serverless Architecture (Terraform-Deployed)
Lambda for detection and remediation

CloudTrail + CloudWatch for monitoring and alerting

GuardDuty for threat detection

AWS Config for compliance validation

SNS for alert distribution

Security Hub for unified threat visibility

Terraform for complete IaC-based deployment

🖥Server-Based Architectures (Baselines)
Manually deployed EC2 log monitoring setup (via CLI)

Terraform-deployed EC2-based log forwarding pipeline

Baseline comparison with Lavi et al. (2024) detection-only model

Attack Simulation Tools
CloudGoat – Simulates IAM privilege escalation, Lambda abuse, and SSRF

AWS GuardDuty Tester – Generates real GuardDuty findings for:

SSH brute-force

Port scanning

DNS exfiltration

IAM abuse

Evaluation Metrics
Metric	Description
1. Detection Accuracy	If the architecture detects each attack
2. Time-to-Detect	Time from attack initiation to alert
3. Remediation Effectiveness	Was auto-remediation successfully triggered?
4. False Positives	Are alerts relevant and valid?
5. Reproducibility	Can the setup be deployed identically in other environments?
6. Compliance Score	AWS Config rule violations before/after remediation

Tools & Technologies
Terraform – Infrastructure as Code

AWS Lambda, EC2, S3, CloudTrail, Config, SNS, CloudWatch

Amazon GuardDuty, Security Hub

CloudGoat, AWS GuardDuty Tester

Checkov – Terraform misconfiguration scanning

Project Status
Server-based architectures implemented

Terraform modules completed for server-based architecture setups

Currently need to implement serverless setup simulating benign and malicious Lambda workloads

CloudGoat and GuardDuty attack scenarios in progress

Comparative analysis and evaluation scheduled for August 2025

Research Questions
RQ1: How effective is a serverless AWS security architecture in detecting and remediating threats using AWS-native services?

RQ2: How do manual vs Terraform-deployed server-based setups compare in terms of scalability, consistency, and security?

Comparative Evaluation
Setup	                       Automation	         Remediation	 Compliance	  Threat Detection
Serverless (Terraform)	      Yes	                Yes	        AWS Config	   GuardDuty, Cloudtrail logs, SecurityHub
Server-Based (CLI)	          Manual	            No	         Partial	     Delayed
Server-Based (Terraform)	    Yes	               Limited	     AWS config   GuardDuty, Cloudtrail logs, VPC flow logs, SecurityHub
Lavi et al. (2024)	         Detection Only	     No	            No	         CloudTrail Logs

License
This project is open-source and developed solely for academic research and educational purposes. Attack simulations are performed ethically in isolated AWS environments and comply with AWS's acceptable use policies.

Acknowledgements
University of Hertfordshire – MSc Cyber Security Programme

AWS Educate – Research Account

Rhino Security Labs – CloudGoat

HashiCorp – Terraform

AWS Datasets collected from logs and synthesized by me, Documentation, and Tools
