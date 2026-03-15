<h1 align="center">Sentinel-JIT</h1>
<p align="center">
<b>Autonomous Just-In-Time Deception Security System</b>
</p>
<p align="center">
<img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white"/>
<img src="https://img.shields.io/badge/AI-Google%20Gemini-F9AB00?style=for-the-badge&logo=google&logoColor=white"/>
<img src="https://img.shields.io/badge/Project-Hackathon%20Prototype-6A5ACD?style=for-the-badge"/>
</p>

**Sentinel-JIT** is a cybersecurity prototype that studies attackers instead of immediately blocking them.

Traditional systems block threats instantly, which prevents defenders from understanding attacker intent. Sentinel-JIT deploys a controlled decoy environment when suspicious activity is detected, allowing the attacker to continue interacting while their behavior is logged and analyzed.

The system then generates structured intelligence reports describing the attacker’s activity and objectives.

# How It Works ?

The system simulates a modern cyber-defense workflow.
1.	Suspicious login attempts are detected.
2.	A risk scoring engine evaluates threat severity.
3.	If the risk threshold is exceeded, a decoy environment is triggered.
4.	The attacker’s commands are logged and analyzed.
5.	AI classification generates an incident report describing attack stages.

This approach prioritizes threat intelligence collection rather than immediate blocking.

# Dashboard Features

The Streamlit dashboard provides:

**• Threat Overview**
Displays source IP, failed login count, command activity, risk score, and decoy trigger status.

**• Command Timeline**
Interactive table showing attacker commands and classified attack stages.

**• AI Attack Analysis**
Narrative report describing attacker behavior.

**• Incident Report Export**
Downloadable report summarizing the attack session.

# Future Improvements

Possible directions for extending the system:

1. Real SSH or web-server log ingestion
2. Real-time monitoring dashboard
3. Geo-IP attacker location mapping
4. Multi-attacker session tracking
5. Automated PDF incident reports