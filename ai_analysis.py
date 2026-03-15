# =============================================================================
# ai_analysis.py
# Sentinel-JIT - Autonomous Just-In-Time Deception Security System
# =============================================================================
#
# PURPOSE:
#   This module simulates an AI-powered threat intelligence system.
#   It reads attacker command events from logs.json, classifies each command
#   into a known attack stage, and generates a human-readable behavior report.
#
# IMPORTANT:
#   This module does NOT generate events and does NOT calculate risk scores.
#   It only interprets what the attacker did once inside the decoy environment.
#
# ARCHITECTURE FLOW:
#   attack_simulator.py -> logs.json -> risk_engine.py
#   -> ai_analysis.py -> report
#
# RUN WITH:
#   python ai_analysis.py
#
# =============================================================================

import json
import os
from typing import Dict, List, Optional

# Load environment variables from .env file automatically.
# This is how the GEMINI_API_KEY set in .env reaches the program.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed — env vars must be set manually

# google-genai is an optional dependency.
# If installed and GEMINI_API_KEY is set, LLM reports are enabled.
# Otherwise the system falls back to rule-based reports silently.
try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

LOG_FILE = "logs.json"

# ---------------------------------------------------------------------------
# STAGE CLASSIFICATION MAP
# ---------------------------------------------------------------------------
# Maps each attack stage name to a list of keywords.
# If any keyword appears inside a command string, it belongs to that stage.
# Stages are checked in order - the first match wins.
#
# These stages are loosely based on the MITRE ATT&CK framework,
# simplified for beginner readability.
# ---------------------------------------------------------------------------

STAGE_KEYWORDS = {
    "Reconnaissance": ["whoami", "id", "uname", "hostname"],
    "Discovery": ["ls", "cd", "find", "ps", "netstat", "ifconfig"],
    "Credential Access": [
        "cat passwords", "cat /etc/passwd", "cat /etc/shadow"
    ],
    "Malware Deployment": ["wget", "curl", "ftp", "scp"],
    "Privilege Escalation": ["sudo", "su", "chmod", "useradd", "chown"],
}


# ---------------------------------------------------------------------------
# FUNCTION 1: load_logs
# ---------------------------------------------------------------------------
def load_logs(filepath: str = LOG_FILE) -> List[Dict[str, str]]:
    """
    Reads logs.json and returns all security events as a list.

    Returns an empty list if the file is missing or empty, so the
    rest of the program continues safely without crashing.

    Args:
        filepath (str): Path to the JSON log file.

    Returns:
        list[dict]: A list of event dictionaries.
    """

    try:
        with open(filepath, "r") as f:
            content = f.read().strip()

            if not content:
                return []

            return json.loads(content)

    except FileNotFoundError:
        print(
            f"[WARNING] {filepath} not found. "
            "Run attack_simulator.py first."
        )
        return []


# ---------------------------------------------------------------------------
# FUNCTION 2: extract_attacker_commands
# ---------------------------------------------------------------------------
def extract_attacker_commands(
    events: List[Dict[str, str]]
) -> List[str]:
    """
    Filters the full event list and returns only attacker command strings.

    We only care about events where type = "attacker_command".
    We extract just the "command" string (not the full dict) because
    that is all the classifier needs.

    Args:
        events (list[dict]): All events loaded from logs.json.

    Returns:
        list[str]: A list of command strings, in the order they were run.
    """

    commands = []

    for event in events:
        if event.get("type") == "attacker_command":
            commands.append(event.get("command", ""))

    return commands


# ---------------------------------------------------------------------------
# FUNCTION 3: classify_command
# ---------------------------------------------------------------------------
def classify_command(command: str) -> str:
    """
    Classifies a single shell command into an attack stage.

    Checks whether any keyword from STAGE_KEYWORDS appears in the command.
    The check is case-insensitive so "WHOAMI" and "whoami" both match.

    If no keyword matches, the stage is labeled "Unknown".

    Args:
        command (str): The shell command to classify.

    Returns:
        str: The name of the attack stage (e.g. "Reconnaissance").
    """

    command_lower = command.lower()

    for stage, keywords in STAGE_KEYWORDS.items():
        for keyword in keywords:
            if keyword in command_lower:
                return stage

    return "Unknown"


# ---------------------------------------------------------------------------
# FUNCTION 4: analyze_attack
# ---------------------------------------------------------------------------
def analyze_attack(commands: List[str]) -> List[Dict[str, str]]:
    """
    Iterates through all attacker commands and classifies each one.

    Builds a list of result dictionaries, one per command, that pair the
    command text with its classified attack stage.

    Args:
        commands (list[str]): The list of command strings to analyse.

    Returns:
        list[dict]: A list like:
                    [
                      {"command": "whoami", "stage": "Reconnaissance"},
                      {"command": "ls",     "stage": "Discovery"},
                      ...
                    ]
    """

    analysis = []

    for command in commands:
        stage = classify_command(command)
        analysis.append({"command": command, "stage": stage})

    return analysis


# ---------------------------------------------------------------------------
# FUNCTION 5 (NEW): generate_llm_report
# ---------------------------------------------------------------------------
def generate_llm_report(
    commands: List[str],
    api_key: Optional[str] = None
) -> Optional[str]:
    """
    Sends the attacker command list to the Google Gemini API and returns
    an AI-generated cybersecurity incident report.

    This function is OPTIONAL. If the API key is missing, or if the
    google-generativeai package is not installed, or if the API call
    fails for any reason, it returns None so the caller can fall back
    to the rule-based generate_report() instead.

    The API key is read from:
      1. The 'api_key' argument (if provided directly).
      2. The GEMINI_API_KEY environment variable.

    Args:
        commands (List[str]): The list of attacker shell commands.
        api_key  (str, optional): Gemini API key. Reads from env if None.

    Returns:
        str  : The Gemini-generated report text, or
        None : If LLM is unavailable or the call fails.
    """

    # Step 1: Check that the google-generativeai package is installed.
    if not GENAI_AVAILABLE:
        return None

    # Step 2: Resolve the API key.
    # Re-load .env here with override=True so we always pick up the latest
    # key even if the environment was set before this function was called.
    try:
        from dotenv import load_dotenv as _lde
        _lde(override=True)
    except ImportError:
        pass
    resolved_key = api_key or os.environ.get("GEMINI_API_KEY", "")
    if not resolved_key:
        # No API key found — silently return None to trigger fallback.
        return None

    # Step 3: Build a clear, focused prompt for Gemini.
    command_list = "\n".join(f"  - {cmd}" for cmd in commands)
    prompt = (
        "You are a cybersecurity analyst. "
        "An attacker was observed running the following shell commands "
        "inside a honeypot (decoy) environment:\n\n"
        + command_list
        + "\n\nAnalyze this attacker command sequence and produce a "
        "structured cybersecurity incident report covering:\n"
        "1. Attack stages observed (e.g. Reconnaissance, Discovery).\n"
        "2. What the attacker was trying to achieve at each stage.\n"
        "3. Overall attacker objective.\n"
        "4. Recommended defensive actions.\n"
        "Keep the report concise and beginner-friendly."
    )

    # Step 4: Call the Gemini API. Catch all errors so we can fall back.
    try:
        client = genai.Client(api_key=resolved_key)
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return str(response.text)

    except Exception:  # noqa: BLE001
        # Any API failure (bad key, quota, network) falls back to
        # the rule-based report - the user sees no error.
        return None


# ---------------------------------------------------------------------------
# FUNCTION 6: generate_report
# ---------------------------------------------------------------------------
def generate_report(analysis: List[Dict[str, str]]) -> str:
    """
    Produces a human-readable plain-English attack behavior report.

    The report covers:
      - How many commands were run in total.
      - Which attack stages were observed.
      - Specific commands linked to each stage.
      - A conclusion about the attacker's likely objective.

    Args:
        analysis (list[dict]): Output of analyze_attack() - list of
                               {command, stage} dicts.

    Returns:
        str: The full report as a multi-line string.
    """

    if not analysis:
        return "No attacker commands found. Cannot generate a report."

    total_commands = len(analysis)

    # Build a mapping of stage -> list of commands seen in that stage.
    stage_commands: Dict[str, List[str]] = {}

    for item in analysis:
        stage = item["stage"]
        command = item["command"]

        if stage not in stage_commands:
            stage_commands[stage] = []

        stage_commands[stage].append(command)

    # Collect unique stages in the order they first appeared.
    seen_stages: List[str] = []
    for item in analysis:
        if item["stage"] not in seen_stages:
            seen_stages.append(item["stage"])

    # Build the report as clean paragraphs — no separator lines.
    stages_str = ", ".join(seen_stages)

    report = "Attack Analysis Report\n\n"
    report += (
        "Commands analysed: " + str(total_commands)
        + "\nStages detected: " + stages_str + "\n\n"
    )
    report += "Narrative Summary\n\n"

    # Reconnaissance stage
    if "Reconnaissance" in stage_commands:
        cmds = ", ".join(stage_commands["Reconnaissance"])
        report += (
            "The attacker began with Reconnaissance commands ("
            + cmds
            + ") to identify the current user, system "
            "privileges, and OS version.\n"
        )

    # Discovery stage
    if "Discovery" in stage_commands:
        cmds = ", ".join(stage_commands["Discovery"])
        report += (
            "\nThey then explored the file system using "
            "Discovery commands ("
            + cmds
            + ") to locate interesting files and directories.\n"
        )

    # Credential Access stage
    if "Credential Access" in stage_commands:
        cmds = ", ".join(stage_commands["Credential Access"])
        report += (
            "\nThe attacker attempted to access sensitive "
            "credential-related files ("
            + cmds
            + "), indicating a possible credential "
            "harvesting attempt.\n"
        )

    # Malware Deployment stage
    if "Malware Deployment" in stage_commands:
        cmds = ", ".join(stage_commands["Malware Deployment"])
        report += (
            "\nA Malware Deployment action was observed ("
            + cmds
            + "). This suggests the attacker tried to download "
            "malicious tools or payloads onto the system.\n"
        )

    # Privilege Escalation stage
    if "Privilege Escalation" in stage_commands:
        cmds = ", ".join(stage_commands["Privilege Escalation"])
        report += (
            "\nPrivilege Escalation was attempted ("
            + cmds
            + "), indicating the attacker tried to gain "
            "superuser (root) access.\n"
        )

    # Unknown stage
    if "Unknown" in stage_commands:
        cmds = ", ".join(stage_commands["Unknown"])
        report += (
            "\nSome commands could not be classified ("
            + cmds
            + "). These may require manual investigation.\n"
        )

    # Conclusion
    report += "\nConclusion\n\n"
    report += (
        "This pattern of behavior is consistent with a targeted "
        "intrusion attempt. The attacker followed a methodical "
        "kill-chain: gathering system information, exploring the "
        "environment, harvesting credentials, and attempting to "
        "escalate privileges. This is characteristic of a "
        "credential harvesting and system compromise attempt.\n\n"
    )
    report += (
        "Recommended action: Escalate to the Security "
        "Operations Center (SOC).\n"
    )

    return report


# ---------------------------------------------------------------------------
# FUNCTION 6: main
# ---------------------------------------------------------------------------
def main():
    """
    Orchestrates the full analysis pipeline:

      1. Load all events from logs.json.
      2. Extract attacker command strings.
      3. Classify each command into an attack stage.
      4. Print the per-command classification table.
      5. Print the full narrative report.
    """

    print()
    print("AI Analysis  —  classifying attack commands")
    print()

    # Step 1: Load events.
    events = load_logs()

    if not events:
        print("No events to analyse.")
        return

    # Step 2: Extract attacker commands.
    commands = extract_attacker_commands(events)
    print(f"  {len(commands)} attacker commands found.")
    print()

    # Step 3: Classify each command.
    analysis = analyze_attack(commands)

    # Step 4: Print the per-command classification table.
    print(f"  {'Command':<42} Stage")
    print(f"  {'-'*40}")
    for item in analysis:
        print(f"  {item['command']:<42} {item['stage']}")
    print()

    # Step 5: Generate the attack report.
    # Try the Gemini LLM report first.
    # If the API key is missing or the call fails, use the rule-based report.
    llm_report = generate_llm_report(commands)

    if llm_report:
        print("[LLM] Gemini AI report generated.")
        print()
        print(llm_report)
        report = llm_report
    else:
        # No API key set or LLM unavailable — fall back silently.
        print("[INFO] Gemini API key not set or unavailable.")
        print("[INFO] Using rule-based report instead.")
        print()
        report = generate_report(analysis)
        print(report)

    # Return analysis and report so app.py can use them directly.
    return {
        "analysis": analysis,
        "report": report
    }


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
