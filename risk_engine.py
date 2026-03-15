# =============================================================================
# risk_engine.py
# Sentinel-JIT — Autonomous Just-In-Time Deception Security System
# =============================================================================
#
# PURPOSE:
#   This module reads the raw security events from logs.json (produced by
#   attack_simulator.py) and analyses them to determine how suspicious the
#   observed behavior is.
#
#   It calculates a numeric risk score (0–100) and decides whether the
#   risk level is high enough to trigger a decoy (honeypot) environment.
#
# IMPORTANT:
#   This module does NOT simulate attacker actions.
#   It only reads logs and evaluates them.
#
# ARCHITECTURE FLOW:
#   attack_simulator.py → logs.json → risk_engine.py → risk score + decision
#
# RUN WITH:
#   python risk_engine.py
#
# =============================================================================

import json

# ---------------------------------------------------------------------------
# CONSTANTS — Scoring weights and thresholds
# ---------------------------------------------------------------------------

# How many risk points each failed login attempt contributes.
POINTS_PER_FAILED_LOGIN = 10

# How many risk points each attacker command contributes.
POINTS_PER_COMMAND = 5

# The maximum possible risk score.
MAX_RISK_SCORE = 100

# Risk level boundaries.
LOW_RISK_THRESHOLD    = 40   # below this  → Low risk
MEDIUM_RISK_THRESHOLD = 70   # 40–70       → Medium risk
                              # above 70    → High risk → trigger decoy

# Path to the shared log file.
LOG_FILE = "logs.json"


# ---------------------------------------------------------------------------
# FUNCTION 1: load_logs
# ---------------------------------------------------------------------------
def load_logs(filepath=LOG_FILE):
    """
    Reads logs.json and returns all stored security events as a list.

    If the file is missing or empty, returns an empty list so the rest
    of the program can continue safely.

    Args:
        filepath (str): Path to the JSON log file.

    Returns:
        list[dict]: A list of event dictionaries.
    """

    try:
        with open(filepath, "r") as f:
            content = f.read().strip()

            # If the file is empty, return an empty list.
            if not content:
                return []

            return json.loads(content)

    except FileNotFoundError:
        # logs.json hasn't been created yet (attack_simulator not run).
        print(f"[WARNING] {filepath} not found. Run attack_simulator.py first.")  # noqa: E501
        return []


# ---------------------------------------------------------------------------
# FUNCTION 2: count_failed_logins
# ---------------------------------------------------------------------------
def count_failed_logins(events):
    """
    Counts how many login attempt events ended in failure.

    A failed login is any event where:
      - "type" is "login_attempt"
      - "status" is "failed"

    Args:
        events (list[dict]): All events loaded from logs.json.

    Returns:
        int: Number of failed login attempts.
    """

    count = 0

    for event in events:
        if event.get("type") == "login_attempt" and event.get("status") == "failed":  # noqa: E501
            count += 1

    return count


# ---------------------------------------------------------------------------
# FUNCTION 3: count_attacker_commands
# ---------------------------------------------------------------------------
def count_attacker_commands(events):
    """
    Counts how many attacker command events are present in the logs.

    An attacker command is any event where:
      - "type" is "attacker_command"

    Args:
        events (list[dict]): All events loaded from logs.json.

    Returns:
        int: Number of attacker commands found.
    """

    count = 0

    for event in events:
        if event.get("type") == "attacker_command":
            count += 1

    return count


# ---------------------------------------------------------------------------
# FUNCTION 4: calculate_risk_score
# ---------------------------------------------------------------------------
def calculate_risk_score(events):
    """
    Computes a numeric risk score (0–100) based on the events in the logs.

    Scoring model:
      • Each failed login attempt adds 10 points.
      • Each attacker command adds 5 points.
      • The score is capped at 100 (cannot exceed maximum).

    Example:
      5 failed logins  →  5 × 10 = 50 points
      8 attacker cmds  →  8 ×  5 = 40 points
      Total            →       90 points (risk score = 90)

    Args:
        events (list[dict]): All events loaded from logs.json.

    Returns:
        int: The calculated risk score between 0 and 100.
    """

    failed_logins = count_failed_logins(events)
    attacker_commands = count_attacker_commands(events)

    # Apply the scoring weights.
    login_score   = failed_logins     * POINTS_PER_FAILED_LOGIN
    command_score = attacker_commands * POINTS_PER_COMMAND

    raw_score = login_score + command_score

    # Clamp the score so it never exceeds 100.
    final_score = min(raw_score, MAX_RISK_SCORE)

    return final_score


# ---------------------------------------------------------------------------
# FUNCTION 5: decoy_decision
# ---------------------------------------------------------------------------
def decoy_decision(risk_score):
    """
    Determines the risk level and whether a decoy environment should be
    triggered, based on the calculated risk score.

    Risk level rules:
      score < 40   → LOW    → no decoy
      score 40–70  → MEDIUM → no decoy (monitor closely)
      score > 70   → HIGH   → trigger decoy environment

    Args:
        risk_score (int): The calculated risk score (0–100).

    Returns:
        dict: A result dictionary containing:
              - "risk_score"      : the numeric score
              - "risk_level"      : "LOW", "MEDIUM", or "HIGH"
              - "decoy_triggered" : True if risk is HIGH, else False
    """

    # Determine the risk level based on thresholds.
    if risk_score > MEDIUM_RISK_THRESHOLD:
        risk_level      = "HIGH"
        decoy_triggered = True

    elif risk_score >= LOW_RISK_THRESHOLD:
        risk_level      = "MEDIUM"
        decoy_triggered = False

    else:
        risk_level      = "LOW"
        decoy_triggered = False

    return {
        "risk_score":      risk_score,
        "risk_level":      risk_level,
        "decoy_triggered": decoy_triggered
    }


# ---------------------------------------------------------------------------
# FUNCTION 6: main
# ---------------------------------------------------------------------------
def main():
    """
    Orchestrates the full risk evaluation pipeline:

      1. Load events from logs.json.
      2. Count failed logins and attacker commands (for display).
      3. Calculate the risk score.
      4. Determine risk level and decoy decision.
      5. Print a clear, readable summary.
    """

    print()
    print("Risk Engine  —  evaluating threat level")
    print()

    # Step 1: Load all events from the log file.
    events = load_logs()

    if not events:
        print("[INFO] No events found. Exiting.")
        return

    # Step 2: Count individual event types (for the printed summary).
    failed_logins     = count_failed_logins(events)
    attacker_commands = count_attacker_commands(events)

    print(f"[*] Total events loaded    : {len(events)}")
    print(f"[*] Failed login attempts  : {failed_logins}")
    print(f"[*] Attacker commands      : {attacker_commands}")
    print()

    # Step 3: Calculate the risk score.
    risk_score = calculate_risk_score(events)

    # Step 4: Determine risk level and whether to trigger a decoy.
    result = decoy_decision(risk_score)

    # Step 5: Print the result in a readable format.
    print(f"  Risk Score      : {result['risk_score']}")
    print(f"  Risk Level      : {result['risk_level']}")
    print(
        f"  Decoy Triggered : "
        f"{'YES' if result['decoy_triggered'] else 'NO'}"
    )
    print()

    return result


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
