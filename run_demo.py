# =============================================================================
# run_demo.py
# Sentinel-JIT — Autonomous Just-In-Time Deception Security System
# =============================================================================
#
# PURPOSE:
#   One-click demo runner that executes the full Sentinel-JIT pipeline
#   in the correct order, printing clear progress messages at each stage.
#
# RUN WITH:
#   python3 run_demo.py
#
# PIPELINE:
#   [1/3] attack_simulator  → generates events → writes logs.json
#   [2/3] risk_engine       → reads logs       → prints risk score
#   [3/3] ai_analysis       → reads logs       → prints attack report
#
# After this script completes, launch the visual dashboard with:
#   python3 -m streamlit run app.py
#
# =============================================================================

import json
import attack_simulator
import risk_engine
import ai_analysis
import alert_engine

LOG_FILE = "logs.json"


def reset_logs() -> None:
    """
    Clears logs.json before each demo run so events do not accumulate
    across multiple runs of this script.
    """
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
    print(f"  [reset] {LOG_FILE} cleared — starting fresh.")
    print()


DIVIDER = "=" * 60


def main() -> None:
    """
    Runs the full Sentinel-JIT demo pipeline step by step.
    """

    print()
    print("Sentinel-JIT  —  running full demo pipeline")
    print()

    # Reset logs first so we always get a fresh 14-event simulation,
    # not accumulated duplicates from previous runs.
    reset_logs()

    # ------------------------------------------------------------------
    # STEP 1 — Generate simulated attack events
    # ------------------------------------------------------------------
    print("Step 1 of 4  —  Simulating attack events")
    print()
    attack_simulator.main()
    print()

    # ------------------------------------------------------------------
    # STEP 2 — Calculate risk score
    # ------------------------------------------------------------------
    print("Step 2 of 4  —  Calculating risk score")
    print()
    risk_engine.main()
    print()

    # ------------------------------------------------------------------
    # STEP 3 — Run AI attack analysis
    # ------------------------------------------------------------------
    print("Step 3 of 4  —  Running AI attack analysis")
    print()
    result = ai_analysis.main()
    print()

    # ------------------------------------------------------------------
    # STEP 4 — Send email alert if risk is HIGH
    # ------------------------------------------------------------------
    events = risk_engine.load_logs()
    risk_score = risk_engine.calculate_risk_score(events)
    decision = risk_engine.decoy_decision(risk_score)

    if decision["decoy_triggered"]:
        print("Step 4 of 4  —  High risk detected, sending alert...")
        print()

        # Build stage summary from AI analysis result
        stage_summary = {}
        if result and isinstance(result.get("analysis"), list):
            for item in result["analysis"]:
                if isinstance(item, dict):
                    s = str(item.get("stage", "Unknown"))
                    c = str(item.get("command", ""))
                    if s not in stage_summary:
                        stage_summary[s] = []
                    stage_summary[s].append(c)

        # Get source IP
        source_ip = "Unknown"
        for event in events:
            if isinstance(event, dict) and event.get("ip"):
                source_ip = str(event["ip"])
                break

        alert_engine.send_alert_email(
            source_ip=source_ip,
            risk_score=int(risk_score),
            risk_level=str(decision["risk_level"]),
            stage_summary=stage_summary,
        )
        print()
    else:
        print("Step 4 of 4  —  Risk below threshold, no alert sent.")
        print()

    # ------------------------------------------------------------------
    # DONE — Print next-step instructions
    # ------------------------------------------------------------------
    print("Pipeline complete.")
    print()
    print("  Launch the dashboard:  python3 -m streamlit run app.py")
    print("  Then open:             http://localhost:8501")
    print()


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
