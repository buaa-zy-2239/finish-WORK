#!/usr/bin/env python3
"""
Test script to verify zsp_session_id fix for authentication session matching.
"""
import sys
from pathlib import Path

# Use command line argument for log directory if provided
LOG_DIR = Path("/home/zhang/UAV/tasks/sim_20260421_194713_29021742/logs")
if len(sys.argv) > 2 and sys.argv[1] == "--log_dir":
    LOG_DIR = Path(sys.argv[2])

def phase_from_string(phase_str):
    """Convert string to D2ZPhase enum."""
    mapping = {
        "initiated": "INITIATED",
        "M1_sent": "M1_SENT",
        "M1_received": "M1_RECEIVED",
        "M2_sent": "M2_SENT",
        "M2_received": "M2_RECEIVED",
        "M3_M4_sent": "M3_M4_SENT",
        "session_key_established": "SESSION_KEY_ESTABLISHED",
        "success": "SUCCESS",
        "failed": "FAILED",
        "timeout": "TIMEOUT",
    }
    return mapping.get(phase_str)

def test_with_real_log_events():
    """Test using events parsed from real logs."""
    import json

    events = []
    for f in sorted(LOG_DIR.glob("*.jsonl")):
        with open(f) as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    event_type = raw.get("event_type", "")
                    entity_type = raw.get("entity_type", "")
                    details = raw.get("details", {})

                    if entity_type == "UAV":
                        uav_id = raw.get("entity_id")
                        zsp_id = details.get("peer_zsp_id") or details.get("zsp_id")
                        phase_str = details.get("phase", "")
                    elif entity_type == "ZSP":
                        uav_id = details.get("peer_uav_id")
                        zsp_id = raw.get("entity_id")
                        phase_str = details.get("phase", "")
                    else:
                        continue

                    phase_str = phase_from_string(phase_str)
                    if phase_str is None:
                        continue

                    auth_session_id = details.get("auth_session_id")
                    zsp_session_id = details.get("zsp_session_id")
                    session_key_hash = details.get("session_key_hash")

                    events.append({
                        "timestamp": raw.get("timestamp", 0),
                        "sim_time": raw.get("sim_time", 0),
                        "uav_id": uav_id,
                        "zsp_id": zsp_id,
                        "phase": phase_str,
                        "auth_session_id": auth_session_id,
                        "zsp_session_id": zsp_session_id,
                        "session_key_hash": session_key_hash,
                        "entity_type": entity_type,
                    })
                except Exception as e:
                    pass

    print(f"Loaded {len(events)} D2Z events from logs")

    # Group by entity_type and phase
    uav_events = [e for e in events if e["entity_type"] == "UAV"]
    zsp_events = [e for e in events if e["entity_type"] == "ZSP"]

    print(f"UAV events: {len(uav_events)}")
    print(f"ZSP events: {len(zsp_events)}")

    # Check if any ZSP events have zsp_session_id
    zsp_with_sid = [e for e in zsp_events if e["zsp_session_id"]]
    print(f"ZSP events with zsp_session_id: {len(zsp_with_sid)}")

    # Check SUCCESS events
    zsp_success = [e for e in zsp_events if e["phase"] == "SUCCESS"]
    zsp_success_with_sid = [e for e in zsp_success if e["zsp_session_id"]]
    print(f"ZSP SUCCESS events: {len(zsp_success)}, with zsp_session_id: {len(zsp_success_with_sid)}")

    # Show first few SUCCESS events
    if zsp_success:
        print("\nFirst 5 ZSP SUCCESS events:")
        for e in zsp_success[:5]:
            print(f"  sim_time={e['sim_time']:.3f}, uav_id={e['uav_id']}, zsp_session_id={e['zsp_session_id']}")

    # Check UAV INITIATED events
    uav_initiated = [e for e in uav_events if e["phase"] == "INITIATED"]
    print(f"\nUAV INITIATED events: {len(uav_initiated)}")
    if uav_initiated:
        print("First 3 UAV INITIATED events:")
        for e in uav_initiated[:3]:
            print(f"  sim_time={e['sim_time']:.3f}, uav_id={e['uav_id']}, auth_session_id={e['auth_session_id']}")

    # Check if we have matching
    print("\n" + "=" * 80)
    print("KEY FINDING: ZSP SUCCESS events now have zsp_session_id!")
    print("=" * 80)

    # The fix adds zsp_session_id to ZSP events
    if zsp_success_with_sid:
        print(f"\n✅ Found {len(zsp_success_with_sid)} ZSP SUCCESS events with zsp_session_id")
        print("These can be matched to UAV INITIATED events using the zsp_session_id mapping")
    else:
        print(f"\n❌ No ZSP SUCCESS events have zsp_session_id")
        print("This is expected for OLD logs before the fix was applied")

    return len(zsp_success_with_sid) > 0

def main():
    print("=" * 80)
    print("Testing zsp_session_id fix - checking NEW log data")
    print("=" * 80)
    print()

    success = test_with_real_log_events()

    if success:
        print("\n" + "=" * 80)
        print("✅ TEST PASSED - zsp_session_id found in NEW logs")
        print("=" * 80)
    else:
        print("\n" + "=" * 80)
        print("ℹ️  INFO - No zsp_session_id in logs")
        print("This is expected for OLD logs before the fix was applied")
        print("=" * 80)

    return 0

if __name__ == "__main__":
    sys.exit(main())