#!/usr/bin/env python3
"""
Check ZSP SUCCESS events structure.
"""
import json
from pathlib import Path

LOG_DIR = Path("/home/zhang/UAV/tasks/sim_20260421_194713_29021742/logs")

def main():
    print("=" * 80)
    print("Checking ZSP SUCCESS events")
    print("=" * 80)
    print()
    
    zsp_file = LOG_DIR / "sim_661943814_ZSP_11.jsonl"
    if not zsp_file.exists():
        print(f"ZSP log file not found: {zsp_file}")
        return
    
    print(f"Reading {zsp_file.name}...")
    
    success_events = []
    with open(zsp_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "AUTHENTICATION_SUCCESS":
                    success_events.append(event)
            except Exception as e:
                print(f"Error parsing line: {e}")
    
    print(f"Found {len(success_events)} AUTHENTICATION_SUCCESS events")
    print()
    
    for i, event in enumerate(success_events):
        print(f"Event {i+1}:")
        print(f"  sim_time: {event.get('sim_time')}")
        print(f"  entity_type: {event.get('entity_type')}")
        print(f"  entity_id: {event.get('entity_id')}")
        details = event.get('details', {})
        print(f"  details.phase: {details.get('phase')}")
        print(f"  details.status: {details.get('status')}")
        print(f"  details.peer_id: {details.get('peer_id')}")
        print(f"  details.peer_uav_id: {details.get('peer_uav_id')}")
        print(f"  details.peer_zsp_id: {details.get('peer_zsp_id')}")
        print(f"  details.zsp_session_id: {details.get('zsp_session_id')}")
        print(f"  details.protocol_step: {details.get('protocol_step')}")
        print()
    
    return 0

if __name__ == "__main__":
    main()
