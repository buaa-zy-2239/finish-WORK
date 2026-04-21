#!/usr/bin/env python3
"""
Test script to verify session matching with zsp_session_id.
"""
import sys
import os
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('/home/zhang/UAV'))

from Backend.analysis.protocol_analyzer import D2ZAnalyzer
from Backend.core.log_parser import D2ZLogParser
from Backend.core.event_models import D2ZPhase

# Use command line argument for log directory if provided
LOG_DIR = Path("/home/zhang/UAV/tasks/sim_20260421_194713_29021742/logs")
if len(sys.argv) > 2 and sys.argv[1] == "--log_dir":
    LOG_DIR = Path(sys.argv[2])

def main():
    print("=" * 80)
    print("Testing session matching with zsp_session_id")
    print("=" * 80)
    print()
    
    # Parse logs
    parser = D2ZLogParser()
    events = []
    
    for f in sorted(LOG_DIR.glob("*.jsonl")):
        print(f"Parsing {f.name}...")
        try:
            file_events = parser.parse_file(str(f))
            events.extend(file_events)
        except Exception as e:
            print(f"Error parsing {f.name}: {e}")
    
    print(f"\nTotal events parsed: {len(events)}")
    
    # Print ZSP SUCCESS events
    print("\nZSP SUCCESS events:")
    for event in events:
        if event.entity_type == "ZSP" and event.phase == D2ZPhase.SUCCESS:
            print(f"  sim_time: {event.sim_time:.3f}, uav_id: {event.uav_id}, zsp_id: {event.zsp_id}, zsp_session_id: {event.zsp_session_id}")
    
    # Analyze events
    analyzer = D2ZAnalyzer(events)
    
    # Get metrics
    summary = analyzer.get_summary()
    print("\n" + "=" * 80)
    print("Analysis Summary")
    print("=" * 80)
    print(f"Total sessions: {summary.get('total_sessions', 0)}")
    print(f"Successful sessions: {summary.get('successful_sessions', 0)}")
    print(f"Failed sessions: {summary.get('failed_sessions', 0)}")
    print(f"Timeout sessions: {summary.get('timeout_sessions', 0)}")
    print(f"Success rate: {summary.get('success_rate', 0):.2f}%")
    print(f"Channel reliability: {summary.get('channel_reliability', 0):.2f}%")
    
    # Get all sessions
    sessions = analyzer.get_all_sessions()
    print(f"\nTotal logical sessions: {len(sessions)}")
    
    # Show successful sessions
    successful = [s for s in sessions if s.get('success', False)]
    print(f"Successful sessions: {len(successful)}")
    
    if successful:
        print("\nFirst 5 successful sessions:")
        for s in successful[:5]:
            print(f"  UAV {s.get('uav_id')} -> ZSP {s.get('zsp_id')}")
            print(f"    Start: {s.get('start_time'):.3f}, End: {s.get('end_time'):.3f}")
            print(f"    Auth session ID: {s.get('auth_session_id')}")
            print(f"    ZSP session ID: {s.get('zsp_session_id')}")
            print(f"    Success: {s.get('success')}")
            print()
    
    # Show UAV statistics
    print("\n" + "=" * 80)
    print("UAV Statistics")
    print("=" * 80)
    
    # Get unique UAV IDs
    uav_ids = set()
    for s in sessions:
        uav_id = s.get('uav_id')
        if uav_id is not None:
            uav_ids.add(uav_id)
    
    for uav_id in sorted(uav_ids):
        stats = analyzer.get_uav_statistics(uav_id)
        print(f"UAV {uav_id}:")
        print(f"  Total sessions: {stats.get('total_sessions', 0)}")
        print(f"  Successful sessions: {stats.get('successful_sessions', 0)}")
        print(f"  Failed sessions: {stats.get('failed_sessions', 0)}")
        print(f"  Success rate: {stats.get('success_rate_percent', 0):.2f}%")
        print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
