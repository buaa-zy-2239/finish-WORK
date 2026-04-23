#!/usr/bin/env python3
"""
测试子会话时序图生成

该脚本模拟前端的子会话分组和过滤逻辑，验证后端日志解析器的输出是否正确
"""

import os
import sys
import json
from collections import defaultdict

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from Backend.core.log_parser import D2ZLogParser
from Backend.core.event_models import D2ZEvent, D2ZPhase

def format_number(num):
    """格式化数字，保留三位小数"""
    return f"{num:.3f}"

def get_event_priority(event):
    """获取事件优先级"""
    if event.phase == D2ZPhase.INITIATED and not (event.protocol_step and 'RETRY' in event.protocol_step):
        return 1
    if event.phase == D2ZPhase.M1_SENT and event.success:
        return 2
    if not event.success and (event.error_reason and 'dropped' in event.error_reason or (event.protocol_step and 'DROPPED' in event.protocol_step)):
        return 3
    if (event.protocol_step and 'RETRY_AFTER' in event.protocol_step):
        return 4
    if event.phase in [D2ZPhase.M2_SENT, D2ZPhase.M3_M4_SENT]:
        return 5
    if event.phase == D2ZPhase.M2_RECEIVED:
        return 6
    if event.phase == D2ZPhase.ACK_RECEIVED:
        return 6.5
    if event.phase == D2ZPhase.SESSION_KEY_ESTABLISHED:
        return 7
    if event.phase == D2ZPhase.SUCCESS:
        return 8
    if event.phase == D2ZPhase.TIMEOUT or (event.protocol_step and 'RETRY_BUDGET_EXHAUSTED' in event.protocol_step):
        return 9
    return 10

def sort_events(events):
    """排序事件"""
    return sorted(events, key=lambda a: (
        a.subsession_id if a.subsession_id is not None else 0,
        a.sim_time if a.sim_time is not None else 0,
        get_event_priority(a)
    ))

def group_by_subsession(events):
    """按子会话分组"""
    subsession_groups = defaultdict(list)
    
    # 按子会话ID分组
    for item in events:
        # 过滤掉M1_received事件
        if item.phase == D2ZPhase.M1_RECEIVED:
            continue
        # 过滤掉M3/M4_sent事件，但保留M3/M4_RECV、DROPPED和RETRY_BUDGET_EXHAUSTED事件
        if item.phase == D2ZPhase.M3_M4_SENT and not ((item.protocol_step and 'DROPPED' in item.protocol_step) or (item.protocol_step and 'M3_M4_RECV' in item.protocol_step) or (item.protocol_step and 'RETRY_BUDGET_EXHAUSTED' in item.protocol_step)):
            continue
        # 过滤掉M1重试事件
        if (item.protocol_step and 'RETRY_AFTER' in item.protocol_step) or (item.protocol_step and 'ATTACK_RETRY' in item.protocol_step) or item.message_type == 'RETRY':
            continue
        # 过滤掉UAV侧的会话密钥建立和认证成功事件
        if item.entity_type == 'UAV' and (item.phase == D2ZPhase.SESSION_KEY_ESTABLISHED or item.phase == D2ZPhase.SUCCESS):
            continue
        
        # 为每个子会话分组添加事件
        subsession_key = item.subsession_id if item.subsession_id is not None else 0
        subsession_groups[subsession_key].append(item)
    
    # 过滤掉只包含一个事件的子会话
    filtered_groups = {}
    for key, group in subsession_groups.items():
        if len(group) > 1:
            filtered_groups[key] = group
        elif len(group) == 1:
            # 检查这个事件是否是超时事件
            item = group[0]
            if item.phase == D2ZPhase.TIMEOUT or (item.protocol_step and 'RETRY_BUDGET_EXHAUSTED' in item.protocol_step):
                # 如果是超时事件，保留它
                filtered_groups[key] = group
    
    # 确保子会话之间的时间顺序正确
    sorted_groups = {}
    for key in sorted(filtered_groups.keys()):
        # 确保子会话的事件按时间顺序排序
        events = filtered_groups[key]
        events.sort(key=lambda x: x.sim_time if x.sim_time is not None else 0)
        sorted_groups[key] = events
    
    return sorted_groups

def filter_subsession_events(events, subsession_key):
    """过滤子会话事件"""
    group_filtered_events = []
    
    # 确保事件按照时间顺序排序
    events.sort(key=lambda x: x.sim_time if x.sim_time is not None else 0)
    
    # 不需要过滤事件，保留所有事件
    for item in events:
        group_filtered_events.append(item)
    
    return group_filtered_events

def get_message_type(item):
    """获取消息类型"""
    if (item.protocol_step and 'RETRY_AFTER' in item.protocol_step) or (item.protocol_step and 'ATTACK_RETRY' in item.protocol_step) or item.message_type == 'RETRY':
        return 'M1 (重试)'
    elif item.phase == D2ZPhase.M1_SENT or item.message_type == 'M1':
        return 'M1'
    elif item.phase in [D2ZPhase.M2_SENT, D2ZPhase.M2_RECEIVED] or item.message_type == 'M2':
        return 'M2'
    elif item.phase == D2ZPhase.ACK_RECEIVED or item.message_type == 'D2Z_ACK':
        return 'ACK'
    elif item.phase == D2ZPhase.M3_M4_SENT or item.message_type == 'M3/M4' or (item.protocol_step and 'M3_M4_RECV' in item.protocol_step) or (item.phase == D2ZPhase.M3_M4_SENT and item.protocol_step and 'M3_M4_RECV' in item.protocol_step) or (item.protocol_step and 'M3_M4_DROPPED' in item.protocol_step):
        return 'M3/M4'
    elif item.phase == D2ZPhase.INITIATED and not (item.protocol_step and 'RETRY' in item.protocol_step) and item.message_type != 'RETRY':
        return '会话建立'
    elif item.phase == D2ZPhase.TIMEOUT or (item.protocol_step and 'RETRY_BUDGET_EXHAUSTED' in item.protocol_step):
        return '超时'
    elif item.phase == D2ZPhase.SESSION_KEY_ESTABLISHED:
        return '会话密钥建立'
    elif item.phase == D2ZPhase.SUCCESS:
        return '认证成功'
    else:
        return 'Unknown'

def get_direction(item):
    """获取消息方向"""
    if (item.protocol_step and 'RETRY_AFTER' in item.protocol_step) or (item.protocol_step and 'ATTACK_RETRY' in item.protocol_step) or item.message_type == 'RETRY':
        return 'uav-to-zsp'
    elif item.phase == D2ZPhase.M1_SENT or item.message_type == 'M1':
        return 'uav-to-zsp'
    elif item.phase in [D2ZPhase.M2_SENT, D2ZPhase.M2_RECEIVED] or item.message_type == 'M2':
        return 'zsp-to-uav'
    elif item.phase == D2ZPhase.ACK_RECEIVED or item.message_type == 'D2Z_ACK':
        return 'zsp-to-uav'
    elif item.phase == D2ZPhase.M3_M4_SENT or item.message_type == 'M3/M4' or (item.protocol_step and 'M3_M4_RECV' in item.protocol_step) or (item.phase == D2ZPhase.M3_M4_SENT and item.protocol_step and 'M3_M4_RECV' in item.protocol_step) or (item.protocol_step and 'M3_M4_DROPPED' in item.protocol_step):
        return 'uav-to-zsp'
    elif item.phase == D2ZPhase.INITIATED and not (item.protocol_step and 'RETRY' in item.protocol_step) and item.message_type != 'RETRY':
        return 'uav-to-zsp'
    elif item.phase == D2ZPhase.TIMEOUT or (item.protocol_step and 'RETRY_BUDGET_EXHAUSTED' in item.protocol_step):
        return 'uav-to-zsp'
    elif item.phase == D2ZPhase.SESSION_KEY_ESTABLISHED:
        return 'uav-to-zsp'
    elif item.phase == D2ZPhase.SUCCESS:
        return 'uav-to-zsp'
    else:
        return 'uav-to-zsp'

def is_packet_drop(item):
    """检测是否为丢包事件"""
    return not item.success and (item.error_reason and 'dropped' in item.error_reason or (item.protocol_step and 'DROPPED' in item.protocol_step))

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <task_dir> [<auth_session_id>] [<subsession_id>]")
        print("Example: python test_subsession_timeline.py /home/zhang/UAV/tasks/sim_20260423_140713_7a77c806 24eb8bba-ed11-4e3b-b5dd-44136e1afec0 1")
        print("Example: python test_subsession_timeline.py /home/zhang/UAV/tasks/sim_20260423_140713_7a77c806  # 显示所有会话")
        sys.exit(1)
    
    task_dir = sys.argv[1]
    auth_session_id = sys.argv[2] if len(sys.argv) > 2 else None
    subsession_id = int(sys.argv[3]) if len(sys.argv) > 3 else None
    
    # 解析日志
    log_dir = os.path.join(task_dir, 'logs')
    if not os.path.exists(log_dir):
        print(f"Error: Log directory not found: {log_dir}")
        sys.exit(1)
    
    print(f"[INFO] Parsing logs from {log_dir}")
    all_events = D2ZLogParser.parse_all_logs(log_dir)
    print(f"[INFO] Parsed {len(all_events)} events")
    
    if auth_session_id:
        # 过滤指定会话的事件
        session_events = [e for e in all_events if e.auth_session_id == auth_session_id]
        print(f"[INFO] Found {len(session_events)} events for session {auth_session_id}")
        
        if not session_events:
            print("[ERROR] No events found for the specified session")
            sys.exit(1)
        
        # 排序事件
        sorted_events = sort_events(session_events)
        
        # 按子会话分组
        subsession_groups = group_by_subsession(sorted_events)
        print(f"[INFO] Found {len(subsession_groups)} subsessions")
        
        # 打印所有子会话
        print("\n[INFO] Subsession summary:")
        for key in sorted(subsession_groups.keys()):
            events = subsession_groups[key]
            print(f"  Subsession {key}: {len(events)} events")
        
        # 处理指定子会话
        if subsession_id is not None:
            if subsession_id not in subsession_groups:
                print(f"[ERROR] Subsession {subsession_id} not found")
                sys.exit(1)
            
            print(f"\n[INFO] Processing subsession {subsession_id}")
            events = subsession_groups[subsession_id]
            filtered_events = filter_subsession_events(events, subsession_id)
            
            print(f"[INFO] Filtered events: {len(filtered_events)}")
            print("\n[INFO] Timeline for subsession {subsession_id}:")
            print("-" * 80)
            print(f"{'Time':<10} {'Direction':<12} {'Message':<15} {'Event Type':<20} {'Details':<20}")
            print("-" * 80)
            
            for item in filtered_events:
                time = format_number(item.sim_time) if item.sim_time else 'N/A'
                direction = get_direction(item)
                message = get_message_type(item)
                event_type = item.entity_type or 'N/A'
                details = item.protocol_step or 'N/A'
                drop = " (丢包)" if is_packet_drop(item) else ""
                
                print(f"{time:<10} {direction:<12} {message:<15} {event_type:<20} {details:<20}{drop}")
            
            print("-" * 80)
        else:
            # 处理所有子会话
            for key in sorted(subsession_groups.keys()):
                print(f"\n[INFO] Processing subsession {key}")
                events = subsession_groups[key]
                filtered_events = filter_subsession_events(events, key)
                
                print(f"[INFO] Filtered events: {len(filtered_events)}")
                print("\n[INFO] Timeline for subsession {key}:")
                print("-" * 80)
                print(f"{'Time':<10} {'Direction':<12} {'Message':<15} {'Event Type':<20} {'Details':<20}")
                print("-" * 80)
                
                for item in filtered_events:
                    time = format_number(item.sim_time) if item.sim_time else 'N/A'
                    direction = get_direction(item)
                    message = get_message_type(item)
                    event_type = item.entity_type or 'N/A'
                    details = item.protocol_step or 'N/A'
                    drop = " (丢包)" if is_packet_drop(item) else ""
                    
                    print(f"{time:<10} {direction:<12} {message:<15} {event_type:<20} {details:<20}{drop}")
                
                print("-" * 80)
    else:
        # 显示所有会话
        # 按会话分组
        sessions = {}
        for e in all_events:
            if e.auth_session_id:
                if e.auth_session_id not in sessions:
                    sessions[e.auth_session_id] = []
                sessions[e.auth_session_id].append(e)
        
        print(f"[INFO] Found {len(sessions)} sessions")
        
        # 处理每个会话
        for session_id, session_events in sessions.items():
            print(f"\n[INFO] Processing session {session_id}")
            print(f"[INFO] Found {len(session_events)} events")
            
            # 排序事件
            sorted_events = sort_events(session_events)
            
            # 按子会话分组
            subsession_groups = group_by_subsession(sorted_events)
            print(f"[INFO] Found {len(subsession_groups)} subsessions")
            
            # 打印所有子会话
            print("[INFO] Subsession summary:")
            for key in sorted(subsession_groups.keys()):
                events = subsession_groups[key]
                print(f"  Subsession {key}: {len(events)} events")
            
            # 处理所有子会话
            for key in sorted(subsession_groups.keys()):
                print(f"\n[INFO] Processing subsession {key}")
                events = subsession_groups[key]
                filtered_events = filter_subsession_events(events, key)
                
                print(f"[INFO] Filtered events: {len(filtered_events)}")
                print("\n[INFO] Timeline for subsession {key}:")
                print("-" * 80)
                print(f"{'Time':<10} {'Direction':<12} {'Message':<15} {'Event Type':<20} {'Details':<20}")
                print("-" * 80)
                
                for item in filtered_events:
                    time = format_number(item.sim_time) if item.sim_time else 'N/A'
                    direction = get_direction(item)
                    message = get_message_type(item)
                    event_type = item.entity_type or 'N/A'
                    details = item.protocol_step or 'N/A'
                    drop = " (丢包)" if is_packet_drop(item) else ""
                    
                    print(f"{time:<10} {direction:<12} {message:<15} {event_type:<20} {details:<20}{drop}")
                
                print("-" * 80)

if __name__ == "__main__":
    main()
