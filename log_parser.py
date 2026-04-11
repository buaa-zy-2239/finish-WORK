import json
import glob
import os
from collections import defaultdict

def parse_and_test_logs(log_directory="./logs"):
    all_events = []
    
    # 1. 加载所有 .jsonl 日志文件
    log_files = glob.glob(os.path.join(log_directory, "*.jsonl"))
    if not log_files:
        print("未找到任何 .jsonl 文件，请确保日志文件在当前目录下。")
        return

    for filename in log_files:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    all_events.append(json.loads(line))

    # 2. 按仿真时间 (timestamp) 进行全局排序，以还原真实的交互顺序
    all_events.sort(key=lambda x: x['timestamp'])

    # 用于记录和比对 Hash 值: { hash_value: {"UAV": id, "ZSP": id} }
    session_hashes = defaultdict(dict)

    print("="*85)
    print("                    UAV-ZSP 身份认证与切换流程追踪表                    ")
    print("="*85)

    # 3. 解析并打印认证流程
    for event in all_events:
        time = event.get('sim_time', 0.0)
        entity_type = event.get('entity_type', 'UNK')
        entity_id = event.get('entity_id', '?')
        entity = f"{entity_type}-{entity_id}"
        e_type = event.get('event_type')
        details = event.get('details', {})

        # 根据事件类型进行格式化输出
        if e_type == "MESSAGE_SENT":
            msg_type = details.get('message_type')
            print(f"[{time:>5.1f}s] {entity:^10} | >> [发送消息] {msg_type} (大小: {details.get('payload_size')} bytes)")
            
        elif e_type == "MESSAGE_RECEIVED":
            msg_type = details.get('message_type')
            print(f"[{time:>5.1f}s] {entity:^10} | << [接收消息] {msg_type} (大小: {details.get('payload_size')} bytes)")
            
        elif e_type == "IDENTIFIER_OPERATION" and details.get('operation') == 'rotated':
            old_pid = details.get('old_pid', '')[:8]
            new_pid = details.get('new_pid', '')[:8]
            print(f"[{time:>5.1f}s] {entity:^10} | 🔄 [PID 更新] {old_pid} -> {new_pid}")
            
        elif e_type == "MOBILITY_EVENT" and details.get('event_type') == 'handover':
            from_zsp = details.get('from_zsp_id')
            to_zsp = details.get('to_zsp_id')
            print(f"\n[{time:>5.1f}s] {entity:^10} | ✈️  [跨区切换] 离开 ZSP-{from_zsp} ---> 接入 ZSP-{to_zsp}")
            
        elif e_type == "SESSION_ESTABLISHED":
            key_hash = details.get('session_key_hash')
            print(f"[{time:>5.1f}s] {entity:^10} | 🔐 [会话建立] 生成 Hash: {key_hash[:16]}...")
            
            # 记录 Hash 以便后续验证
            if entity_type == 'UAV':
                session_hashes[key_hash]['UAV'] = entity_id
            elif entity_type == 'ZSP':
                session_hashes[key_hash]['ZSP'] = entity_id

    # 4. Hash 值一致性检测总结
    print("\n" + "="*85)
    print("                       最终 Session Key Hash 一致性验证结果                     ")
    print("="*85)
    
    match_count = 0
    for key_hash, entities in session_hashes.items():
        uav_id = entities.get('UAV')
        zsp_id = entities.get('ZSP')
        
        # 判断双方是否都生成了相同的 Hash
        if uav_id is not None and zsp_id is not None:
            status = "✅ 匹配成功"
            match_count += 1
        else:
            status = "❌ 匹配失败或不完整"
            
        print(f"Hash 值: {key_hash}")
        print(f"持有方 : UAV-{uav_id} 与 ZSP-{zsp_id}  -->  {status}\n")
        
    print(f"共检测到 {len(session_hashes)} 个唯一会话密钥，其中 {match_count} 个成功匹配。")

if __name__ == "__main__":
    parse_and_test_logs()