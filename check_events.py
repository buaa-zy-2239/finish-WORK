from Backend.core.log_parser import D2ZLogParser

# 解析所有日志事件
events = D2ZLogParser.parse_all_logs('/home/zhang/UAV/tasks/sim_20260421_205130_27a89465/logs')
print(f'Loaded {len(events)} events')

# 检查是否有INITIATED事件
initiated_events = []
for e in events:
    if e.phase.value == 'initiated':
        initiated_events.append(e)

print(f'Found {len(initiated_events)} INITIATED events')
for e in initiated_events:
    print(f'INITIATED event: uav_id={e.uav_id}, zsp_id={e.zsp_id}, auth_session_id={e.auth_session_id}')

# 检查所有事件的phase值
print('\nAll event phases:')
phases = set()
for e in events:
    phases.add(e.phase.value)
print(phases)
