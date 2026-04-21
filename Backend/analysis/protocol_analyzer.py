# Backend/analysis/protocol_analyzer.py
"""
D2Z协议效率分析器（支持 auth_session_id 与多轮会话）
"""

import statistics
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional

from core.event_models import D2ZEvent, D2ZMetrics, D2ZPhase, D2ZSession


class D2ZAnalyzer:
    """D2Z流程分析器"""

    def __init__(self, events: List[D2ZEvent]):
        self.events = events
        self.sessions: Dict[str, D2ZSession] = {}
        self.logical_sessions: Dict[str, D2ZSession] = {}
        self.metrics = D2ZMetrics()
        self._sid_alias: Dict[str, str] = {}
        self._zsp_sid_to_auth_sid: Dict[str, str] = {}
        self._analyze()

    def _analyze(self) -> None:
        self._identify_sessions()
        self._aggregate_session_events()
        self._calculate_metrics()

    @staticmethod
    def _distance_bucket(distance_m: Optional[float], bucket_size: int = 50) -> Optional[str]:
        if distance_m is None:
            return None
        lower = int(distance_m // bucket_size) * bucket_size
        upper = lower + bucket_size
        return f"{lower}-{upper}m"

    @staticmethod
    def _classify_trigger(protocol_step: Optional[str]) -> str:
        step = (protocol_step or "").upper()
        if step == "D2Z_TRIGGER_EDGE_RSSI":
            return "edge_rssi"
        if step == "D2Z_TRIGGER_TIME":
            return "time_window"
        if step == "D2Z_INITIATED":
            return "connect"
        if "RETRY" in step:
            return "retry"
        if step.startswith("D2Z_TRIGGER_"):
            return step.replace("D2Z_TRIGGER_", "").lower()
        return "unknown"

    def _identify_sessions(self) -> None:
        ordered = sorted(self.events, key=lambda e: (e.sim_time, e.timestamp))
        pending: Dict[str, D2ZSession] = {}
        stacks: Dict[tuple, List[str]] = defaultdict(list)

        for e in ordered:
            pair = None
            if e.uav_id is not None and e.uav_id >= 0 and e.zsp_id is not None:
                pair = (e.uav_id, int(e.zsp_id))

            if e.phase == D2ZPhase.INITIATED and pair is not None:
                print(f"DEBUG:   Creating session for INITIATED event", file=sys.stderr)
                print(f"DEBUG:   Event details: uav_id={e.uav_id}, zsp_id={e.zsp_id}, auth_session_id={e.auth_session_id}", file=sys.stderr)
                raw_sid = e.auth_session_id or f"legacy-{pair[0]}-{pair[1]}-{e.sim_time:.6f}"
                trigger_reason = self._classify_trigger(e.protocol_step)
                if trigger_reason == "retry" and stacks[pair]:
                    # 检查原会话是否仍在进行中（pending）
                    latest_sid = stacks[pair][-1]
                    if latest_sid in pending:
                        # 原会话仍在进行中，重试属于同一逻辑会话
                        self._sid_alias[raw_sid] = latest_sid
                        continue
                    else:
                        # 原会话已完成（成功/失败/超时），清理旧sid，创建新独立会话
                        # 清除已完成的旧sid，避免后续事件匹配错误
                        stacks[pair].clear()
                if trigger_reason == "retry" and not stacks[pair]:
                    # 原上下文已完成，这是新的独立认证尝试
                    pass  # 允许创建新会话
                sid = raw_sid
                sess = D2ZSession(
                    uav_id=pair[0],
                    zsp_id=pair[1],
                    start_time=e.sim_time,
                    end_time=None,
                    auth_session_id=sid,
                    protocol=e.protocol,
                    analysis_family=e.analysis_family,
                    trigger_reason=trigger_reason,
                    trigger_step=e.protocol_step,
                    init_distance_m=e.distance_m,
                    init_rssi=e.rssi,
                    init_link_zone=e.link_zone,
                )
                pending[sid] = sess
                self.logical_sessions[sid] = sess
                stacks[pair].append(sid)
                self._sid_alias[raw_sid] = sid
                print(f"DEBUG:   Created session: {sid} for UAV {pair[0]} -> ZSP {pair[1]}", file=sys.stderr)
                continue

            # 处理SESSION_KEY_ESTABLISHED事件：记录session_key_hash（不结束会话）
            if e.phase == D2ZPhase.SESSION_KEY_ESTABLISHED:
                sid = e.auth_session_id
                if sid:
                    sid = self._sid_alias.get(sid, sid)
                if not sid and e.zsp_session_id and e.zsp_session_id in self._zsp_sid_to_auth_sid:
                    sid = self._zsp_sid_to_auth_sid[e.zsp_session_id]
                if not sid and pair is not None and stacks[pair]:
                    sid = stacks[pair][-1]
                # 合并日志按时间排序后，UAV 常在同一 sim_time 先写 SESSION 再写 SUCCESS，
                # ZSP 的 SESSION 略晚到达；SUCCESS 已把会话从 pending 移入 self.sessions。
                # 若仍只查 pending，会丢失 ZSP 侧 session_key_hash，误判为 key_mismatch。
                sess = None
                if sid:
                    sess = pending.get(sid) or self.sessions.get(sid)
                if sess is None and pair is not None:
                    best = None
                    best_dt = float("inf")
                    for cand in self.sessions.values():
                        if cand.uav_id != pair[0] or cand.zsp_id != pair[1]:
                            continue
                        if cand.end_time is None:
                            continue
                        dt = abs(float(cand.end_time) - float(e.sim_time))
                        if dt < best_dt:
                            best_dt = dt
                            best = cand
                    if best is not None and best_dt <= 1.0:
                        sess = best
                if sess is not None and e.session_key_hash and e.entity_type:
                    if e.entity_type == "UAV":
                        sess.uav_session_key_hash = e.session_key_hash
                    elif e.entity_type == "ZSP":
                        sess.zsp_session_key_hash = e.session_key_hash
                        if e.zsp_session_id and not sess.zsp_session_id:
                            sess.zsp_session_id = e.zsp_session_id
                            self._zsp_sid_to_auth_sid[e.zsp_session_id] = sess.auth_session_id or sid
                continue  # SESSION_KEY_ESTABLISHED不结束会话

            if e.phase in (D2ZPhase.SUCCESS, D2ZPhase.FAILED, D2ZPhase.TIMEOUT):
                sid = e.auth_session_id
                if sid:
                    sid = self._sid_alias.get(sid, sid)
                if not sid and pair is not None and stacks[pair]:
                    sid = stacks[pair][-1]
                if (
                    not sid
                    and e.phase in (D2ZPhase.FAILED, D2ZPhase.TIMEOUT)
                    and e.zsp_id is not None
                ):
                    zid = int(e.zsp_id)
                    candidates = [
                        psid
                        for psid, sess in pending.items()
                        if sess.zsp_id == zid
                    ]
                    if candidates:
                        sid = max(candidates, key=lambda psid: pending[psid].start_time)
                # 如果还是没有sid，尝试通过peer_uav_id和时间匹配（用于ZSP事件）
                if not sid and e.entity_type == "ZSP" and e.zsp_id is not None:
                    zid = int(e.zsp_id)
                    best_sid = None
                    best_dt = float("inf")
                    # 查找与当前ZSP事件匹配的pending会话
                    for psid, sess in pending.items():
                        if sess.zsp_id != zid:
                            continue
                        # ZSP的SUCCESS事件时间应该略晚于UAV的INITIATED事件
                        # 允许一定的时间差（考虑消息往返延迟）
                        dt = float(e.sim_time) - float(sess.start_time)
                        if 0 < dt < best_dt and dt <= 2.0:  # 最多允许2秒的时间差
                            best_dt = dt
                            best_sid = psid
                    if best_sid:
                        sid = best_sid
                # 如果ZSP SUCCESS事件有zsp_session_id，尝试通过它匹配pending会话
                if not sid and e.entity_type == "ZSP" and e.phase == D2ZPhase.SUCCESS and e.zsp_session_id:
                    zsp_sid = e.zsp_session_id
                    if zsp_sid in self._zsp_sid_to_auth_sid:
                        sid = self._zsp_sid_to_auth_sid[zsp_sid]
                    else:
                        for psid, sess in pending.items():
                            if sess.zsp_session_id == zsp_sid:
                                sid = psid
                                self._zsp_sid_to_auth_sid[zsp_sid] = sid
                                break
                        if not sid:
                            for psid, sess in pending.items():
                                if sess.zsp_id == int(e.zsp_id) and sess.uav_id == e.uav_id:
                                    sid = psid
                                    sess.zsp_session_id = zsp_sid
                                    self._zsp_sid_to_auth_sid[zsp_sid] = sid
                                    break
                # 如果还是没有sid，尝试通过peer_uav_id和zsp_id匹配pending会话
                if not sid and e.entity_type == "ZSP" and e.phase == D2ZPhase.SUCCESS and e.uav_id is not None and e.uav_id >= 0 and e.zsp_id is not None:
                    zid = int(e.zsp_id)
                    for psid, sess in pending.items():
                        if sess.uav_id == e.uav_id and sess.zsp_id == zid:
                            sid = psid
                            # 建立zsp_session_id到auth_session_id的映射
                            if e.zsp_session_id:
                                self._zsp_sid_to_auth_sid[e.zsp_session_id] = sid
                                sess.zsp_session_id = e.zsp_session_id
                            break
                if sid and sid in pending:
                    sess = pending[sid]
                    sess.end_time = e.sim_time
                    # 分别记录UAV和ZSP的session_key_hash（SUCCESS事件可能没有key，但之前的SESSION_KEY_ESTABLISHED应该已经记录）
                    if e.phase == D2ZPhase.SUCCESS:
                        sess.success = True
                        sess.error_reason = None
                        sess.session_key_hash = e.session_key_hash or sess.session_key_hash
                        sess.is_timeout = False
                        # 设置会话的zsp_session_id
                        if e.zsp_session_id:
                            sess.zsp_session_id = e.zsp_session_id
                            self._zsp_sid_to_auth_sid[e.zsp_session_id] = sid
                        self.sessions[sid] = pending.pop(sid)
                        # 更新logical_sessions中的对应会话
                        if sid in self.logical_sessions:
                            self.logical_sessions[sid] = self.sessions[sid]
                        pkey = (sess.uav_id, sess.zsp_id)
                        if pkey in stacks and sid in stacks[pkey]:
                            stacks[pkey].remove(sid)
                    elif e.phase == D2ZPhase.TIMEOUT:
                        # 对于PMAP_ACK协议，超时不意味着失败，因为会重试
                        # 暂时不将超时会话标记为失败，而是等待后续的重试结果
                        # 只有当仿真结束时仍未成功，才将其标记为失败
                        sess.is_timeout = True
                        # 不设置success为False，保持为None
                        sess.error_reason = e.error_reason or "timeout"
                        # 不将超时会话从pending中移除，因为可能会有重试
                        # 只有当收到明确的成功或失败事件时，才将其从pending中移除
                    else:
                        # explicit verification failure
                        sess.success = False
                        sess.error_reason = e.error_reason or "failed"
                        sess.is_timeout = False
                        self.sessions[sid] = pending.pop(sid)
                        pkey = (sess.uav_id, sess.zsp_id)
                        if pkey in stacks and sid in stacks[pkey]:
                            stacks[pkey].remove(sid)
                elif e.entity_type == "ZSP" and e.phase == D2ZPhase.SUCCESS and e.uav_id is not None and e.uav_id >= 0 and e.zsp_id is not None:
                    # 如果是ZSP SUCCESS事件且找不到对应的pending会话，创建一个新会话
                    # 这种情况通常发生在UAV侧的INITIATED事件丢失，但ZSP侧成功完成了认证
                    sid = f"zsp_success-{e.uav_id}-{e.zsp_id}-{e.sim_time:.6f}"
                    sess = D2ZSession(
                        uav_id=e.uav_id,
                        zsp_id=int(e.zsp_id),
                        start_time=e.sim_time,
                        end_time=e.sim_time,
                        auth_session_id=sid,
                        zsp_session_id=e.zsp_session_id,
                        protocol=e.protocol,
                        analysis_family=e.analysis_family,
                        trigger_reason="zsp_success",
                        trigger_step=e.protocol_step,
                    )
                    sess.success = True
                    sess.error_reason = None
                    sess.session_key_hash = e.session_key_hash
                    sess.is_timeout = False
                    self.sessions[sid] = sess
                    self.logical_sessions[sid] = sess
                    # 建立zsp_session_id到auth_session_id的映射
                    if e.zsp_session_id:
                        self._zsp_sid_to_auth_sid[e.zsp_session_id] = sid

        # 仿真结束时：pending 会话标记为 TIMEOUT
        for sid, sess in list(pending.items()):
            if sess.end_time is None:
                sess.end_time = max(e.sim_time for e in self.events) if self.events else sess.start_time
                sess.success = False
                sess.error_reason = "simulation_timeout"
                sess.is_timeout = True
            # 只有当会话确实失败（不是暂时超时）时，才将其添加到sessions中
            if not sess.success:
                self.sessions[sid] = sess
                # 同时添加到logical_sessions中
                self.logical_sessions[sid] = sess

    def _event_in_session(self, e: D2ZEvent, s: D2ZSession) -> bool:
        # 如果会话没有结束时间，只检查开始时间
        if s.end_time is None:
            return e.sim_time >= s.start_time
        if e.sim_time < s.start_time or e.sim_time > s.end_time:
            return False
        # 优先使用auth_session_id匹配
        if s.auth_session_id and e.auth_session_id:
            resolved = self._sid_alias.get(e.auth_session_id, e.auth_session_id)
            return resolved == s.auth_session_id
        # 回退到(uav_id, zsp_id)匹配（用于ZSP事件没有auth_session_id的情况）
        if e.uav_id is not None and e.uav_id >= 0:
            return e.uav_id == s.uav_id and e.zsp_id == s.zsp_id
        if e.zsp_id is not None and e.uav_id is not None and e.uav_id < 0:
            # ZSP事件：通过peer_uav_id匹配
            return e.uav_id == s.uav_id and e.zsp_id == s.zsp_id
        return False

    def _aggregate_session_events(self) -> None:
        for sid, session in self.sessions.items():
            for e in self.events:
                if not self._event_in_session(e, session):
                    continue
                session.total_events += 1

                if e.phase in (
                    D2ZPhase.M1_SENT,
                    D2ZPhase.M1_RECEIVED,
                    D2ZPhase.M2_SENT,
                    D2ZPhase.M2_RECEIVED,
                    D2ZPhase.M3_M4_SENT,
                ):
                    session.message_count += 1

                mt = e.message_type or ""
                ps = int(e.payload_size or 0)
                if mt == "M1" and ps:
                    session.m1_size = max(session.m1_size, ps)
                elif mt == "M2" and ps:
                    session.m2_size = max(session.m2_size, ps)
                elif mt in ("M3", "M4", "M3_M4", "M3_4") and ps:
                    session.m3_m4_size = max(session.m3_m4_size, ps)

    def _calculate_metrics(self) -> None:
        if not self.sessions:
            if not self.logical_sessions:
                return

        # 判断双方session_key是否匹配（协商一致性）
        def _keys_match(s: D2ZSession) -> bool:
            # 如果有zsp_session_id，说明ZSP侧已经成功，直接返回True
            if s.zsp_session_id:
                return True
            # 否则检查session_key是否匹配
            if not s.zsp_session_key_hash or not s.uav_session_key_hash:
                return False
            return s.uav_session_key_hash == s.zsp_session_key_hash
        
        # 分类统计所有逻辑会话
        key_matched_successful = []  # 双方key匹配的真正成功会话
        key_mismatched = []  # UAV单方面标记成功但key不匹配（计为失败）
        explicit_failed = []  # 显式失败会话
        timeouts = []  # 超时会话（未完成协议流程）
        
        # 首先处理ZSP侧的成功会话
        for s in self.logical_sessions.values():
            # 检查是否有zsp_session_id，这表示ZSP侧已经成功
            if s.zsp_session_id:
                s.success = True
                s.error_reason = None
                s.is_timeout = False
                key_matched_successful.append(s)
            elif getattr(s, 'is_timeout', False):
                timeouts.append(s)
            elif s.success:
                if _keys_match(s):
                    key_matched_successful.append(s)
                else:
                    # key不匹配：原来是UAV标记的success，但应视为失败
                    key_mismatched.append(s)
                    s.success = False
                    s.error_reason = "session_key_mismatch"
            else:
                explicit_failed.append(s)
        
        # 检查sessions字典中的会话，确保所有ZSP成功事件都被处理
        for s in self.sessions.values():
            if s.zsp_session_id and s not in key_matched_successful:
                s.success = True
                s.error_reason = None
                s.is_timeout = False
                key_matched_successful.append(s)
        
        # 关键修改：对于PMAP_ACK协议，需要特殊处理超时和重试
        # 1. 按UAV和ZSP对分组会话
        by_pair: Dict[tuple, List[D2ZSession]] = defaultdict(list)
        for s in self.logical_sessions.values():
            by_pair[(s.uav_id, s.zsp_id)].append(s)
        
        # 2. 对于每个UAV-ZSP对，检查是否有重试成功的情况
        # 如果一个会话超时后，后续有重试成功的会话，则将超时会话从失败统计中移除
        for pair_sessions in by_pair.values():
            ordered_pair = sorted(pair_sessions, key=lambda s: s.start_time)
            has_success = False
            # 从后往前检查，看看是否有成功的会话
            for i in range(len(ordered_pair) - 1, -1, -1):
                sess = ordered_pair[i]
                if sess.success:
                    has_success = True
                elif getattr(sess, 'is_timeout', False) and has_success:
                    # 如果当前会话是超时，且后面有成功的会话，则将其从timeouts中移除
                    if sess in timeouts:
                        timeouts.remove(sess)
        
        # 3. 重新计算有效会话
        # 关键修改：total_sessions只包含有效会话（成功或失败），不包含超时
        # key_mismatched也算作失败（因为key不匹配意味着认证实际上未成功）
        valid_sessions = key_matched_successful + explicit_failed + key_mismatched
        self.metrics.total_sessions = len(valid_sessions)
        self.metrics.successful_sessions = len(key_matched_successful)
        self.metrics.failed_sessions = len(explicit_failed) + len(key_mismatched)  # key不匹配计入失败
        self.metrics.timeout_sessions = len(timeouts)
        self.metrics.key_mismatch_sessions = len(key_mismatched)

        # 分层成功率指标
        if self.metrics.total_sessions > 0:
            # success_rate: 有效会话中的成功率（排除超时）
            self.metrics.success_rate = self.metrics.successful_sessions / self.metrics.total_sessions * 100
            self.metrics.session_completion_rate = self.metrics.success_rate
            
            # protocol_success_rate: 协议成功率（成功 / (成功+失败+key不匹配)）
            self.metrics.protocol_success_rate = self.metrics.success_rate
            self.metrics.protocol_correctness_rate = self.metrics.success_rate
            
            # channel_reliability: 信道可靠性 = 有效会话数 / 总发起会话数（含超时）
            total_initiated = len(self.logical_sessions)
            self.metrics.channel_reliability = self.metrics.total_sessions / total_initiated * 100 if total_initiated > 0 else 0.0
        else:
            self.metrics.success_rate = 0.0
            self.metrics.session_completion_rate = 0.0
            self.metrics.protocol_success_rate = 0.0
            self.metrics.protocol_correctness_rate = 0.0
            self.metrics.channel_reliability = 0.0

        self.metrics.total_messages = sum(s.message_count for s in self.sessions.values())

        per_session_bytes: List[int] = []
        if key_matched_successful:
            sizes_flat: List[float] = []
            for s in key_matched_successful:
                tb = s.total_bytes
                per_session_bytes.append(tb)
                if s.m1_size:
                    sizes_flat.append(float(s.m1_size))
                if s.m2_size:
                    sizes_flat.append(float(s.m2_size))
                if s.m3_m4_size:
                    sizes_flat.append(float(s.m3_m4_size))
            if sizes_flat:
                self.metrics.avg_message_size = statistics.mean(sizes_flat)
                self.metrics.total_bytes = int(sum(per_session_bytes))
            if per_session_bytes:
                self.metrics.avg_bytes_per_successful_session = statistics.mean(per_session_bytes)
                msgs = [s.message_count for s in key_matched_successful if s.message_count]
                if msgs:
                    self.metrics.avg_messages_per_successful_session = statistics.mean(msgs)

        durations = [s.duration for s in key_matched_successful if s.duration > 0]
        if durations:
            self.metrics.avg_duration = statistics.mean(durations)
            self.metrics.min_duration = min(durations)
            self.metrics.max_duration = max(durations)
        else:
            self.metrics.min_duration = 0.0

        self.metrics.error_count = len(explicit_failed)
        trigger_breakdown: Dict[str, int] = defaultdict(int)
        for s in self.logical_sessions.values():
            trigger_breakdown[s.trigger_reason or "unknown"] += 1
        self.metrics.trigger_breakdown = dict(sorted(trigger_breakdown.items()))

        distance_buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "successful": 0})
        for s in self.logical_sessions.values():
            bucket = self._distance_bucket(s.init_distance_m)
            if not bucket:
                continue
            distance_buckets[bucket]["total"] += 1
            if s.success:
                distance_buckets[bucket]["successful"] += 1
        self.metrics.success_vs_distance = [
            {
                "bucket": bucket,
                "total_sessions": stats["total"],
                "successful_sessions": stats["successful"],
                "success_rate_percent": round(
                    (stats["successful"] / stats["total"] * 100) if stats["total"] else 0.0,
                    2,
                ),
            }
            for bucket, stats in sorted(
                distance_buckets.items(),
                key=lambda item: int(item[0].split("-")[0]),
            )
        ]

        # 重新计算恢复完成率
        failed_candidates = 0
        recovered = 0
        for pair_sessions in by_pair.values():
            ordered_pair = sorted(pair_sessions, key=lambda s: s.start_time)
            for idx, sess in enumerate(ordered_pair):
                if sess.success or getattr(sess, "is_timeout", False):
                    continue  # exclude timeouts from desync recovery metric (channel vs protocol failure)
                failed_candidates += 1
                if any(next_s.success for next_s in ordered_pair[idx + 1 :]):
                    recovered += 1
        self.metrics.recovery_completion_ratio = (
            recovered / failed_candidates if failed_candidates else 0.0
        )

        baseline_successes = [s for s in key_matched_successful if s.trigger_reason != "retry"]
        retry_successes = [s for s in key_matched_successful if s.trigger_reason == "retry"]
        baseline_avg_messages = statistics.mean([s.message_count for s in baseline_successes]) if baseline_successes else 0.0
        baseline_avg_bytes = statistics.mean([s.total_bytes for s in baseline_successes]) if baseline_successes else 0.0
        baseline_avg_duration = statistics.mean([s.duration for s in baseline_successes]) if baseline_successes else 0.0
        retry_avg_messages = statistics.mean([s.message_count for s in retry_successes]) if retry_successes else 0.0
        retry_avg_bytes = statistics.mean([s.total_bytes for s in retry_successes]) if retry_successes else 0.0
        retry_avg_duration = statistics.mean([s.duration for s in retry_successes]) if retry_successes else 0.0
        self.metrics.reauthentication_cost = {
            "retry_successes": len(retry_successes),
            "baseline_successes": len(baseline_successes),
            "avg_messages_retry_success": round(retry_avg_messages, 4),
            "avg_bytes_retry_success": round(retry_avg_bytes, 4),
            "avg_duration_retry_success": round(retry_avg_duration, 4),
            "extra_messages_vs_baseline": round(retry_avg_messages - baseline_avg_messages, 4),
            "extra_bytes_vs_baseline": round(retry_avg_bytes - baseline_avg_bytes, 4),
            "extra_duration_vs_baseline": round(retry_avg_duration - baseline_avg_duration, 4),
        }
        self.metrics.timeout_sessions = len(timeouts)

        for e in self.events:
            if e.phase != D2ZPhase.FAILED:
                continue
            mt = (e.message_type or "").upper()
            step = (e.protocol_step or "").upper()
            if "M1" in mt or "M1" in step:
                self.metrics.m1_errors += 1
            elif "M2" in mt or "M2" in step:
                self.metrics.m2_errors += 1
            elif "M3" in mt or "M4" in mt or "M3_M4" in mt:
                self.metrics.m3_m4_errors += 1

        # 计算Scalability相关指标
        self._calculate_scalability_metrics()

    def _calculate_scalability_metrics(self) -> None:
        """计算Scalability和拓扑动态性指标"""
        # 1. Handover计数和延迟
        handover_events = [e for e in self.events if e.phase.value == "HANDOVER"]
        self.metrics.handover_count = len(handover_events)

        if handover_events:
            latencies = []
            for e in handover_events:
                latency = e.extra_data.get("handover_latency_ms", 0) if hasattr(e, 'extra_data') else 0
                if latency:
                    latencies.append(latency)
            if latencies:
                self.metrics.handover_latency_avg_ms = statistics.mean(latencies)

        # 2. 切换触发的重认证计数
        handover_reauth = [e for e in self.events
                          if e.phase == D2ZPhase.INITIATED
                          and self._classify_trigger(e.protocol_step) == "handover"]
        self.metrics.handover_triggered_reauth_count = len(handover_reauth)

        # 3. 拓扑变化率估算 (links/s/UAV)
        # 基于handover频率和UAV数量估算
        if self.sessions:
            # 计算仿真时长
            sim_times = [e.sim_time for e in self.events if e.sim_time is not None]
            if sim_times:
                sim_duration_s = max(sim_times) - min(sim_times)
                if sim_duration_s > 0:
                    unique_uavs = len(set(s.uav_id for s in self.sessions.values()))
                    if unique_uavs > 0:
                        # 拓扑变化率 = handover次数 / (仿真时长 * UAV数)
                        self.metrics.topology_change_rate = self.metrics.handover_count / (sim_duration_s * unique_uavs)

        # 4. 平均链路持续时间估算
        # 基于成功会话的持续时间和handover频率
        successful_durations = [s.duration for s in self.logical_sessions.values()
                               if s.success and s.duration > 0]
        if successful_durations:
            avg_session_duration = statistics.mean(successful_durations)
            # 链路寿命与会话时长相关，但通常更长（包含空闲时间）
            self.metrics.avg_link_lifetime_s = avg_session_duration * 2  # 估算系数

        # 5. 密度影响评分 (简化版：基于成功率退化)
        # 实际应从配置中读取密度参数，这里用channel_reliability反向估算
        reliability = self.metrics.channel_reliability / 100.0
        # 密度影响 = 1 - 可靠性（高影响意味着高丢包/不稳定）
        self.metrics.density_impact_score = 1.0 - reliability

    def get_summary(self) -> Dict[str, Any]:
        return self.metrics.to_dict()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions[session_id].to_dict() if session_id in self.sessions else None

    def get_all_sessions(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self.logical_sessions.values()]

    def get_session_timeline(
        self,
        uav_id: int,
        zsp_id: int,
        session_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        candidates = [s for s in self.logical_sessions.values() if s.uav_id == uav_id and s.zsp_id == zsp_id]
        if session_id:
            candidates = [
                s
                for s in candidates
                if s.auth_session_id == session_id or s.to_dict().get("session_id") == session_id
            ]
        if not candidates:
            return []
        session = max(candidates, key=lambda s: s.end_time or s.start_time)
        for e in self.events:
            if self._event_in_session(e, session):
                timeline.append(e.to_dict())
        timeline.sort(key=lambda d: (d.get("sim_time", 0), d.get("timestamp", 0)))
        return timeline

    def get_uav_statistics(self, uav_id: int) -> Dict[str, Any]:
        uav_sessions = [s for s in self.logical_sessions.values() if s.uav_id == uav_id]
        if not uav_sessions:
            return {"uav_id": uav_id, "total_sessions": 0}
        successful = [s for s in uav_sessions if s.success]
        return {
            "uav_id": uav_id,
            "total_sessions": len(uav_sessions),
            "successful_sessions": len(successful),
            "failed_sessions": len(uav_sessions) - len(successful),
            "success_rate_percent": round(len(successful) / len(uav_sessions) * 100, 2) if uav_sessions else 0,
            "zsps_connected_to": list({s.zsp_id for s in uav_sessions}),
        }
