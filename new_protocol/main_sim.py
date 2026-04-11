from entities import UAV, GBS
import json
import time


def simulate():
    print("="*60)
    print("🚀 Chameleon-IoD++ 最终修复版仿真")
    print("="*60)

    gbs = GBS()
    uav = UAV("UAV1", b"hardware_seed")

    idx = gbs.enroll_uav(uav)
    print("注册 idx:", idx[:16])

    # =====================
    # 正常认证
    # =====================
    print("\n[阶段1] 正常认证")

    m1 = uav.generate_m1("DATA")
    sess = gbs.process_m1(m1)

    if not sess:
        print("❌ M1 失败")
        return

    m2 = gbs.generate_m2(sess)

    ok = uav.process_m2(m2, json.loads(m1)["nonce"])
    print("认证结果:", ok)

    # =====================
    # 丢包 + 自愈
    # =====================
    print("\n[阶段2] 丢包 + 自愈")

    m1 = uav.generate_m1("DATA2")
    sess = gbs.process_m1(m1)

    gbs.generate_m2(sess)  # 丢弃
    print("💥 M2 丢失")

    time.sleep(1)

    m1_retry = uav.generate_m1("RETRY")
    sess2 = gbs.process_m1(m1_retry)

    if sess2 and sess2["is_bak"]:
        print("🛡️ 触发自愈")

        m2 = gbs.generate_m2(sess2)
        ok = uav.process_m2(m2, json.loads(m1_retry)["nonce"])

        print("自愈结果:", ok)


if __name__ == "__main__":
    simulate()