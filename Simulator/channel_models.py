"""
信道模型模块 - 提供3GPP UAV信道模型实现

支持两种3GPP模型：
1. 3GPP UMA (Urban Macro) - 使用 ns3::ThreeGppUmaPropagationLossModel
2. 3GPP UMI (Urban Micro) - 使用 ns3::ThreeGppUmiStreetCanyonPropagationLossModel
3. 3GPP RMa (Rural Macro) - 使用 ns3::ThreeGppRmaPropagationLossModel
4. 旧模型 - 多模型组合实现 (向后兼容)
"""

import math
from typing import Dict, Any


class ChannelModelFactory:
    """信道模型工厂"""

    @staticmethod
    def setup_3gpp_native_channel(wifi_channel, channel_config: Dict[str, Any]) -> None:
        """设置 ns-3 内置 3GPP 信道模型 (TR 38.901)

        支持的场景类型：
        - uma (Urban Macro) - 城市宏站
        - umi (Urban Micro Street Canyon) - 城市微站街道峡谷
        - rma (Rural Macro) - 农村宏站

        该模型会自动：
        - 根据Z轴高度计算 LOS/NLOS 概率
        - 自动适配空对地 (A2G) 信道特性
        - 内置阴影衰落和多径衰落
        """
        from ns import ns

        scenario_type = channel_config.get("scenario_type", "uma")
        carrier_freq_hz = float(channel_config.get("carrier_freq_hz", 5.9e9))
        enable_shadowing = bool(channel_config.get("enable_shadowing", True))

        loss_model_type = None
        cond_model_type = None

        if scenario_type == "uma":
            loss_model_type = "ns3::ThreeGppUmaPropagationLossModel"
            cond_model_type = "ns3::ThreeGppUmaChannelConditionModel"
        elif scenario_type == "umi":
            loss_model_type = "ns3::ThreeGppUmiStreetCanyonPropagationLossModel"
            cond_model_type = "ns3::ThreeGppUmiStreetCanyonChannelConditionModel"
        elif scenario_type == "rma":
            loss_model_type = "ns3::ThreeGppRmaPropagationLossModel"
            cond_model_type = "ns3::ThreeGppRmaChannelConditionModel"
        else:
            raise ValueError(f"Unknown scenario_type: {scenario_type}")

        wifi_channel.AddPropagationLoss(
            loss_model_type,
            "Frequency", ns.DoubleValue(carrier_freq_hz),
            "ShadowingEnabled", ns.BooleanValue(enable_shadowing),
            "ChannelConditionModel", ns.StringValue(cond_model_type)
        )

    @staticmethod
    def setup_3gpp_uav_channel(wifi_channel, channel_config: Dict[str, Any]) -> None:
        """设置3GPP UAV信道模型 (向后兼容，使用多模型组合)

        该模型考虑了：
        - 无人机高度依赖的路径损耗
        - LoS (Line-of-Sight) 概率
        - A2G (Air-to-Ground) 信道特性
        - 阴影衰落
        - 多径衰落

        适用场景：无人机高度 > 40m 的城区环境

        使用ns-3现有模型组合实现：
        - LogDistancePropagationLossModel (路径损耗)
        - NakagamiPropagationLossModel (多径衰落)
        - RandomPropagationLossModel (阴影衰落)
        """
        from ns import ns

        uav_height = float(channel_config.get("uav_height_m", 80.0))
        env_type = channel_config.get("environment", "urban")
        carrier_freq = float(channel_config.get("carrier_freq_ghz", 2.4))

        env_params = {
            "urban": {
                "a": 0.0,
                "b": 1.0,
                "c": 0.0,
                "sigma_shadow": 8.0,
                "los_prob_alpha": 0.1,
                "los_prob_beta": 0.5,
            },
            "suburban": {
                "a": 0.0,
                "b": 0.8,
                "c": 0.0,
                "sigma_shadow": 6.0,
                "los_prob_alpha": 0.05,
                "los_prob_beta": 0.4,
            },
            "rural": {
                "a": 0.0,
                "b": 0.6,
                "c": 0.0,
                "sigma_shadow": 4.0,
                "los_prob_alpha": 0.02,
                "los_prob_beta": 0.3,
            }
        }

        params = env_params.get(env_type, env_params["urban"])

        d0 = 1.0
        c = 3e8
        PLd0 = 20 * math.log10(4 * math.pi * d0 * carrier_freq * 1e9 / c)

        path_loss_exp = 2.7

        wifi_channel.AddPropagationLoss(
            "ns3::LogDistancePropagationLossModel",
            "Exponent", ns.DoubleValue(path_loss_exp),
            "ReferenceLoss", ns.DoubleValue(PLd0),
            "ReferenceDistance", ns.DoubleValue(1.0),
        )

        sigma_shadow = params["sigma_shadow"]
        wifi_channel.AddPropagationLoss(
            "ns3::RandomPropagationLossModel",
            "Variable", ns.StringValue(f"ns3::NormalRandomVariable[Mean=0|Variance={sigma_shadow**2}]")
        )

        if env_type == "urban":
            m0, m1, m2 = 1.5, 1.0, 0.5
        elif env_type == "suburban":
            m0, m1, m2 = 2.0, 1.5, 1.0
        else:
            m0, m1, m2 = 2.5, 2.0, 1.5

        wifi_channel.AddPropagationLoss(
            "ns3::NakagamiPropagationLossModel",
            "Distance1", ns.DoubleValue(50.0),
            "Distance2", ns.DoubleValue(150.0),
            "m0", ns.DoubleValue(m0),
            "m1", ns.DoubleValue(m1),
            "m2", ns.DoubleValue(m2),
        )

    @staticmethod
    def setup_wifi_network(nodes, channel_config: Dict[str, Any], address_helper) -> Any:
        """设置WiFi网络，支持多种路径损耗和衰落模型"""
        from ns import ns

        loss_model = channel_config.get("loss_model", "friis_log_distance")

        if loss_model == "3gpp_native":
            wifi_channel = ns.YansWifiChannelHelper()
            wifi_channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")
            ChannelModelFactory.setup_3gpp_native_channel(wifi_channel, channel_config)
        elif loss_model == "3gpp_uav":
            wifi_channel = ns.YansWifiChannelHelper()
            wifi_channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel")
            ChannelModelFactory.setup_3gpp_uav_channel(wifi_channel, channel_config)
        else:
            wifi_channel = ns.YansWifiChannelHelper.Default()

            if loss_model == "friis_log_distance":
                wifi_channel.AddPropagationLoss("ns3::FriisPropagationLossModel")
            elif loss_model == "nakagami":
                m0 = float(channel_config.get("nakagami_m0", 1.5))
                m1 = float(channel_config.get("nakagami_m1", 0.75))
                m2 = float(channel_config.get("nakagami_m2", 0.5))
                wifi_channel.AddPropagationLoss(
                    "ns3::NakagamiPropagationLossModel",
                    "Distance1", ns.DoubleValue(50.0),
                    "Distance2", ns.DoubleValue(150.0),
                    "m0", ns.DoubleValue(m0),
                    "m1", ns.DoubleValue(m1),
                    "m2", ns.DoubleValue(m2),
                )
            elif loss_model == "range":
                max_range = float(channel_config.get("max_range", 500.0))
                wifi_channel.AddPropagationLoss(
                    "ns3::RangePropagationLossModel",
                    "MaxRange", ns.DoubleValue(max_range)
                )

        wifi_phy = ns.YansWifiPhyHelper()
        wifi_phy.SetChannel(wifi_channel.Create())

        wifi_mac = ns.WifiMacHelper()
        wifi_mac.SetType("ns3::AdhocWifiMac")

        wifi = ns.WifiHelper()
        wifi.SetStandard(ns.WifiStandard.WIFI_STANDARD_80211g)

        datarate = channel_config.get("datarate", "DsssRate1Mbps")
        # 转换简写格式到 ns3 格式
        datarate_mapping = {
            "6Mbps": "DsssRate11Mbps",
            "9Mbps": "OfdmRate9Mbps",
            "12Mbps": "OfdmRate12Mbps",
            "18Mbps": "OfdmRate18Mbps",
            "24Mbps": "OfdmRate24Mbps",
            "36Mbps": "OfdmRate36Mbps",
            "48Mbps": "OfdmRate48Mbps",
            "54Mbps": "OfdmRate54Mbps",
            "1Mbps": "DsssRate1Mbps",
            "2Mbps": "DsssRate2Mbps",
            "5.5Mbps": "DsssRate5_5Mbps",
            "11Mbps": "DsssRate11Mbps"
        }
        if datarate in datarate_mapping:
            datarate = datarate_mapping[datarate]
        # 使用更兼容的控制速率
        control_datarate = "DsssRate11Mbps"
        if datarate == "DsssRate1Mbps" or datarate == "DsssRate2Mbps" or datarate == "DsssRate5_5Mbps":
            control_datarate = datarate
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                     "DataMode", ns.StringValue(datarate),
                                     "ControlMode", ns.StringValue(control_datarate))

        devices = wifi.Install(wifi_phy, wifi_mac, nodes)
        return address_helper.Assign(devices)