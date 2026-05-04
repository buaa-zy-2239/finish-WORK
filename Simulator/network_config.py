"""
网络配置模块 - 配置仿真网络环境
"""

from typing import Dict, Any


class NetworkConfigurator:
    """网络配置器"""

    @staticmethod
    def install_internet_stack(nodes) -> None:
        """安装 Internet 协议栈（必须在创建 socket 之前调用）"""
        from ns import ns

        stack = ns.InternetStackHelper()
        stack.Install(nodes)

    @staticmethod
    def setup_network(nodes, config: Dict[str, Any], address_helper) -> Any:
        """设置网络栈（假设协议栈已安装）"""
        from ns import ns

        address_helper.SetBase(ns.Ipv4Address("10.1.1.0"), ns.Ipv4Mask("255.255.255.0"))

        channel_config = config.get("channel", {})
        channel_type = channel_config.get("type", "CSMA")

        if channel_type == "WiFi":
            from .channel_models import ChannelModelFactory
            return ChannelModelFactory.setup_wifi_network(nodes, channel_config, address_helper)
        else:
            channel = ns.CsmaHelper()
            channel.SetChannelAttribute("DataRate", ns.StringValue(channel_config.get("datarate", "100Mbps")))
            channel.SetChannelAttribute("Delay", ns.TimeValue(ns.NanoSeconds(6560)))
            devices = channel.Install(nodes)
            return address_helper.Assign(devices)

    @staticmethod
    def create_nodes(config: Dict[str, Any], user_count: int = 0) -> Any:
        """创建仿真节点"""
        from ns import ns

        uav_count = len(config.get("uavs", []))
        zsp_count = len(config.get("zsps", []))
        total = uav_count + zsp_count + user_count

        nodes = ns.NodeContainer()
        nodes.Create(total)
        return nodes