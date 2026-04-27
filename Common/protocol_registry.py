import importlib
from dataclasses import dataclass, field
from typing import Any, Dict, Type


@dataclass(frozen=True)
class ProtocolSpec:
    name: str
    display_name: str
    uav_class_path: str
    zsp_class_path: str
    builder_options: Dict[str, Any] = field(default_factory=dict)
    analysis_family: str = "D2Z"

    @property
    def uav_class(self) -> Type:
        module_name, class_name = self.uav_class_path.rsplit(".", 1)
        return getattr(importlib.import_module(module_name), class_name)

    @property
    def zsp_class(self) -> Type:
        module_name, class_name = self.zsp_class_path.rsplit(".", 1)
        return getattr(importlib.import_module(module_name), class_name)


_PROTOCOLS: Dict[str, ProtocolSpec] = {
    "PMAP": ProtocolSpec(
        name="PMAP",
        display_name="PMAP",
        uav_class_path="Entity.UAV.PMAPUAV.PMAP_UAV",
        zsp_class_path="Entity.ZSP.PMAPZSP.PMAP_ZSP",
        builder_options={"d2z_ack_mode": False},
        analysis_family="D2Z",
    ),
    "PMAP_ACK": ProtocolSpec(
        name="PMAP_ACK",
        display_name="PMAP_ACK",
        uav_class_path="Entity.UAV.PMAPUAV.PMAP_UAV",
        zsp_class_path="Entity.ZSP.PMAPZSP.PMAP_ZSP",
        builder_options={"d2z_ack_mode": True},
        analysis_family="D2Z",
    ),
    "STATIC_BASELINE": ProtocolSpec(
        name="STATIC_BASELINE",
        display_name="STATIC_BASELINE",
        uav_class_path="Entity.UAV.StaticBaselineUAV.StaticBaselineUAV",
        zsp_class_path="Entity.ZSP.StaticBaselineZSP.StaticBaselineZSP",
        builder_options={},
        analysis_family="D2Z",
    ),
    "RLBA_UAV": ProtocolSpec(
        name="RLBA_UAV",
        display_name="RLBA-UAV",
        uav_class_path="Entity.UAV.RLBAUAV.RLBAUAV",
        zsp_class_path="Entity.ZSP.RLBAZSP.RLBAZSP",
        builder_options={},
        analysis_family="D2Z",
    ),
    "RLBA_3WAY": ProtocolSpec(
        name="RLBA_3WAY",
        display_name="RLBA-3WAY",
        uav_class_path="Entity.UAV.RLBAUAV.RLBAUAV",
        zsp_class_path="Entity.ZSP.RLBAZSP.RLBAZSP",
        builder_options={},
        analysis_family="D2Z",
    ),
}


def list_supported_protocols() -> list[str]:
    return sorted(_PROTOCOLS.keys())


def get_protocol_spec(protocol_name: str | None) -> ProtocolSpec:
    name = (protocol_name or "PMAP").strip().upper()
    return _PROTOCOLS.get(name, _PROTOCOLS["PMAP"])
