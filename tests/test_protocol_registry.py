from Common.protocol_registry import get_protocol_spec, list_supported_protocols


def test_protocol_registry_exposes_three_protocols():
    supported = list_supported_protocols()
    assert "PMAP" in supported
    assert "PMAP_ACK" in supported
    assert "STATIC_BASELINE" in supported
    assert "RLBA_UAV" in supported


def test_protocol_registry_defaults_and_options():
    assert get_protocol_spec("unknown").name == "PMAP"
    assert get_protocol_spec("PMAP_ACK").builder_options["d2z_ack_mode"] is True
    assert get_protocol_spec("STATIC_BASELINE").analysis_family == "D2Z"
    assert get_protocol_spec("RLBA_UAV").display_name == "RLBA-UAV"
