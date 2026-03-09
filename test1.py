# platform_runner.py
from scenario_steps import *


def run_scenario(cfg):
    topo = build_topology(cfg)
    entities = load_entities(cfg, topo)
    pre_register(cfg, entities)
    bind_links(cfg, entities)
    schedule_auth(cfg, entities)
    run_simulation(cfg)
    verify_result(entities)
    
if __name__ == "__main__" :
    cfg = {
        "protocol": "PMAP",
        "uav_count": 1,
        "zsp_count": 1,
        "datarate": "5Mbps",
        "delay": "2ms",
        "auth_delay": 3.0,
        "stop_time": 3.5
    }

    run_scenario(cfg)
