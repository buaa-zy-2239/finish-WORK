# ns3_bridge.py
from ns import ns
import cppyy

_registry = {}

def register_obj(obj_id, obj):
    _registry[obj_id] = obj

def _bridge_call(obj_id, method_name):
    obj = _registry.get(obj_id)
    if obj:
        getattr(obj, method_name)()

def schedule_method(obj_id, method_name, time_sec):
    cb = cppyy.gbl.std.function['void()'](
        lambda: _bridge_call(obj_id, method_name)
    )
    ns.Simulator.Schedule(ns.Seconds(time_sec), cb)

def _recv_bridge(obj_id):
    obj = _registry.get(obj_id)
    if obj:
        obj._HandleRead(obj.m_socket)

def bind_recv_callback(socket, obj_id):
    cb = cppyy.gbl.std.function['void()'](
        lambda: _recv_bridge(obj_id)
    )
    socket.SetRecvCallback(cb)
