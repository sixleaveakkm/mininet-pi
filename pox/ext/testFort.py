#!/usr/bin/python
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
from pox.lib.addresses import EthAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

#parts to identify switches dpid
connected = set()
class ConnectionUp(Event):
    def __init__(self,connection,ofp):
        Event.__init__(self)
        self.connection = connection
        self.dpid = connection.dpid
        self.ofp = ofp
        connected.add({'dpid':connection.dpid,'instance':Event})
class ConnectionDown(Event):
    def __init__(self,connection,ofp):
        Event.__init__(self)
        self.connection = connection
        self.dpid = connection.dpid
        connected.remove({'dpid':connection.dpid,'instance':Event})
class MyComponent(object):
    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self,event):
        ConnectionUp(event.connection,event.ofp)
        log.info("Switch %s has come up.",dpid_to_str(event.dpid))

    def _handle_ConnectionDown(self,event):
        ConnectionDown(event.connection,event.dpid)
        log.info("Switch %s has shutdown.",dpid_to_str(event.dpid))
def dump_dpid():
    for dpid in connected:
        log.info("Avalid dpid : %s" , dpid_to_str(dpid))

all_mac = set()

firewall_pattern = set()

def add_mac(mac):
    if mac.is_multicast: return
    if mac.is_bridge_filtered: return
    all_mac.add(mac)

def add_pattern(pattern):
    firewall_pattern.add(pattern)

def match_pattern(parsed):
    #todo
    if parsed.src == "10.0.0.1" and parsed.dst == "10.0.0.3":
        return True

def packet_handler (event):
    add_mac(event.parsed.src)
    add_mac(event.parsed.dst)

    if match_pattern(event.parsed):
        core.getLogger("***Packet matches firewall pattern. BLOCKED")
        return EventHalt

def launch():
    core.registerNew(MyComponent)
    core.openflow.addListenerByName("PacketIn", block_handler)
