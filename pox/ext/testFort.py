#!/usr/bin/python
from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.revent import *
from pox.lib.addresses import EthAddr, IPAddr
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

#parts to identify switches dpid
connected = set()
connections = set()
class ConnectionUp(Event):
    def __init__(self,connection,ofp):
        Event.__init__(self)
        self.connection = connection
        self.dpid = connection.dpid
        self.ofp = ofp
        connections.add(connection)
        connected.add(connection.dpid)
class ConnectionDown(Event):
    def __init__(self,connection,ofp):
        Event.__init__(self)
        self.connection = connection
        self.dpid = connection.dpid
        connected.remove(connection.dpid)
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
	mark = False
	ipv4v = parsed.find('ipv4')
	tcpp = parsed.find('tcp')
	if not ipv4v: return
	if not tcpp: return
	if ipv4v.srcip == "10.0.0.2" and ipv4v.dstip == "10.0.0.4":
		mark = True
	if tcpp.dstport == 80 and mark == True:
		return True

def packet_handler (event):
    add_mac(event.parsed.src)
    add_mac(event.parsed.dst)

    if match_pattern(event.parsed):
        log.info("***Packet matches firewall pattern. BLOCKED")
        return EventHalt
def flow_add():
	my_match = of.ofp_match()
	my_match.nw_src = IPAddr("10.0.0.2")
	my_match.nw_dst = IPAddr("10.0.0.3")
	my_match.dl_type=0x800
	msg = of.ofp_flow_mod()
	msg.match = my_match
	msg.actions.append(of.ofp_action_nw_addr.set_src(IPAddr("10.0.0.4")))
	log.info("msg builded")
	for conn in core.openflow.connections:
		log.info("in connections loop")
		conn.send(msg)
	match_2 = of.ofp_match()
	match_2.nw_src = IPAddr("10.0.0.1")
	match_2.nw_dst = IPAddr("10.0.0.4")
	match_2.dl_type = 0x800
	msg2 = of.ofp_flow_mod()
	msg2.match = match_2
	msg2.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr("10.0.0.4")))
	for conn in core.openflow.connections:
		conn.send(msg2)
	match3 = of.ofp_match()
	match3.nw_src = IPAddr("10.0.0.4")
	match3.nw_dst = IPAddr("10.0.0.1")
	match3.dl_type = 0x800
	msg3 = of.ofp_flow_mod()
	msg3.match = match3
	msg3.actions.append(of.ofp_action_nw_addr.set_dst(IPAddr("10.0.0.2")))
	for conn in core.openflow.connections:
		conn.send(msg3)
def launch():
    core.registerNew(MyComponent)
    core.openflow.addListenerByName("PacketIn", packet_handler)
    core.Interactive.variables['flow_add'] = flow_add
