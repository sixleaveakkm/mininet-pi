"""
Block TCP ports

Save as ext/blocker.py and run along with l2_learning.

You can specify ports to block on the commandline:
./pox.py forwarding.l2_learing blocker --ports=80,8888,8000

Alternatively, if you run with the "py" component, you can use the CLI:
./pox.py forwarding.l2_learning blocker py
...
pox> block(80,8888,8000)
"""

from pox.core import core

# A set of ports to block
block_ports = set()

def block_handler (event):
	#Handles packet event and kills the ones with a blocked port number

	tcpp = event.parsed.find('tcp')
	if not tcpp: return # Not TCP
	if tcpp.srcport in block_ports or tcpp.dstport in block_ports:
		#Halt the event, stopping l2_learning from seeing it
		#(and installing a table entry for it)
		core.getLogger("blocker").debug("Blocked TCP %s <-> %s",
		tcpp.srcport, tcpp.dstport)
		event.halt = True

def unblock (*ports):
	block_ports.difference_update(ports)

def block (*ports):
	block_ports.update(ports)

def launch(ports = ''):

	#Add ports from commandline to list of ports to block
	block_ports.update(int(x) for x in ports.replce(",", " ").split())

	#Add functions to Interactive so when you run POX with py, you can
	#easily add/remove ports to block.
	core.Interactive.variables['block'] = block
	core.Interactive.variables['unblock'] = unblock

	#Listen to packet events
	core.openflow.addListenerByName("PacketIn", block_handler)
