"""

Two directly connected switches plus a host for each switch , with controller:

   h1 --- s1 ---------- s2 ---  h2
            \           / \
             \         /   \ h3
              controller


Test items:
* pingall

"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSSwitch , OVSController, Ryu
from mininet.cli import CLI


topo = Topo()
s1 = topo.addSwitch('s1' , cls=OVSSwitch)
s2 = topo.addSwitch('s2' , cls=OVSSwitch)

h1 = topo.addNode('h1')
h2 = topo.addNode('h2')
h3 = topo.addNode('h3')

c1 = Ryu('c1',port=6633)

topo.addLink(s1 , h1)
topo.addLink(s2 , h2)
topo.addLink(s2 , h3)
topo.addLink(s1 , s2)

net = Mininet(topo=topo, switch=OVSSwitch,build=false)
net.addController(c1)
net.build()
net.start()
CLI(net)
net.stop()