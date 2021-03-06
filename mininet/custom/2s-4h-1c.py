"""

Two directly connected switches plus a host for each switch , with controller:

   h1 --- s1 ---------- s2 ---  h4
         /  \           / \
      h2/    \         /   \ h3
              controller


"""

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import OVSSwitch , OVSController, Ryu, RemoteController
from mininet.cli import CLI


topo = Topo()
s1 = topo.addSwitch('s1' , cls=OVSSwitch)
s2 = topo.addSwitch('s2' , cls=OVSSwitch)

h1 = topo.addNode('h1')
h2 = topo.addNode('h2')
h3 = topo.addNode('h3')
h4 = topo.addNode('h4')

c1 = RemoteController('c1',port=6633)

topo.addLink(s1 , h1)
topo.addLink(s1 , h2)
topo.addLink(s2 , h3)
topo.addLink(s2 , h4)
topo.addLink(s1 , s2)

net = Mininet(topo=topo, switch=OVSSwitch, build=False)
net.addController(c1)
net.build()
net.start()
CLI(net)
net.stop()
