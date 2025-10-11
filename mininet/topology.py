#!/usr/bin/python3
"""
Mininet topology with realistic network conditions,
remote controller, and host xterm popups.
"""

from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.term import makeTerm
from mininet.cli import CLI
from time import sleep


CONTROLLER_IP = '192.168.56.1'


class RealisticTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Link parameters
        link_opts = dict(
            cls=TCLink,
            bw=10,              # Bandwidth 10 Mbps
            delay='20ms',       # Base latency
            jitter='5ms',       # Variable latency
            loss=2,             # 2% packet loss
            max_queue_size=50,
            use_htb=True
        )

        # Connect hosts to switches
        self.addLink(h1, s1, **link_opts)
        self.addLink(h2, s2, **link_opts)

        # Connect switches together
        self.addLink(s1, s2, **link_opts)


def run():
    setLogLevel('info')

    c0 = RemoteController('c0', ip=CONTROLLER_IP, port=6633)
    topo = RealisticTopo()
    net = Mininet(topo=topo, controller=c0, link=TCLink)

    net.start()

    info("Testing network connectivity...\n")
    net.pingAll()

    info("Running iperf test (TCP bandwidth)...\n")
    h1, h2 = net.get('h1', 'h2')
    net.iperf((h1, h2))

    info("Tests completed.\n")
    makeTerm(h1)
    makeTerm(h2)
    makeTerm(net.get('s1'))
    makeTerm(net.get('s2'))
    CLI(net)

    net.stop()


if __name__ == '__main__':
    run()

# Make the topology available for `mn --custom`
topos = {'realistic': (lambda: RealisticTopo())}
