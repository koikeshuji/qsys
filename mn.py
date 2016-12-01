#!/usr/bin/python2

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch


class NetworkTopo(Topo):
    def build(self, *args, **kwargs):
        s1 = self.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow13")
        self.addHost("h1", ip="192.168.1.1/24")
        self.addHost("h2", ip="192.168.1.2/24")
        self.addHost("h3", ip="192.168.1.3/24")
        self.addHost("h4", ip="192.168.1.4/24")
        self.addHost("sv", ip="192.168.1.100/24")
        
        for host in self.hosts():
            self.addLink(s1, host) 


def main():
    topo = NetworkTopo()
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()
    net["sv"].cmd("python -m SimpleHTTPServer &")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
