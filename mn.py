#!/usr/bin/python2

from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.log import setLogLevel

import netaddr

from pprint import pprint

def to_cidr(ip, subnet):
    """
    :type ip: netaddr.IPAddress
    :type subnet: netaddr.IPNetwork
    """
    masklen = 32
    if isinstance(subnet, netaddr.IPNetwork):
        masklen = subnet.prefixlen
    elif isinstance(subnet, int):
        masklen = subnet
    elif isinstance(subnet, str):
        masklen = subnet.split("/")[1]
    return "{}/{}".format(ip, masklen)


class LinuxRouter(Node):
    def config(self, *args, **kwargs):
        super(LinuxRouter, self).config(*args, **kwargs)
        self.cmd("sysctl net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


class NetworkTopo(Topo):
    def build(self, *args, **kwargs):
        router_ip = "192.168.1.253"
        router_ip_cidr = "{}/{}".format(router_ip, 24)
        router = self.addNode("r0", cls=LinuxRouter, ip=router_ip_cidr)
        s0, router_ip = self.addNetwork("192.168.1.0/24", 4, default_gateway=router_ip)
        self.addLink(s0, router, intfName2="r0-eth1", params2={"ip": router_ip_cidr})

        networks = [
            ("192.168.10.0/24", "r0-eth2", 4),
            ("192.168.100.0/24", "r0-eth3", 4)
        ]
        for subnet, intf, size in networks:
            s, ip = self.addNetwork(subnet, size)
            self.addLink(s, router, intfName2=intf, params2={"ip": to_cidr(ip, subnet)})

        sv = self.addHost("sv", ip="192.168.1.100/24", defaultRoute="via {}".format(router_ip))
        self.addLink(s0, sv)

        # pprint(self.links(sort=True))
        # pprint(self.hosts(sort=True))
        # pprint(self.switches(sort=True))


    def addNetwork(self, subnet, size, default_gateway=None):
        """
        :type subnet: str
        :type size: int
        :type default_gateway: str or None
        :rtype: (Node, netaddr.IPAddress)
        """

        subnet = netaddr.IPNetwork(subnet)
        if default_gateway:
            default_gateway = netaddr.IPAddress(default_gateway)
        else:
            default_gateway = subnet[-2]
        
        sw = self.addSwitch("s{}".format(len(self.switches())))
        for host_id, ip in enumerate(subnet[1:1+size], len(self.hosts())):
            name = "h{}".format(host_id)
            host = self.addHost(name, ip=to_cidr(ip, subnet), defaultRoute="via {}".format(default_gateway))
            self.addLink(sw, host)

        return sw, default_gateway


def main():
    setLogLevel("info")
    topo = NetworkTopo(sopt={"cls": OVSSwitch, "protocols": "OpenFlow13"})
    net = Mininet(topo=topo, controller=RemoteController)
    net.start()
    net["sv"].cmd("python -m SimpleHTTPServer &")
    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
