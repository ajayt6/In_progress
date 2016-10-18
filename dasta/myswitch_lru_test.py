from switchyard.lib.testing import Scenario, PacketInputEvent, PacketOutputEvent
from switchyard.lib.packet import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest

    return ether + ippkt + icmppkt

def create_scenario():
	s = Scenario("switch tests for LRU mechanism")
	s.add_interface('eth0', '10:00:00:00:00:01')
	s.add_interface('eth1', '10:00:00:00:00:02')
	s.add_interface('eth2', '10:00:00:00:00:03')

	#1
	testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255") 
	s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An Ethernet frame with a broadcast destination address should arrive on eth1")
	s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet), "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")

	#2
	testpkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:02", "172.16.42.1", "172.16.42.2")
	s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "An ethernet frame from 1 to 2 arrives on eth0")
	s.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 2")

	#3
	testpkt = mk_pkt("30:00:00:00:00:03", "30:00:00:00:00:01", "172.16.42.3", "172.16.42.1")
	s.expect(PacketInputEvent("eth2", testpkt, display=Ethernet), "An ethernet frame from 3 to 1 arrives on eth2")
	s.expect(PacketOutputEvent("eth0", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 2")

	#4
	testpkt = mk_pkt("30:00:00:00:00:04", "10:00:00:00:00:01", "172.16.42.4", "172.0.0.0")
	s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "An ethernet frame from 4 to switch arrives on eth0")

	#5
	testpkt = mk_pkt("30:00:00:00:00:05", "30:00:00:00:00:02", "172.16.42.5", "172.16.42.2")
	s.expect(PacketInputEvent("eth2", testpkt, display=Ethernet), "An ethernet frame from 5 to 2 arrives on eth2")
	s.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 2")

	#6
	testpkt = mk_pkt("30:00:00:00:00:06", "30:00:00:00:00:03", "172.16.42.6", "172.16.42.3")
	s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An ethernet frame from 6 to 3 arrives on eth1")
	s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet), "Frame sent out on all ports except eth1")
	
	#7
	testpkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:02", "172.16.42.1", "172.16.42.2")
	s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "An ethernet frame from 1 to 2 arrives on eth1")
	s.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 2")

	#8
	testpkt = mk_pkt("30:00:00:00:00:05", "30:00:00:00:00:1", "172.16.42.5", "172.16.42.1")
	s.expect(PacketInputEvent("eth2", testpkt, display=Ethernet), "An ethernet frame from 5 to 1 arrives on eth2")
	s.expect(PacketOutputEvent("eth1", testpkt, display=Ethernet), "Frame sent out on eth1 outbound for 1")
	return s

scenario = create_scenario()
