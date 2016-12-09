from switchyard.lib.testing import Scenario, PacketInputEvent, PacketOutputEvent, PacketInputTimeoutEvent
from switchyard.lib.packet import *
import copy

def mk_pkt(hwsrc, hwdst, arp = False, arpsenderhwaddr='', arptargethwaddr='', arpsenderprotoaddr='', arptargetprotoaddr='', ipsrc='', ipdst='', reply=False, error=False,icmp_type='',orig_pkt=None):

    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)

    
    if (arp == False):
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
            if not error:
        	    icmppkt.icmptype = ICMPType.EchoRequest
            elif str(orig_pkt) != '':
                if icmp_type=="DestinationUnreachable":
                    icmppkt.icmptype = ICMPType.DestinationUnreachable
                    icmppkt.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable

                ether_header = orig_pkt.get_header_index(Ethernet)
                ip_header = orig_pkt.get_header_index(IPv4)
                #del orig_pkt[ether_header]
                icmppkt.icmpdata.data = orig_pkt[ip_header].to_bytes()[:28]
                icmppkt.icmpdata.origdgramlen = len(orig_pkt)  # This should be optional probably


    	return ether + ippkt + icmppkt
    else:
    	ether.ethertype = EtherType.ARP
    	arph = Arp()
    	arph.senderhwaddr = arpsenderhwaddr
    	arph.targethwaddr = arptargethwaddr
    	if arptargethwaddr == 'ff:ff:ff:ff:ff:ff':
    		arph.operation = ArpOperation.Request
    	else:	
    		arph.operation = ArpOperation.Reply
    	arph.senderprotoaddr = arpsenderprotoaddr
    	arph.targetprotoaddr = arptargetprotoaddr
	
    	return ether + arph

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    # hwdst (hwsrc), ipsrc (ipdst), ipdst (ipsrc) come from arpreq

    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply


def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt 



def create_scenario():
    s = Scenario("router tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.0.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2''')

    #Test item 1, 2, 3

    reqpkt = mk_ping("20:00:00:00:00:01", "10:00:00:00:00:01", '192.168.1.100','172.16.42.2', ttl=64)
    reqpkt2 = copy.deepcopy(reqpkt)
    reqpkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:03")
    reqpkt2.get_header(Ethernet).dst = EthAddr("30:00:00:00:00:01")

    arpreq = create_ip_arp_request("10:00:00:00:00:03", "172.16.42.1", "172.16.42.2")
    arpresp = mk_arpresp(arpreq, "30:00:00:00:00:01") # , "10:00:00:00:00:03", "172.16.42.2", "172.16.42.1")

    arpreq2 = create_ip_arp_request("10:00:00:00:00:01", "192.168.1.1", "192.168.1.100")
    arpresp2 = mk_arpresp(arpreq2, "20:00:00:00:00:01") # , "10:00:00:00:00:01", "192.168.1.100", "192.168.1.1")

    resppkt = mk_ping("30:00:00:00:00:01", "10:00:00:00:00:03", '172.16.42.2', '192.168.1.100', reply=True, ttl=64)
    resppkt2 = copy.deepcopy(resppkt)
    resppkt2.get_header(Ethernet).src = EthAddr("10:00:00:00:00:01")
    resppkt2.get_header(Ethernet).dst = EthAddr("20:00:00:00:00:01")
    ttlmatcher = '''lambda pkt: pkt.get_header(IPv4).ttl == 63'''

    s.expect(PacketInputEvent("router-eth0", reqpkt, display=IPv4), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth2", arpreq, display=Arp), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")
    s.expect(PacketInputEvent("router-eth2", arpresp, display=Arp), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")
    s.expect(PacketOutputEvent("router-eth2", reqpkt2, display=IPv4, exact=False, predicates=[ttlmatcher]), "IP packet should be forwarded to 172.16.42.2 out router-eth2")
    s.expect(PacketInputEvent("router-eth2", resppkt, display=IPv4), "IP packet to be forwarded to 192.168.1.100 should arrive on router-eth2")
    s.expect(PacketOutputEvent("router-eth0", arpreq2, display=Arp), "Router should send ARP request for 192.168.1.100 out router-eth0")
    s.expect(PacketInputEvent("router-eth0", arpresp2, display=Arp), "Router should receive ARP response for 192.168.1.100 on router-eth0")
    s.expect(PacketOutputEvent("router-eth0", resppkt2, display=IPv4, exact=False, predicates=[ttlmatcher]), "IP packet should be forwarded to 192.168.1.100 out router-eth0")

    #Test item 2, 3, 4, 5
    testpkt_1 = mk_pkt("06:07:08:09:0a:0b", "10:00:00:00:00:02", False, "","","","", "192.168.1.239", "10.10.50.250")
    s.expect(PacketInputEvent("router-eth0", testpkt_1), "IP packet for 10.10.50.250 arrives on eth0.")
    testpkt_arp1 = mk_pkt("10:00:00:00:00:2", "ff:ff:ff:ff:ff:ff", True, "10:00:00:00:00:02", "ff:ff:ff:ff:ff:ff", "10.10.0.1", "10.10.50.250")
    s.expect(PacketOutputEvent("router-eth1", testpkt_arp1), "ARP request for 10.10.50.250 sent on eth1")
    
    testpkt_2 = mk_pkt( "ab:cd:ef:ab:cd:ef", "10:00:00:00:00:03", False, "","","","", "172.16.42.12", "172.16.4.3")
    s.expect(PacketInputEvent("router-eth2", testpkt_2), "IP packet for 172.16.42.3 arrives on eth2. Host 172.16.4.3 does not exist")
    testpkt_arp2 = mk_pkt("10:00:00:00:00:1", "ff:ff:ff:ff:ff:ff", True, "10:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "192.168.1.2")
    s.expect(PacketOutputEvent("router-eth0", testpkt_arp2), "ARP request for 192.168.1.2 sent on eth0")

    s.expect(PacketInputTimeoutEvent(1.5), "The router should timeout on recv_packet")
    s.expect(PacketOutputEvent("router-eth1", testpkt_arp1), "ARP request for 10.10.50.250 sent on eth1")
    s.expect(PacketOutputEvent("router-eth0", testpkt_arp2), "ARP request for 192.168.1.2 sent on eth0")
    s.expect(PacketInputEvent("router-eth2", testpkt_2), "IP packet for 172.16.42.3 arrives on eth2. Host 172.16.4.3 does not exist")
    
    s.expect(PacketInputTimeoutEvent(1.5), "The router should timeout on recv_packet")
    s.expect(PacketOutputEvent("router-eth1", testpkt_arp1), "ARP request for 10.10.50.250 sent on eth1")
    s.expect(PacketOutputEvent("router-eth0", testpkt_arp2), "ARP request for 192.168.1.2 sent on eth0")

    s.expect(PacketInputEvent("router-eth0", testpkt_1), "IP packet for 10.10.50.250 arrives on eth0.")

    s.expect(PacketInputTimeoutEvent(1.5), "The router should timeout on recv_packet")
    s.expect(PacketOutputEvent("router-eth1", testpkt_arp1), "ARP request for 10.10.50.250 sent on eth1")
    s.expect(PacketOutputEvent("router-eth0", testpkt_arp2), "ARP request for 192.168.1.2 sent on eth0")

    
    s.expect(PacketInputEvent("router-eth0", testpkt_1), "IP packet for 10.10.50.250 arrives on eth0.")

    s.expect(PacketInputTimeoutEvent(1.5), "The router should timeout on recv_packet")
    s.expect(PacketOutputEvent("router-eth1", testpkt_arp1), "ARP request for 10.10.50.250 sent on eth1")
    s.expect(PacketOutputEvent("router-eth0", testpkt_arp2), "ARP request for 192.168.1.2 sent on eth0")
    s.expect(PacketInputTimeoutEvent(1.5), "The router should timeout on recv_packet")




    return s

scenario = create_scenario()
