#!/usr/bin/env python3

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
	def __init__(self, net):
		self.net = net
		self.interfaces = net.interfaces()
		self.ip_mac_dict = {}
		self.fwd_table = {}
		self.buffer = {}
		self.buffer_info = {} #List of port, time, arppacket for resend, count, src ip of original sender, icoming port of original packet
		
		#Use static forwarding table
		f = open('forwarding_table.txt', 'r')
		data = f.readlines()
		for line in data:
			item = line.replace("\n", "").split(" ")
			if item[0] not in self.fwd_table:
				self.fwd_table[item[0]] = [item[1], item[2], item[3]]

		#Add entries to fwd table corresponding to interfaces on the router
		for intf in self.interfaces:
			if intf.ipaddr not in self.fwd_table:
				netaddr = IPv4Address(int(IPv4Address(intf.netmask)) & int(IPv4Address(intf.ipaddr)))
				self.fwd_table[netaddr] = [str(intf.netmask), str(intf.ipaddr), intf.name]
				#print(intf.netmask, str(intf.netmask), intf.ipaddr, str(intf.ipaddr), netaddr)

		#Uncomment to see the entries in the forwarding table
		#for item in self.fwd_table:
		#	print (item, self.fwd_table[item])

	def router_forward(self,dev,pkt):
		arp = pkt.get_header(Arp)
		if arp is not None:
			# ---------------------------------Item 1 starts here-------------------------------------------
			if arp.operation == ArpOperation.Request:  # Handle ARP request
				if not arp.senderprotoaddr in self.ip_mac_dict:
					self.ip_mac_dict[arp.senderprotoaddr] = arp.senderhwaddr

				myIPs = [intf.ipaddr for intf in self.interfaces]
				if arp.targetprotoaddr in myIPs:
					target_intf = myIPs.index(arp.targetprotoaddr)
					targetMAC = self.interfaces[target_intf].ethaddr
					pkt = create_ip_arp_reply(targetMAC, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
					self.net.send_packet(dev, pkt)
			# ----------------------------------Item 1 ends here----------------------------------------------

			# ------------------------------------- Item 3 starts here---------------------------------------
			elif arp.operation == ArpOperation.Reply:  # Handle ARP Reply
				if not arp.senderprotoaddr in self.ip_mac_dict:
					self.ip_mac_dict[arp.senderprotoaddr] = arp.senderhwaddr
				if not arp.targetprotoaddr in self.ip_mac_dict:
					self.ip_mac_dict[arp.targetprotoaddr] = arp.targethwaddr

				if str(arp.senderprotoaddr) in self.buffer:
					for buffer_pkt in self.buffer[str(arp.senderprotoaddr)]:
						port = self.buffer_info[str(arp.senderprotoaddr)][0]
						eth_index = buffer_pkt.get_header_index(Ethernet)
						ether = buffer_pkt.get_header(Ethernet)
						del buffer_pkt[eth_index]

						# modify MAC headers,src : MAC address of router interface
						# dst : MAC address of next hop
						ether.dst = arp.senderhwaddr
						names = [intf.name for intf in self.interfaces]
						port_index = names.index(port)
						ether.src = self.interfaces[port_index].ethaddr
						buffer_pkt.insert_header(eth_index, ether)
						self.net.send_packet(port, buffer_pkt)
					# ---------------------------------------Item 3 ends here ---------------------------------------------
		else:
			log_debug("No ARP headers in the packet")

		# --------------------------------------Item 2 starts here ----------------------------------------------
		ip = pkt.get_header(IPv4)
		if ip is not None:
			dstaddr = ip.dst
			match = 0
			port = ''
			nexthop = ''
			for key in self.fwd_table:
				val = self.fwd_table[key]
				netaddr = IPv4Network(str(key) + "/" + str(val[0]))
				if dstaddr in netaddr:
					if netaddr.prefixlen > match:
						match = netaddr.prefixlen
						port = val[2]
						nexthop = val[1]

			# Once we know the nexthop, I do one crucial thing here
			# if next hop is one of the IPs on the router interfaces, dst in same subnet as router interface
			# change next hop to the dst which we already have
			myIPs = [intf.ipaddr for intf in self.interfaces]
			if IPv4Address(nexthop) in myIPs:
				nexthop = str(ip.dst)
			# print("nexthop is : ", nexthop)

			# --------------------------------------Item 4 starts here ------------------------------------------
			if dstaddr in [intf.ipaddr for intf in
						   self.interfaces]:  # The destination is one of the interfaces of the router.
				# For this router, handle ICMP echo requests in this case
				icmp = pkt.get_header(ICMP)
				if icmp is not None and icmp.icmptype == ICMPType.EchoRequest:

					icmp_reply = ICMP()
					icmp_reply.icmptype = ICMPType.EchoReply
					icmp_reply.icmpdata.sequence = icmp.icmpdata.sequence
					#	icmp_reply.sequence \
					#seq	= icmp.icmpdata.sequence
					log_debug("the icmp is {}".format(str(icmp)))
					icmp_reply.icmpdata.identifier = icmp.icmpdata.identifier
					icmp_reply.icmpdata.data = icmp.icmpdata.data

					ip_reply = IPv4()
					ip_reply.protocol = IPProtocol.ICMP
					ip_reply.src = dstaddr
					ip_reply.dst = ip.src
					ip_reply.ttl = 30  # Find standard and change ttl to that

					reply_pkt = ip_reply + icmp_reply
					self.router_forward(dev,reply_pkt)
				else:	#An incoming packet is destined to an IP addresses assigned to one of the router's interfaces, but the packet is not an ICMP echo request
					# --------------------------------------Item 5 Part 4 starts here ----------------------------------
					if (ip.ttl == 0):
						log_debug("An incoming packet is destined to an IP addresses assigned to one of the router's interfaces, but the packet is not an ICMP echo request.Sending a ICMP port unreachable error message.")
						icmp_reply = ICMP()
						icmp_reply.icmptype = ICMPType.DestinationUnreachable
						icmp_reply.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable
						icmp_reply.icmpdata.data = pkt.to_bytes()[:28]
						icmp_reply.icmpdata.origdgramlen = len(pkt)  # This should be optional probably

						ip_reply = IPv4()
						ip_reply.protocol = IPProtocol.ICMP
						ip_reply.src = dev.ipaddr
						ip_reply.dst = ip.src
						ip_reply.ttl = 30  # Find standard and change ttl to that

						reply_pkt = ip_reply + icmp_reply
						self.router_forward(dev, reply_pkt)
					# --------------------------------------Item 5 Part 4 ends here ----------------------------------
			# --------------------------------------Item 4 ends here -------------------------------------------
			# --------------------------------------Item 5 Part 1 starts here ----------------------------------
			elif port == '':
				log_debug("No match found. Sending a destination network unreachable error ICMP reply.")
				icmp_reply = ICMP()
				icmp_reply.icmptype = ICMPType.DestinationUnreachable
				icmp_reply.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable
				icmp_reply.icmpdata.data = pkt.to_bytes()[:28]
				icmp_reply.icmpdata.origdgramlen = len(pkt)	#This should be optional probably

				ip_reply = IPv4()
				ip_reply.protocol = IPProtocol.ICMP
				ip_reply.src = dev.ipaddr
				ip_reply.dst = ip.src
				ip_reply.ttl = 30  # Find standard and change ttl to that

				reply_pkt = ip_reply + icmp_reply
				self.router_forward(dev, reply_pkt)
			# --------------------------------------Item 5 Part 1 ends here -----------------------------------
			elif IPv4Address(nexthop) in [intf.ipaddr for intf in self.interfaces]:
				log_debug("Packet meant for the router. Do nothing.")
			else:
				ip.ttl -= 1

				# --------------------------------------Item 5 Part 2 starts here ----------------------------------
				if(ip.ttl == 0):
					log_debug("TTL = 0.Sending a ICMP time exceeded error message.")
					icmp_reply = ICMP()
					icmp_reply.icmptype = ICMPType.TimeExceeded
					icmp_reply.icmpcode = ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired
					icmp_reply.icmpdata.data = pkt.to_bytes()[:28]
					icmp_reply.icmpdata.origdgramlen = len(pkt)  # This should be optional probably

					ip_reply = IPv4()
					ip_reply.protocol = IPProtocol.ICMP
					ip_reply.src = dev.ipaddr
					ip_reply.dst = ip.src
					ip_reply.ttl = 30  # Find standard and change ttl to that

					reply_pkt = ip_reply + icmp_reply
					self.router_forward(dev, reply_pkt)
				# --------------------------------------Item 5 Part 2 ends here ----------------------------------_

				all_ports = [intf.name for intf in self.interfaces]
				port_index = all_ports.index(port)

				if IPv4Address(nexthop) not in self.ip_mac_dict:  # check if nexthop IP not in ARP cache
					if nexthop not in self.buffer:  # check if there are no packets for dst IP address
						# Construct an ARP packet to find the mac address of next hop
						ether = Ethernet()
						srchwaddr = self.interfaces[port_index].ethaddr
						ether.src = srchwaddr
						ether.dst = 'ff:ff:ff:ff:ff:ff'
						ether.ethertype = EtherType.ARP
						arp = Arp()
						arp.operation = ArpOperation.Request
						arp.senderhwaddr = self.interfaces[port_index].ethaddr
						arp.targethwaddr = 'ff:ff:ff:ff:ff:ff'
						arp.senderprotoaddr = self.interfaces[port_index].ipaddr
						arp.targetprotoaddr = nexthop
						arppacket = ether + arp

						# Create entry for nexthop IP & buffer the packet
						self.buffer[nexthop] = []
						self.buffer[nexthop].append(pkt)
						self.buffer_info[nexthop] = [port, time.time() * 1000, arppacket, 1, ip.src, dev]
						# Send an ARP request
						self.net.send_packet(port, arppacket)
					else:  # no need to send ARP request, store the packet in the buffer
						self.buffer[nexthop].append(pkt)

				else:  # nexthop IP lookup in the ARP cache
					eth_index = pkt.get_header_index(Ethernet)
					ether = pkt.get_header(Ethernet)
					del pkt[eth_index]
					# modify MAC headers,src : MAC address of router interface, dst : MAC address of next hop
					ether.dst = self.ip_mac_dict[IPv4Address(nexthop)]
					names = [intf.name for intf in self.interfaces]
					port_index = names.index(port)
					ether.src = self.interfaces[port_index].ethaddr
					pkt.insert_header(eth_index, ether)

					self.net.send_packet(port, pkt)
				# -------------------------------------Item 2 ends here ----------------------------

	def router_main(self):    
		while True:
			gotpkt = True
			#------------------------------ this portion is related to Item 3-----------------------------
			#update ARP cache periodically
			for key in self.buffer_info:
				if time.time()*1000 - self.buffer_info[key][1] >= 1000:
					if self.buffer_info[key][3] > 5:	#Send ICMP error message if ARP request is not satisfied even after 5 retransmissions
						# --------------------------------------Item 5 Part 3 starts here ----------------------------------
						if (ip.ttl == 0):
							log_debug("5 retransmissions of ARP query over.Sending a ICMP host unreachable error message.")
							icmp_reply = ICMP()
							icmp_reply.icmptype = ICMPType.DestinationUnreachable
							icmp_reply.icmpcode = ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable
							icmp_reply.icmpdata.data = pkt.to_bytes()[:28]
							icmp_reply.icmpdata.origdgramlen = len(pkt)  # This should be optional probably

							ip_reply = IPv4()
							ip_reply.protocol = IPProtocol.ICMP
							ip_reply.src = self.buffer_info[key][5].ipaddr
							ip_reply.dst = self.buffer_info[key][4]
							ip_reply.ttl = 30  # Find standard and change ttl to that

							reply_pkt = ip_reply + icmp_reply
							self.router_forward(self.buffer_info[key][5], reply_pkt)
						# --------------------------------------Item 5 Part 3 ends here ----------------------------------_
						del self.buffer[key]
						del self.buffer_info[key]
					else:
						#update count and time, send new ARP request
						self.buffer_info[key][3] += 1
						self.buffer_info[key][1] = time.time()*1000
						self.net.send_packet(self.buffer_info[key][0], self.buffer_info[key][2])
			#------------------------------------------------------------------------------------------------
				
			try:
				dev,pkt = self.net.recv_packet(timeout=1.0)
				self.router_forward(dev,pkt)

				
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break

			if gotpkt:
				log_debug("Got a packet: {}".format(str(pkt)))



def switchy_main(net):
	r = Router(net)
	r.router_main()
	net.shutdown()
