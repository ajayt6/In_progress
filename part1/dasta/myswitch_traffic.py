#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

'''
For the traffic volume based mechanism, each entry in the forwarding table is a list of [ MAC address, port, traffic_volume ]
The traffic volume is incremented every time destination MAC address = MAC address of the entry
'''

def switchy_main(net):
	my_interfaces = net.interfaces() 
	fwd_table = []
	mymacs = [intf.ethaddr for intf in my_interfaces]

	
	while True:
		try:
			dev,packet = net.recv_packet()
			
			fwd_table_macs = [item[0] for item in fwd_table]
			#if forwarding table contains entry for src address			
			if packet[0].src in fwd_table_macs:
				i = fwd_table_macs.index(packet[0].src)
				if dev == fwd_table[i][1]:
					pass
				else:
					fwd_table[i][1] = dev

			else:
				#if forwarding table is full (i.e. sized 5), remove the entry with the least traffic volume and append the new entry
				if (len(fwd_table) == 5):
					traffic_volumes = [item[2] for item in fwd_table]
					i = traffic_volumes.index(min(traffic_volumes))
					fwd_table = fwd_table[0:i] + fwd_table[i+1 : 5] + [[packet[0].src, dev, 0]]
				else :
					fwd_table.append([packet[0].src, dev, 0])
		except NoPackets:
			continue
		except Shutdown:
			return

		log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
		
		fwd_table_macs = [item[0] for item in fwd_table]
		#If destination address is one of the addresses on the switch
		if packet[0].dst in mymacs:
			log_debug ("Packet intended for me")

		#If forwarding table contains the destination address
		elif packet[0].dst in fwd_table_macs:
			#update the traffic volume
			i = fwd_table_macs.index(packet[0].dst)
			fwd_table[i][2] += 1

			net.send_packet(fwd_table[i][1], packet)
			
		elif packet[0].dst not in fwd_table_macs or packet[0].dst == "ff:ff:ff:ff:ff:ff":
			for intf in my_interfaces:
				if dev != intf.name:
					log_debug ("Flooding packet {} to {}".format(packet, intf.name))
					net.send_packet(intf.name, packet)
	net.shutdown()
