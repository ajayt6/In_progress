#!/usr/bin/env python3

import time
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

'''
For the timeout based mechanism, each entry in the forwarding table is a list of [ MAC address, port, timestamp ]
The timestamp is the Epoch time in milliseconds
'''

def switchy_main(net):
	my_interfaces = net.interfaces() 
	fwd_table = []
	mymacs = [intf.ethaddr for intf in my_interfaces]

	
	while True:
		try:
			dev,packet = net.recv_packet()
			#if fwd table contains entry for src address
			fwd_table_macs = [item[0] for item in fwd_table]
			
			if packet[0].src in fwd_table_macs:
				i = fwd_table_macs.index(packet[0].src)
				if dev == fwd_table[i][1]:
					fwd_table[i][2] = time.time()*1000
				else:
					fwd_table[i][1] = dev
					fwd_table[i][2] = time.time()*1000

			else:
				fwd_table.append([packet[0].src, dev, time.time()*1000])
		except NoPackets:
			continue
		except Shutdown:
			return
		log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))

		#Based on current time, delete entries where time elapsed is more than 10 seconds
		current_time = time.time()*1000
		fwd_table = [item for item in fwd_table if (current_time - item[2]) < 10000]
		
		fwd_table_macs = [item[0] for item in fwd_table]
		#If destination address is one of the addresses on the switch
		if packet[0].dst in mymacs:
			log_debug ("Packet intended for me")

		#If forwarding table contains the destination address
		elif packet[0].dst in fwd_table_macs:
			i = fwd_table_macs.index(packet[0].dst)
			net.send_packet(fwd_table[i][1], packet)
			
		elif packet[0].dst not in fwd_table_macs or packet[0].dst == "ff:ff:ff:ff:ff:ff":
			for intf in my_interfaces:
				if dev != intf.name:
					log_debug ("Flooding packet {} to {}".format(packet, intf.name))
					net.send_packet(intf.name, packet)
	net.shutdown()
