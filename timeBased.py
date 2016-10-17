#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
import datetime


def addressTableAdd(addressTable,dstMac,src):
    currentTS = datetime.datetime.now()
    if len(addressTable) > 0:
        for key in addressTable:
            if addressTable[key][1].second - currentTS.second  > 10:
                addressTable.popitem(key)
    addressTable[dstMac] = [src,datetime.datetime.now()]

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    addressTable = {}
    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        dstMac = packet[0].dst
        if dstMac in mymacs:
            log_debug ("Packet intended for me")
        else:
            if dstMac in addressTable:
                log_debug("sending to specific device")
                net.send_packet(addressTable[dstMac],packet)
            else:
                #Add that entry to the AddressTable
                addressTableAdd(addressTable,dstMac,packet[0].src)	#This is a naive implementation where address table will grow infinitely if source devices are introduced infinitely
                #Then flood it to all connected devices (interfaces)
                for intf in my_interfaces:
                            if dev != intf.name:
                                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                                    net.send_packet(intf.name, packet)
    net.shutdown()