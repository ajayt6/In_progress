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


def addressTableAdd(addressTable,dev,src):
    currentTS = datetime.datetime.now().time()
    minTS = currentTS
    if len(addressTable) < 5:
        minTS = currentTS
        addressTable[src] = [dev,currentTS]
    else:
        delIndex = ''
        for key in addressTable:
            if addressTable[key][1] <= minTS:
                minTS = addressTable[key][1]
                delIndex = key

        addressTable.pop(delIndex)
        addressTable[src] = [dev, currentTS]


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
        srcMac = packet[0].src

        if srcMac in addressTable:
            if addressTable[srcMac][0] != dev:
                addressTable[srcMac][0] = dev
        else:
            addressTableAdd(addressTable, dev, srcMac)

        if dstMac in mymacs:
            log_debug ("Packet intended for me")
        else:
            if (dstMac not in addressTable) or (dstMac == "FF:FF:FF:FF:FF:FF"):

                # Then flood it to all connected devices (interfaces)
                for intf in my_interfaces:
                    if dev != intf.name:
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)


            else:
                log_debug("sending to specific device")
                addressTable[dstMac][1] = datetime.datetime.now().time()
                net.send_packet(addressTable[dstMac][0], packet)

    net.shutdown()