#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
from random import randint
import random
import time

def switchy_main(net):

    my_intf = net.interfaces()
    my_names = [intf.name for intf in my_intf]
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    mac_IP = [['10:00:00:00:00:01', '192.168.100.1'],['20:00:00:00:00:01', '192.168.200.1']]
    

    f = open('middlebox_params.txt', 'r')
    val = f.readlines()[0].strip('\n').split(' ')[1]
    f.close()
    d_rate = float(val)

    #total_sent = 0
    while True:

        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            print("packet received from blaster : ", str(pkt))

            if (random.random() > d_rate):
                ether_index = pkt.get_header_index(Ethernet)
                ether = pkt.get_header(Ethernet)
                del pkt[ether_index]

                ether.src = mymacs[my_names.index('middlebox-eth1')]
                ether.dst = mac_IP[1][0]
                pkt.insert_header(ether_index, ether)

                #total_sent = total_sent + 1
                #print("Sending packet and total sent is: " + str(total_sent))
                net.send_packet("middlebox-eth1", pkt)
            else:
                pass
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            print("ACK received from blastee : ", str(pkt))
            ether_index = pkt.get_header_index(Ethernet)
            ether = pkt.get_header(Ethernet)
            del pkt[ether_index]

            ether.src = mymacs[my_names.index('middlebox-eth0')]
            ether.dst = mac_IP[0][0]
            pkt.insert_header(ether_index, ether)
            
            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
