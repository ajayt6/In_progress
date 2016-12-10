#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import time
import sys

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    blaster_param_file = open("blaster_params.txt")
    params = blaster_param_file.readlines()[0].strip('\n').split(' ')
    blaster_param_file.close()
    # -b <blaster_IP> -n <num>
    blaster_IP = params[1]
    num = params[3]

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
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            #Extract sequence number
            ether_header_recv = pkt.get_header_index(Ethernet)
            del pkt[ether_header_recv]
            ip_header_recv = pkt.get_header_index(IPv4)
            del pkt[ip_header_recv]
            udp_header_recv = pkt.get_header_index(UDP)
            del pkt[udp_header_recv]

            seq_num_bytes = pkt.to_bytes()[:4]
            ack_payload = pkt.to_bytes()[6:]

            #Take care of padding if required
            if sys.getsizeof(ack_payload) < 8:
                pad_length = 8 - sys.getsizeof(ack_payload)
                padding = bytearray(pad_length)
                ack_payload.append(padding)

            #Create an ACK packet and send
            ack_pkt = Ethernet() + IPv4() + UDP()
            ack_pkt[1].protocol = IPProtocol.UDP
            ack_pkt[1].srcip = '10.0.0.14'
            ack_pkt[1].dstip = blaster_IP
            ack_pkt[2].srcport = 6666
            ack_pkt[2].dstport = 9999
            ack_pkt = ack_pkt + RawPacketContents(seq_num_bytes) + ack_payload

            net.send_packet("blastee-eth0", ack_pkt)


    net.shutdown()
