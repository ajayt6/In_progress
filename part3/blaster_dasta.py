#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time
import struct

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    
    f = open("blaster_params.txt")
    params = f.readlines()[0].strip('\n').split(' ')
    f.close()
    #-b <blastee_IP> -n <num> -l <length> -w <sender_window> -t <timeout> -r <recv_timeout> 
    blastee_IP = params[1]
    num = int(params[3])
    payload_len = int(params[5])
    sw = int(params[7])
    to = float(params[9])
    recv_to = float(params[11]) # assume recv_to < to

    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            dev,pkt = net.recv_packet(timeout=recv_to/1000)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            print("ACK received from blastee via middlebox", str(pkt))
        else:
            log_debug("Didn't receive anything")

            '''
            Creating the headers for the packet
            '''
            pkt = Ethernet() + IPv4() + UDP()
            pkt[0].src = '10:00:00:00:00:01'
            pkt[0].dst = '40:00:00:00:00:01'
            pkt[0].ethertype = EtherType.IPv4
            pkt[1].srcip = '192.168.100.1'
            pkt[1].dstip = blastee_IP
            pkt[1].protocol = IPProtocol.UDP
            pkt[2].srcport = 1111
            pkt[2].dstport = 2222
            
            seq_bytes = struct.pack('>I', 0)
            len_bytes = struct.pack('>H', payload_len)
            payload_bytes = bytes(payload_len)

            pkt = pkt +  pkt.add_header(seq_bytes) + pkt.add_header(len_bytes) #+pkt.add_payload(payload_bytes)
            print("Packet sent to blastee via middlebox......")
            net.send_packet('blaster-eth0', pkt)
            '''
            Do other things here and send packet
            '''

    net.shutdown()
