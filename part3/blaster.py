#!/usr/bin/env python3

#Let Blaster IP be 192.168.100.1
#Let Blastee IP be 192.168.200.1

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time
import struct
import sys
from threading import Timer

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    LHS = 1
    RHS = 1
    SW = None #Get this from params
    total_sent = 0
    total_sent_acked = 0
    total_time = 0
    num_reTX = 0
    num_coarseTO = 0
    throughput = 0
    goodput = 0

    blaster_param_file = open("blaster_params.txt")
    params = blaster_param_file.readlines()[0].strip('\n').split(' ')
    blaster_param_file.close()
    #-b <blastee_IP> -n <num> -l <length> -w <sender_window> -t <timeout> -r <recv_timeout>
    blastee_IP = params[1]
    num = int(params[3])
    length = int(params[5])
    sender_window = int(params[7])
    timeout = float(params[9])
    recv_timeout = float(params[11]) # assume recv_to < to

    SW = sender_window
    SW_dict = {}
    buffer_dict = {} #buffer to store the packets later for retransmission
    timer = time.time()*1000
    total_time = time.time()*1000
    while total_sent_acked < num:

        if time.time()*1000 - timer > timeout :
            num_coarseTO += 1
            for key in buffer_dict:
                print("Retransmit pkt with seq number "+ str(key) + " .....")
                throughput += length
                net.send_packet("blaster-eth0", buffer_dict[key])
                num_reTX += 1
            timer = time.time()*1000 # reset timer

        gotpkt = True
        try:
            dev,pkt = net.recv_packet(timeout=recv_timeout / 1000)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            #print("ACK received from blastee via middlebox", str(pkt))
            #Extract seq_num of ack packet
            # Extract sequence number
            ether_header_recv = pkt.get_header_index(Ethernet)
            del pkt[ether_header_recv]
            ip_header_recv = pkt.get_header_index(IPv4)
            del pkt[ip_header_recv]
            udp_header_recv = pkt.get_header_index(UDP)
            del pkt[udp_header_recv]

            seq_num_bytes = pkt.to_bytes()[:4]
            seq_num = int.from_bytes(seq_num_bytes,byteorder = 'big')

            print("ACK received from blastee via middlebox with seq num : ", str(seq_num))
            if seq_num in SW_dict and SW_dict[seq_num] == 0:
                total_sent_acked += 1
            if seq_num in SW_dict:
                #print("Going to set")
                SW_dict[seq_num] = 1
                if seq_num in buffer_dict:
                    del buffer_dict[seq_num]

            #Ensure condition 2
            while LHS in SW_dict and SW_dict[LHS] == 1:
                LHS += 1
                timer = time.time()*1000   #reset timer
            print("Packet status : " + str(SW_dict))

        elif not gotpkt and total_sent < num:  
            log_debug("Didn't receive anything")

            #Ensure condition 1
            if RHS - LHS + 1 <= SW :
                '''
                Creating the headers for the packet
                '''
                pkt = Ethernet() + IPv4() + UDP()
                pkt[0].src = '10:00:00:00:00:01'
                pkt[0].dst = '40:00:00:00:00:01'
                pkt[0].ethertype = EtherType.IPv4
                pkt[1].protocol = IPProtocol.UDP
                pkt[1].srcip = '192.168.100.1'
                pkt[1].dstip = blastee_IP
                pkt[2].srcport = 9999
                pkt[2].dstport = 6666


                #Take care of fixed length of 32 bits for seq_num and 16 bits for length -> This logic of ensuring the specific fixed length has to be ensured
                seq_num = RHS
                SW_dict[seq_num] = 0
                RHS += 1
                seq_num_bytes = struct.pack('>I', seq_num) #seq_num.to_bytes((seq_num.bit_length()+1) // 8 , 'big') or b'/0'
                payload_str = '''mininet is awesome and this poject as a whole is really informative.'''

                length_InBytes_payload_str = len(payload_str)
                if length < length_InBytes_payload_str:
                    payload_str = payload_str[:length]
                elif length > length_InBytes_payload_str:
                    payload_str = payload_str + "0" * (length - length_InBytes_payload_str)
                #print("payload string is :", payload_str, length, length_InBytes_payload_str)

                length_bytes = struct.pack('>H', length)	#length.to_bytes((length.bit_length()+1) // 8 , 'big') or b'/0'

                #Check and confirm if RawPacketContents takes care of big endianness
                pkt = pkt.add_header(seq_num_bytes)
                pkt = pkt.add_header(length_bytes)
                pkt = pkt + RawPacketContents(payload_str)
                buffer_dict[seq_num] = pkt
                print("Packet with seq no. " + str(seq_num) + " sent to blastee via middlebox......")

                throughput = throughput + length
                goodput += length

                net.send_packet("blaster-eth0", pkt)
                total_sent = total_sent + 1

    total_time = time.time()*1000 - total_time

    net.shutdown()

    if total_sent_acked == num:
        '''
        Total TX time (in seconds): Time between the first packet sent and last packet ACKd
        Number of reTX: Number of retransmitted packets, this doesn't include the first transmission of a packet. Also if the same packet is retransmitted more than once, all of them will count.
        Number of coarse TOs: Number of coarse timeouts
        Throughput (Bps): You will obtain this value by dividing the total # of sent bytes(from blaster to blastee) by total TX time. This will include all the retransmissions as well! When calculating the bytes, only consider the length of the variable length payload!
        Goodput (Bps): You will obtain this value by dividing the total # of sent bytes(from blaster to blastee) by total TX time. However, this will NOT include the bytes sent due to retransmissions! When calculating the bytes, only consider the length of the variable length payload!
        '''

        print("Total TX time (in seconds): " + str(total_time/1000))
        print("Number of reTX: " + str(num_reTX))
        print("Number of coarse TOs: " + str(num_coarseTO))
        print("Throughput (Bps): " + str(throughput*1000/total_time))
        print("Goodput (Bps): " + str(goodput*1000/total_time))
