Dastagiri 9075665092
Ajay_Joseph_Thomas 9075720087

The blaster keeps an internal dictionary 'SW_dict' (key being #seq, value is 1 if packet is ACKed else 0) to keep track of status of packets sent. Additionally, it also maintains a buffer dictionary 'buffer_dict' (key again begin #seq, value being the packet sent). This is to avoid packet construction at the time of retransmission. Each time an ACK is received, the value for the seq# is updated to 1 in SW_dict and additionally the entry corresponding to seq# is deleted from buffer_dict. Thus, at any given point of time, buffer_dict only contains entries for packets that have not been ACKed. On coarse timeout, packets corresponding to all present entries in buffer_dict are retransmitted.

