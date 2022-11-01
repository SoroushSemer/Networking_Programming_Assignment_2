from ipaddress import ip_address
import dpkt
import socket
# import numpy as np
import datetime


WINDOW_SIZE_SCALING_FACTOR = 16384
MSS = 1460

f = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)

def get_ip_str(ip):
    return socket.inet_ntop(socket.AF_INET, ip)


sender = {"ip":"130.245.145.12", "start_counts":0}
reciever ={ "ip":"128.208.2.198", "start_counts":0}




class TCP_Flow:
    def print_flow(self):
        
        

        print('\n==========(',self.src_port,',',self.src_ip, ',',self.dest_port,',',self.dest_ip,')==========')
        if(self.is_open):
            print("Flow never closed")
        self.start = datetime.datetime.utcfromtimestamp(self.messages[0][6])
        end = datetime.datetime.utcfromtimestamp(self.messages[-1][6])
        time = (end - self.start).total_seconds()
        # print(time)
        print(self.sent, "bytes sent over", time, "seconds")
        # time = 2
        throughput = (self.sent / time) 
        print("Throughput: {:e} Bps ({:e} bps)".format(throughput, throughput*8))
        

        # print("\t----First Two Tranactions----")
        start= 2
        if(self.messages[2][4] == 0):
            start = 3
        # print(self.messages[2])
        transact = 1
        timeouts = 0

        ooo = 0
        # out_of_order = 0
        for x in range(start, len(self.messages)):
           
            # if(transact > 2):
            #     break
            if(self.messages[x][0]==1):
                max_seq = 0
                for i in self.messages[x+1:]:
                    if(i[0] == 1):
                        max_seq = max(max_seq, i[2])
                    if(i[0]==2 and self.messages[x][3] == i[2]):
                        # if(transact == 1):
                        #     start = self.messages[x][6]
                        #     end = self.messages[-2][6]
                        #     time = (end - start) / 1000
                        #     throughput = (self.sent / time) 
                        #     print("Throughput: {:e} Bps".format(throughput))
                        start = datetime.datetime.utcfromtimestamp(self.messages[x][6])
                        end = datetime.datetime.utcfromtimestamp(i[6])
                        if(transact == 1):
                            self.start = start
                            self.rtt = (end - start).total_seconds()
                            self.actual_rtt = self.rtt
                        #  
                        else:
                            self.actual_rtt = -1*(1-0.125)*self.actual_rtt + 0.125*((end - start).total_seconds())
                        if((end - start).total_seconds() > self.rtt):
                            timeouts+=1
                        if(self.messages[self.messages.index(i)+1][2] == i[3] and self.messages[self.messages.index(i)+1][2] > max_seq):
                            ooo+=1
                        if(transact <3):
                            print( "\tTransaction", transact)
                            print("\t\traw SEQ:", self.messages[x][2])
                            print("\t\traw ACK:", self.messages[x][3])
                            print("\t\tRecieve Window Size:", self.messages[x][5])
                            print("\t\tRecieve Window Size (scaled):", self.messages[x][5] * WINDOW_SIZE_SCALING_FACTOR)
                            print("\t\tlen:", self.messages[x][4])
                        

                        transact+=1
                        break
            
        print("RTT:",self.rtt, "seconds")
        RTT_packet_counts =[0,0,0]
        current_RTT = 0
        current_max = self.start + (datetime.timedelta(seconds = self.rtt))
        current_min = self.start
        for packet in self.messages:
            if(datetime.datetime.utcfromtimestamp(packet[6]) <= current_max ):
                if(datetime.datetime.utcfromtimestamp(packet[6]) > current_min and packet[0] == 1):
                    RTT_packet_counts[current_RTT] += 1
            else:
                current_RTT += 1
                current_min = current_max
                current_max += datetime.timedelta(seconds = self.rtt)
                if(current_RTT > 2):
                    break
        print("cwnd:", RTT_packet_counts)
        
        triple_dup_acks = 0
        out_of_order = 0
        acks = 0 
        current_ack = 0
        # for i in set(self.acks):
        for i in range(len(self.messages)):
           if(self.messages[i][0]==2):
                if(self.messages[i][3]==current_ack):
                    acks+=1
                else:
                    acks = 0
                    current_ack = self.messages[i][3]
           elif(self.messages[i][2]==current_ack and acks >= 2 ):
                triple_dup_acks+=1
                # print(current_ack)

        # for i in range(len(self.messages)-2):
        #     if(self.messages[i][0] == 2 and self.messages[i+1][0] == 1 and self.messages[i][3] == self.messages[i+1][2]  and self.messages[i+1][2]+self.messages[i+1][4] != self.messages[i+2][2]):
        #             out_of_order+=1
        for i in range(len(self.seqs)-1):
            if(self.seqs[i] > self.seqs[i+1] ):
                out_of_order+=1
        #     if()
        retransmissions = 0
        for i in set(self.seqs):
            
            if(self.seqs.count(i) >= 2):
                retransmissions += self.seqs.count(i)-1
        retransmissions -= triple_dup_acks 

            # if(self.messages[i][0]== 2 and self.messages[i+1][0]== 2 and self.messages[i+2][0]== 2 and self.messages[i+3][0]==1):
            #     if(self.messages[i][3] == self.messages[i+1][3] and self.messages[i][3] == self.messages[i+2][3] and self.messages[i][3] == self.messages[i+3][2]):
            #         triple_dup_acks+=1
            #         print(self.messages[i][3])
        print("Triple Dup ACKs:", triple_dup_acks)
        # print("Timeouts:", timeouts)
        print("Retransmissions due to timeout:", retransmissions)

        # print("\t\t\tACK: ", self.messages[2])
        
        
    def check_same_flow(self, port1, ip1, port2, ip2):
        if(self.is_open):
            if(self.src_port==port1 and self.src_ip == ip1 and self.dest_port == port2 and self.dest_ip==ip2):
                return 1
            if(self.src_port==port2 and self.src_ip == ip2 and self.dest_port == port1 and self.dest_ip==ip1):
                return 2
        return 0

    def add_msg(self,message):
        # rel_seq = 0
        # rel_ack = 1
        # if(len(self.messages)!=0):
        #     rel_seq = self.messages[-1][-2] + self.messages[-1][4]
        #     rel_ack = self.messages[-1][-1]
        # if(message[0]==2):
        #     rel_ack = 
        # message.append(rel_seq, rel_ack)
        self.messages.append(message)
    def __init__(self, src_port, src_ip, dest_port, dest_ip):
        self.src_port = src_port
        self.src_ip = src_ip
        self.dest_port = dest_port
        self.dest_ip = dest_ip
        self.messages = []
        self.is_open = True #flow is still open
        self.one_left = False
        self.sent = 0
        self.cwnd = MSS
        self.rtt = 0
        self.start = 0
        self.acks = []
        self.seqs = []
        self.actual_rtt = 0
    
tcp_flows = []
# flags = []
last_eth=  0
for ts, buf in pcap:
    # print (ts, len(buf))
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    # ip.pprint()
    tcp = ip.data
    # print()
    src_ip = get_ip_str(ip.src)
    dest_ip =get_ip_str(ip.dst)
    # flags.append(tcp.flags)
    if(tcp.flags == 2):
        if(src_ip==sender["ip"]):
            sender["start_counts"]+=1
        elif(src_ip==reciever["ip"]):
            reciever["start_counts"]+=1
        tcp_flows.append(TCP_Flow(tcp.sport, src_ip, tcp.dport, dest_ip))
        # print(tcp.flags)
    for flow in tcp_flows:
        check_same_flow = flow.check_same_flow(tcp.sport, src_ip, tcp.dport, dest_ip)
        if(check_same_flow!=0):
            flow.add_msg((check_same_flow,hex(tcp.flags),  tcp.seq, tcp.ack, ip.len-52, tcp.win, ts))
            # if(len(flow.messages)== 1):
            #     for i in dpkt.tcp.parse_opts(buf):
            #        i[1].pprint()

            if(check_same_flow == 1):
                flow.sent += len(tcp.data)
                flow.seqs.append(tcp.seq)
            if(check_same_flow == 2):
                flow.acks.append(tcp.ack)
            if(flow.one_left):
                flow.is_open = False
                flow.one_left = False
            if(tcp.flags == 17):
                flow.one_left = True
                # print("hit fin")
    last_eth = eth
# print(str(datetime.datetime.utcfromtimestamp(last_ts)))     
# last_eth.pprint()
    # break
0.12
# print(sender["ip"], sender["start_counts"])
# print(reciever["ip"], reciever["start_counts"])
for i in tcp_flows:
    i.print_flow()
# print(set(flags))
# for i in src_ips:
#     if(i == sender["ip"]):
#         sender["count"]+=1
#     if(i==reciever["ip"]):
#         reciever["count"]+=1


