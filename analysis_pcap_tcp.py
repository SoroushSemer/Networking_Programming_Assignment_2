from ipaddress import ip_address
import dpkt
import socket
import numpy as np


WINDOW_SIZE_SCALING_FACTOR = 16384

f = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)

def get_ip_str(ip):
    return socket.inet_ntop(socket.AF_INET, ip)


sender = {"ip":"130.245.145.12", "start_counts":0}
reciever ={ "ip":"128.208.2.198", "start_counts":0}




class TCP_Flow:
    def print_flow(self):
        
        print('==========(',self.src_port,',',self.src_ip, ',',self.dest_port,',',self.dest_ip,')==========')
        print(self.sent, "bytes sent")
        if(self.is_open):
            print("Flow never closed")
        seq_adjust = self.messages[0][2] 
        ack_adjust = self.messages[1][3] 
        
        # print("\t----First Two Tranactions----")
        start= 2
        if(self.messages[2][4] == 0):
            start = 3
        # print(self.messages[2])
        transact = 1
        for x in range(start, len(self.messages)):
           
            if(transact > 2):
                break
            if(self.messages[x][0]==1):
                for i in self.messages[x+1:]:
                    if(i[0]==2 and self.messages[x][3] == i[2]):
                        if(transact == 1):
                            start = self.messages[x][6]
                            end = self.messages[-2][6]
                            time = (end - start) / 1000
                            throughput = (self.sent / time) 
                            print("Throughput:", throughput, "Bps")
                        print( "\tTransaction", transact)
                        print("\t\traw SEQ:", self.messages[x][2])
                        print("\t\traw ACK:", self.messages[x][3])
                        print("\t\tRecieve Window Size:", self.messages[x][5] * WINDOW_SIZE_SCALING_FACTOR)
                        print("\t\tlen:", self.messages[x][4])
                        transact+=1
                        break
            
            
                
        
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
    
tcp_flows = []
# flags = []
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
            flow.sent += ip.len - 60
            if(flow.one_left):
                flow.is_open = False
                flow.one_left = False
            if(tcp.flags == 17):
                flow.one_left = True
                print("hit fin")
        

    # break

print(sender["ip"], sender["start_counts"])
print(reciever["ip"], reciever["start_counts"])
for i in tcp_flows:
    i.print_flow()

# print(set(flags))
# for i in src_ips:
#     if(i == sender["ip"]):
#         sender["count"]+=1
#     if(i==reciever["ip"]):
#         reciever["count"]+=1

