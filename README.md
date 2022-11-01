# Networking_Programming_Assignment_2
## Before Running ##
Be sure to install ```dpkt``` ```socket``` and ```datetime```

## How to Run Code ##
```python3 analysis_pcap_tcp.py```

## Output from ```assignment2.pcap``` ##
```==========( 43498 , 130.245.145.12 , 80 , 128.208.2.198 )==========
10096912 bytes sent over 2.010401 seconds
Throughput: 5.022337e+06 Bps (4.017870e+07 bps)
        Transaction 1
                raw SEQ: 705669103
                raw ACK: 1921750144
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 24
        Transaction 2
                raw SEQ: 705669127
                raw ACK: 1921750144
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 1448
RTT: 0.072774 seconds
cwnd: [9, 19, 33]
Triple Dup ACKs: 2
Retransmissions due to timeout: 2

==========( 43500 , 130.245.145.12 , 80 , 128.208.2.198 )==========
10228680 bytes sent over 8.32037 seconds
Throughput: 1.229354e+06 Bps (9.834832e+06 bps)
        Transaction 1
                raw SEQ: 3636173852
                raw ACK: 2335809728
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 24
        Transaction 2
                raw SEQ: 3636173876
                raw ACK: 2335809728
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 1448
RTT: 0.073102 seconds
cwnd: [9, 31, 43]
Triple Dup ACKs: 4
Retransmissions due to timeout: 91

==========( 43502 , 130.245.145.12 , 80 , 128.208.2.198 )==========
1048600 bytes sent over 0.740275 seconds
Throughput: 1.416501e+06 Bps (1.133200e+07 bps)
        Transaction 1
                raw SEQ: 2558634630
                raw ACK: 3429921723
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 24
        Transaction 2
                raw SEQ: 2558634654
                raw ACK: 3429921723
                Recieve Window Size: 3
                Recieve Window Size (scaled): 49152
                len: 1448
RTT: 0.072921 seconds
cwnd: [9, 21, 33]
Triple Dup ACKs: 0
Retransmissions due to timeout: 1
Part B (1) comments:
The congestion window size grows as the flows move on pretty linearly this is
because the congestion control starts growing the size exponentially until it
hits a packet loss at which point it becomes linear growth.```
