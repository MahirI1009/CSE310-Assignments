- High Level Summary of the Code and how the answers were estimated:

My code is mostly built on dictionaries. I first created a tuple of the src ip, src port, dest ip and dest port. I used this tuple as the key in virtually all my several dictionaries. My main dictionary is TCPFlows which maps each flow to all of its associated packets, a flow is represented by the tuple I mentioned earlier. 

Part A:

I use a for loop to go through every packet, I check create the tuple of the src ip, src port, dest ip and dest port, then I check if it's in the TCP flows dictionary. If it isn't then I add it as a new key and I map it to the current packet (in a list of packets). Otherwise I append it to the list of packets for the existing key. 

I use a separate for loop to get the first two transmissions. I create a tuple, where the first element is an array of 2 items: the sender and the receiver. In my for loop, I go through every flow, and in every flow I go through every packet. I skip the 3 way handshake and then I check if the first sender tuple is empty, if it is then I add it. Then I check if the first receiver is empty, if it is I add the receiver if the receiver's ack is larger than the sender's seq #. I repeat this process for the second sender and receiver. 

I can simply use the .win field from the library to get the Receive Window Size.

I calculate the throughput by adding the size of all the sender packets in a flow, and I calculate the time it took to send all the packets in a flow. Then I divide the total size by the total time.

Part B:

To calculate the first 3 congestion window sizes, I first estimated the RTT as the time between sending SYN and receiving the SYN/ACK. Then starting from the first packet after the three way handshake, I counted the number of packets sent 1 RTT after the first packet sent for the first congestion window, then the number of packets 1 RTT after the last packet in the previous RTT for the second congestion window, and then repeat that process one last time for the third congestion window. The congestion window sizes likely grew due to better bandwidth and shorter RTT times during the TCP flow.

To calculate the number of retransmissions, I had a dictionary mapping sequence numbers to timestamps. If a sequence number repeated but it didn't have the same time stamp as the first time it sent, then it was likely a retransmit. I then checked if the retransmit is due to a timeout, I did this by checking if more than 2 RTTs have passed since it was originally sent, if it did then it was due to a timeout. If it didnt, then I had a list of 3 acks that I was constantly updating with the last 3 acks received, I check if all 3 acks are the same, if they are then I count it as a timeout for a triple duplicate ack. 

- How to run the code:
In order to run the code you need a valid pcap file otherwise the program will crash and you will need to rerun it.

To run it, first you must have python and dpkt installed. To install dpkt, in your terminal do `pip install dpkt`. Then in your terminal navigate to the directory that contains the program, and then run in the terminal using this command: `python analysis_pcap_tcp.py <filename.pcap>`.

For example: `python analysis_pcap_tcp.py assignment2.pcap`

Example of my output using the assignment2.pcap file:

$ python analysis_pcap_tcp.py assignment2.pcap
Number of TCP Flows: 3
TCP Flow 1
src IP: 130.245.145.12  src port: 43498 dest IP: 128.208.2.198  dest port: 80
Transaction 1
        Sender -> Receiver       Sequence #: 705669103   Acknowledgement #: 1921750144   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 1921750144  Acknowledgement #: 705669127    Receive Win Size: 3
Transaction 2
        Sender -> Receiver       Sequence #: 705669127   Acknowledgement #: 1921750144   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 1921750144  Acknowledgement #: 705670575    Receive Win Size: 3
Throughput: 5551805.84 bytes/s
Congestion Window Sizes: [25, 57, 92]
Total Retransmissions: 4
        Total retransmissions due to triple duplicate acks: 2
        Total retransmissions due to timeouts: 1
        Total retransmissions due to other reasons: 1

TCP Flow 2
src IP: 130.245.145.12  src port: 43500 dest IP: 128.208.2.198  dest port: 80
Transaction 1
        Sender -> Receiver       Sequence #: 3636173852  Acknowledgement #: 2335809728   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 2335809728  Acknowledgement #: 3636173876   Receive Win Size: 3
Transaction 2
        Sender -> Receiver       Sequence #: 3636173876  Acknowledgement #: 2335809728   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 2335809728  Acknowledgement #: 3636175324   Receive Win Size: 3
Throughput: 1279144.24 bytes/s
Congestion Window Sizes: [65, 97, 140]
Total Retransmissions: 95
        Total retransmissions due to triple duplicate acks: 4
        Total retransmissions due to timeouts: 90
        Total retransmissions due to other reasons: 1

TCP Flow 3
src IP: 130.245.145.12  src port: 43502 dest IP: 128.208.2.198  dest port: 80
Transaction 1
        Sender -> Receiver       Sequence #: 2558634630  Acknowledgement #: 3429921723   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 3429921723  Acknowledgement #: 2558634654   Receive Win Size: 3
Transaction 2
        Sender -> Receiver       Sequence #: 2558634654  Acknowledgement #: 3429921723   Receive Win Size: 3
        Receiver -> Sender       Sequence #: 3429921723  Acknowledgement #: 2558636102   Receive Win Size: 3
Throughput: 1830487.97 bytes/s
Congestion Window Sizes: [30, 55, 60]
Total Retransmissions: 1
        Total retransmissions due to triple duplicate acks: 0
        Total retransmissions due to timeouts: 0
        Total retransmissions due to other reasons: 1
