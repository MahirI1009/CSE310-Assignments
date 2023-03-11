import dpkt
import sys
import socket

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)
    
def s_or_r(flow, ip):
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    tcp = ip.data
    if sender == inet_to_str(ip.src) and receiver == inet_to_str(ip.dst):
        if flow[1] == tcp.sport and flow[3] == tcp.dport:
            return 's'
    elif sender == inet_to_str(ip.dst) and receiver == inet_to_str(ip.src):
        if flow[1] == tcp.dport and flow[3] == tcp.sport:
            return 'r'
    else:
        return 'n'

def parse(pcapfile):
    file = open(pcapfile, 'rb')
    pcap = dpkt.pcap.Reader(file)
    sender = '130.245.145.12'
    receiver = '128.208.2.198'
    TCPFlows = {}
    handshake = []                                                      #three way handshake tracker
    throughputs = {}                                       
    bytes = {}                                                          #flow -> bytes
    starts = {}                                                         #flow -> start time ts
    ends = {}                                                           #flow -> end time ts
    rtt = 0                                                             
    cwnds = {}                                                          #flow -> cwnd size
    window = 0                                                          #cwnd size
    startrtt = 0                                                        #cwnd start time
    cwndpackets = 0                                                     #cwnd total packets
    acks = {}                                                           #acknowledgements list used for dupes
    packs = {}                                                          #seq num -> ts
    first = 0                                                           #first packet ts
    retrans = {}
    timeouts = {}
    tdacks = {}

    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)                               #unpack ethernet frame

        if not isinstance(eth.data, dpkt.ip.IP):
            continue                                                    #skip this iteration if no IP packet 

        ip = eth.data                                                   #unpack data in ethernet frame, (IP packet)

        if ip.p != dpkt.ip.IP_PROTO_TCP:                                #skip this iteration if not a TCP protocol
            continue

        tcp = ip.data
        srcIP = inet_to_str(ip.src)
        srcprt = tcp.sport
        destIP = inet_to_str(ip.dst)
        destprt = tcp.dport
        if not srcIP == receiver:
            packet = (srcIP, srcprt, destIP, destprt)                   #create flow tuple
        else:
            packet = (destIP, destprt, srcIP, srcprt)                   #create reverse flow tuple
        ptype = s_or_r(packet, ip)
        
        #----------------create dict mapping packets to (srcIP, srcprt, destIP, destprt) keys---------------#
        if packet in TCPFlows:
            TCPFlows[packet].append(ip)                                 #if flow is a dupe, map to existing flow

            if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                rtt = ts - startrtt                                     #calculate rtt as SYN/ACK ts - SYN ts
                window = rtt + ts                                       #congestion window size
                handshake.append(True)                                  #SYN/ACK
                continue

            if tcp.flags & dpkt.tcp.TH_ACK and len(handshake) == 2:      
                handshake.append(True)                                  #three way handshake done
                #first = ts                                             #timestamp of first packet sent
                continue

            #-----------------------------congestion window calculation---------------------------------------#
            
            if len(cwnds[packet]) < 3:                                  
                if ts <= window:
                    cwndpackets += 1                                    #update cwnd size
                else:
                    cwnds[packet].append(cwndpackets)                   #append total cwnd packets
                    window = rtt + ts                                   #update window
                    cwndpackets = 1

            #-----------------------------retransmission calculation------------------------------------------#
            if ptype == 'r':                                            #keep track of acks         
                acks[packet].append(tcp.ack)                            
                while len(acks[packet]) > 3:
                    acks[packet] = acks[packet][1:]                     #keep acks to 3
                
            if ptype == 's':
                if first == 0:
                    first = ts                                          #ts of first packet sent

                if not tcp.seq in packs.keys(): 
                    packs[tcp.seq] = ts                                 #map all ts and map to seq
                else:                                                   #if in keys then likely retransmit
                    if ts != first:                                     #key in packs, but ts != start time
                        retrans[packet] += 1                            #retransmit                       
                    if (ts - packs[tcp.seq]) >= (rtt * 2):
                        timeouts[packet] += 1                           #2 rtts since packet sent, timeout
                    if len(acks[packet]) == 3:                          #check if triple dupe ack
                        if acks[packet][0] == acks[packet][1] and acks[packet][0] == acks[packet][2]:
                            tdacks[packet] += 1
                
            #--------------------------------------calculate throughput--------------------------------------------#    
                if not packet in bytes:
                    bytes[packet] = len(tcp)                            #if flow not in dict, add flow with length
                    starts[packet] = ts                                 #start time
                elif tcp.flags & dpkt.tcp.TH_FIN:
                    elapsed = ends[packet] - starts[packet]
                    throughput = bytes[packet] / elapsed                #calculate throughput
                    throughputs[packet] = throughput                    #put flow and throughput in dict
                else:                                                       
                    bytes[packet] += len(tcp)                           #if flow in dict, add length 
                    ends[packet] = ts                                   #append to list of timestamps       
                
            #-------------------------------------------------------------------------------------------------#

        else:
            TCPFlows[packet] = [ip]                                     #else create new flow key
            handshake.append(True)                                      #SYN
            startrtt = ts                                               #ts at start of flow (SYN)
            cwnds[packet] = []                                          #new flow with cwnd packet list
            acks[packet] = []                                           #new flow, new trip dup acks to track
            retrans[packet] = 0
            timeouts[packet] = 0
            tdacks[packet] = 0      
    #end of for
        
    #iterate through associated packet lists of each key (tcpflow), get 2 transactions and throughput
    transactions = {}
    for tcpflow, packetList in TCPFlows.items():                        #iterate through flows
        sr = ([], [])
        handshake = []
        for packet in packetList:                                       #iterating through packet list
            ptype = s_or_r(tcpflow, packet)
            if packet == 'n':
                continue
            tcp = packet.data
            if len(sr[0]) == 2 and len(sr[1]) == 2:                    #if 2 transactions, go to next flow
                transactions[tcpflow] = sr
                break
            #---------------------------------three way handshake---------------------------------#
            elif tcp.flags & dpkt.tcp.TH_SYN:      
                handshake.append(True)
                continue                                                #skip SYN packet, conn est
            elif tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:      
                handshake.append(True)
                continue                                                #skip SYN/ACK
            elif tcp.flags & dpkt.tcp.TH_ACK and len(handshake) == 2:      
                handshake.append(True)
                continue                                                #three way handshake done
            #-------------------------------------------------------------------------------------#
            elif ptype == 's' and len(tcp.data) != 0:                   #if sender
                if len(sr[0]) == 0:                                     #if transaction 1
                    sr[0].append(tcp)                                   
                elif len(sr[1]) == 0:                                   #if transaction 2
                    sr[1].append(tcp)
            elif ptype == 'r':                                          #if receiver
                if len(sr[0]) == 1:                                     #if transaction 1
                    if tcp.ack > sr[0][0].seq:                      
                        sr[0].append(tcp)                               
                elif len(sr[1]) == 1:                                   #if transaction 2
                    if tcp.ack > sr[1][0].seq:
                        sr[1].append(tcp)

    #print output
    i = 0
    print("Number of TCP Flows: " + str(len(TCPFlows)))
    for k in TCPFlows.keys():
        i += 1
        print("TCP Flow " + str(i))
        print("src IP: " + str(k[0]) + "\tsrc port: " + str(k[1]) + "\tdest IP: " + str(k[2]) + "\tdest port: " + str(k[3]))
        sr = transactions.get(k)
        s = sr[0][0]
        r = sr[0][1]
        print("Transaction 1")
        print("\tSender -> Receiver \t Sequence #: " + str(s.seq) + "\t Acknowledgement #: " + str(s.ack) + "\t Receive Win Size: " + str(s.win))  
        print("\tReceiver -> Sender \t Sequence #: " + str(r.seq) + "\t Acknowledgement #: " + str(r.ack) + "\t Receive Win Size: " + str(r.win)) 
        s = sr[1][0]
        r = sr[1][1]
        print("Transaction 2")
        print("\tSender -> Receiver \t Sequence #: " + str(s.seq) + "\t Acknowledgement #: " + str(s.ack) + "\t Receive Win Size: " + str(s.win))  
        print("\tReceiver -> Sender \t Sequence #: " + str(r.seq) + "\t Acknowledgement #: " + str(r.ack) + "\t Receive Win Size: " + str(r.win)) 
        print("Throughput: " + "{:.2f}".format(throughputs[k]) + " bytes/s")
        print("Congestion Window Sizes: " + str(cwnds[k]))
        print("Total Retransmissions: " + str(retrans[k]))
        print("\tTotal retransmissions due to triple duplicate acks: " + str(tdacks[k]))
        print("\tTotal retransmissions due to timeouts: " + str(timeouts[k]))
        print("\tTotal retransmissions due to other reasons: " + str(retrans[k] - timeouts[k] - tdacks[k]))
        print("")

    file.close
    
def main():
    file = sys.argv[1]
    parse(file)

if __name__ == "__main__":
    main()