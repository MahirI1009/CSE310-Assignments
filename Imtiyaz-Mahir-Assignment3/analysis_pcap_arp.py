import dpkt
import sys

def arp_analysis(file):
    pcap = dpkt.pcap.Reader(open(file, 'rb'))   #open file and create Reader 

    packets = []    #list for the request and reply packets

    is_req = False  #boolean to check if the request packet has been received 
    for ts, buf in pcap:

        if buf[12:14].hex() != '0806': 
            continue    #skip non arp packets

        type = buf[20:22].hex() #opcode

        if len(packets) == 0:
            #if the packet list is empty and the opcode is 1 then the packet is a request
            #if is_req is false then that means a request hasn't been added to the list
            if type == '0001' and is_req == False:  
                packets.append(buf) #append packet
                is_req = True       #set is_req to true, so in the next iteration it's known
        else:
            #if opcode is 2 then its a reply, if is_req is true then a request has already been added to packet list
            if type == '0002' and is_req == True:
                packets.append(buf)
                break   #exit loop after this, as the request and response has been added to the packet list

    for packet in packets:
        type = packet[20:22].hex()
        if type == '0001':
            print("ARP Request")
        else:
            print("\nARP Response")
        #output 
        print('Hardware Type: {}'.format(packet[14:16].hex()))
        print('Protocol Type: {}'.format(packet[16:18].hex()))
        print('Hardware Size: {}'.format(packet[18:19].hex()))
        print('Protocol Size: {}'.format(packet[19:20].hex()))
        print('Opcode: {}'.format(packet[20:22].hex()))
        print('Sender MAC Address: {}:{}:{}:{}:{}:{}'.format(packet[22:23].hex(), packet[23:24].hex(), packet[24:25].hex(), packet[25:26].hex(), packet[26:27].hex(), packet[27:28].hex()))
        print('Sender IP Address: {}:{}:{}:{}'.format(int(packet[28:29].hex(), 16), int(packet[29:30].hex(), 16), int(packet[30:31].hex(), 16), int(packet[31:32].hex(), 16)))
        print('Target MAC Address: {}:{}:{}:{}:{}:{}'.format(packet[32:33].hex(), packet[33:34].hex(), packet[34:35].hex(), packet[35:36].hex(), packet[36:37].hex(), packet[37:38].hex()))
        print('Target IP Address: {}:{}:{}:{}'.format(int(packet[38:39].hex(), 16), int(packet[39:40].hex(), 16), int(packet[40:41].hex(), 16), int(packet[41:42].hex(), 16)))

if __name__ == '__main__':
    arp_analysis(sys.argv[1])