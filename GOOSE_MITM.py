from scapy.all import *
import sys
import os
import time

##########################################| DISCLAIMER AND USER INPUT |########################################

try:
    print "\n"
    print "      ================================================================"
    print "      |                      |   Disclaimer:   |                     |"
    print "      ================================================================"
    print "      |           G  O  O   S   E   -  A  T  T  A  C  K  E  R        |"
    print "      |++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++|"
    print "      |                                                              |"
    print "      |   This work is based on other available frameworks (scapy)   |"
    print "      | Neither author, nor the university should be held liable for |"
    print "      |  unintended use of this program, IEC61850 and all the codes  |"
    print "      |              belong to its respective owners                 |"
    print "      |                                                              |"
    print "      ================================================================  "
    print "                       ||                        ||                "
    print "               ============================================"
    print "               ==|                                      |=="
    print "               ==|            SAGUN GHIMIRE             |=="
    print "            
    print "               ==|                                      |=="
    print "               ============================================ \n \n"
    interface = raw_input("Enter interface name Used : ")
    publisherIP = raw_input("Enter GOOSE Publisher IP : ")
    gatewayIP = raw_input("Enter gateway/VLAN IP : ")
except KeyboardInterrupt:
    print "\n !!! Process Interrupted by users"
    sys.exit(1)

##########################################| CHECK IF HOST IS ALIVE   |########################################


##########################################| ALL THE FUNCTIONS GOES HERE   |########################################

def fetch_mac_addr():
    layers = []
    counter = 0
    while True:
        layer = pkt.getlayer(counter)
        if (layer != None):
            print layer.name
            layers.append(layer.name)
        else:
            break
        counter += 1

    print "Layers are:\t\t", layers
##########################################| INPUT FOR ATTACK OPTION |########################################


while True:
    attack_choice = raw_input("\n[0] GOOSE FLOODING \n[1] GOOSE REPLAY  \n[2] MASQUERADE AS SUBSCRIBER \n[3] FRAME INJECTION \n[4] RETURN BACK TO MAIN MENU \n[5] EXIT THE GOOSE ATTACKER \n\nPLEASE SELECT YOUR ATTACK OPTION: ")
    if attack_choice == "0":
        print ("GOOSE FLOODING")
        print fetch_mac_addr()
        break
    if attack_choice == "1":
        print ("GOOSE REPLAY")
        break
    elif attack_choice == "2":
        print ("MasQ")
        break
    elif attack_choice == "3":
        print ("Frame Inject")
        break
    elif attack_choice == "4":
        # Clear screen based on windows or Linux
        _ = os.system('cls' if os.name == 'nt' else 'clear')
        # restart the program / comment the line on windows in case of any error
        os.execl(sys.executable, sys.executable, *sys.argv)
        break
    elif attack_choice == "5":
        sys.exit(1)
    print ("\nERROR: INVALID SELECTION TRY AGAIN ")
        # return back to attack_choice

##########################################| REPLAY ATTACK |########################################

