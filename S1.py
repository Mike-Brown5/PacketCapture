import logging, subprocess, sys, os
from datetime import datetime
try:
    from scapy.all import *
except ImportError:
    print("scapy is not installed.... ")
    sys.exit()
try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    
    print("*******************************************")
    print("| You have to run this application as root |")
    print("*******************************************")
    
    interface = input("\nEnter the network interface that you want to sniff packets from: ")

    dirL = os.walk('/sys/class/net').__next__()[1]
    subprocess.call(["ifconfig", interface, "promisc"])
    if interface in dirL:
        print(f"\n{interface} was succesfully set to promisc mode")

    else:
        print(f"*\nThere is no {interface} interface installed\nClosing....")
        sys.exit()

    try:
        packets = input("\nEnter the number of packets to sniff (0 = infinit): ")
        if int(packets) !=0:
            print(f"\nCapturing {packets} packets")
        elif int(packets) == 0:
            print("\nThe program will keep capturing packets until the end of the timeout.\n")
    except:
        print("\nInvalid input\nClosing..")
        sys.exit()
    try:
        timeO = input("\nEnter the number of seconds you want to keep the capture running: ")

        if int(timeO) != 0:
            print(f"\nThe capture will Run for {timeO} seconds. ")
    except:
        print("\nInvalid input\nClosing..")
        sys.exit()
        
    pSniff = input(f"\n*Enter the protocol you want to capture (tcp | arp | icmp | bootp | 0=all): ")

    if(pSniff=="arp") or (pSniff=="bootp") or (pSniff=="icmp") or (pSniff=="tcp"):
        print(f"\n*The sniffer will only sniff {pSniff.upper()} packets")

    elif pSniff == "0":
        print("\n*Program Will capture all protocols")

    fileN = input("\nGive a name to the log file: ")
    sniffLog = open(fileN,"a")


    def packetLog(packet):
        now = datetime.now()

        if pSniff == "0":
            print("Date: "+ str(now)+" Protocols: All"+" SRC-MAC: "+ packet[0].src +" DST-MAC: "+ packet[0].dst, file = sniffLog)
        elif (pSniff=="arp") or (pSniff=="bootp"): 
            print("Date: "+ str(now)+ " Protocols: "+ pSniff.upper()+" SRCMAC: "+packet[0].src + " DSTMAC: "+ packet[0].dst  , file=sniffLog)
        elif (pSniff=="icmp") or (pSniff=="tcp"):
            print("Date: "+ str(now)+ " Protocols: "+ pSniff.upper()+" SRCMAC: "+packet[0].src + " DSTMAC: "+ packet[0].dst + " SRC-IP: "+ packet[0][1].src + " DST-IP: "+packet[0][1].dst , file=sniffLog)

    print("\n*Capturing....")

    if pSniff == "0":
        sniff(iface = interface , count=int(packets), timeout = int(timeO) ,prn=packetLog)

    elif (pSniff=="arp") or (pSniff=="bootp") or (pSniff=="icmp") or (pSniff=="tcp"):
        sniff(iface = interface , filter=pSniff ,count=int(packets), timeout = int(timeO),prn=packetLog)

    else:
        print("\n*Unkown protocol\nClosing program....\n")
        sys.exit()

    print(f"\n*All the logs stored in the {fileN} file.\n")
except KeyboardInterrupt:
    print("\nClosing...")
    sys.exit()
sniffLog.close()