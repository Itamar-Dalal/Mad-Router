from scapy.all import *

IFACE = "Ethernet 5"
SUBNET = "192.168.1"


def main():
    pkt = IP(dst="192.168.2.2")
    pkt.show()
    sendp(pkt, iface=IFACE, count=1)


if __name__ == "__main__":
    main()
