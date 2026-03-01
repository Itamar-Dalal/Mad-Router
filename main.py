from scapy.all import *

IFACE_1 = "enp0s8"
SUBNET_1 = "192.168.1"

IFACE_2 = "enp0s9"
SUBNET_2 = "192.168.2"


def main():
    while True:
        sniff(iface=IFACE_1, prn=lambda pkt: sendp(pkt, IFACE_2), filter=f"ip dst {SUBNET_2}", count=1)
        sniff(iface=IFACE_2, prn=lambda pkt: sendp(pkt, IFACE_1), filter=f"ip dst {SUBNET_1}", count=1)


if __name__ == "__main__":
    main()
