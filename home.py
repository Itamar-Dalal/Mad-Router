from scapy.all import *

IFACE = r"\Device\NPF_{BBFAF8BF-8879-4C10-83D4-705B892AA256}"
ENP0S8_MAC = "08:00:27:61:cb:8f"
ENP0S9_IP = "192.168.2.1"


def main():
    pkt = Ether(dst=ENP0S8_MAC)/IP(dst=ENP0S9_IP)/ICMP()
    pkt.show()
    sendp(pkt, iface=IFACE)


if __name__ == "__main__":
    main()
