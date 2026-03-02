from scapy.all import *


IFACE = r"\Device\NPF_{DE1ED8B8-2D79-41EB-BF7C-9AA7872C13FD}"
ENP0S9_MAC = "08:00:27:54:8c:74"


def main():
    pkt = Ether(dst=ENP0S9_MAC) / IP(dst="192.168.1.1") / UDP(dport=12345)
    pkt.show()
    sendp(pkt, iface=IFACE)
    sniff(iface=IFACE)


if __name__ == "__main__":
    main()
