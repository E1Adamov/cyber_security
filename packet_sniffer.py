import scapy.all as scapy
from scapy_http import http


# prn = function to be called every time a packet is received
# filter= 'udp', 'arp', 'tcp', 'port 21'(ftp) - bpf syntax: http://biot.com/capstats/bpf.html *optional
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        # use scapy.<layer_name> for different layers
        if packet.haslayer(scapy.Raw):

            # packet[<layer_name>].<field_name>
            print(packet[scapy.Raw].load)


# use 'wlan0' for real LAN
sniff('eth0')
