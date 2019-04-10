import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.Ip(packet.get_payload())
    sp = scapy.Ip
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()