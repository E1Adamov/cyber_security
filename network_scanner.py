import scapy.all as scapy
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP / IP range')
    options_ = parser.parse_args()
    return options_


# get MAC address from devices via ARP protocol
def scan(ip):
    # # simple method that replaces all of the below code
    # scapy.arping(ip)

    arp_request = scapy.ARP(pdst=ip)

    # # list all fields of scapy.ARP()
    # scapy.ls(scapy.ARP())

    # print(arp_request.summary())

    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    # combine two packets together using '/'
    arp_request_broadcast = broadcast/arp_request

    # # show the contents of the packet
    # arp_request_broadcast.show()

    # 'send and receive' packet with custom 'Ether' part ('ff:ff:ff:ff:ff:ff')
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)
    # print(answered_list.summary())

    return [{'ip': answer[1].psrc, 'mac': answer[1].hwsrc} for answer in answered_list]


def print_network(ntwrk):
    print('IP\t\tMAC Address\n-------------------------------')
    for device in ntwrk:
        print('{}\t{}'.format(device['ip'], device['mac']))


options = get_arguments()
devices = scan(options.target)
print_network(devices)

# ##### USE IN TERMINAL #####
# python3 network_scanner.py -t 10.0.2.1/24
