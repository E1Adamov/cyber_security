import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--interface', dest='interface', help='Interface to change its MAC address')
    parser.add_option('-m', '--mac', dest='new_mac', help='New MAC address')
    values_, _ = parser.parse_args()
    if not values.interface:
        parser.error('[-] You need to enter a valid interface. Use --help for more info.')
    if not values.new_mac:
        parser.error('[-] You need to enter a valid MAC address. Use --help for more info.')
    return values_


def change_mac_address(interface, mac):
    print('[+] Changing MAC address for {} to {}'.format(interface, mac))
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['ifconfig', interface, 'hw', 'ether' + mac])
    subprocess.call(['ifconfig', interface, 'up'])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface])
    current_mac = re.search(r"((\w\w:){5}\w\w)", ifconfig_result)
    if current_mac:
        return current_mac.group(0)
    else:
        print("[-] Can't read the current MAC address")


values = get_arguments()

old_mac = get_current_mac(values.interface)
print('[+] The current MAC address is', old_mac)

change_mac_address(values.interface, values.new_mac)

new_mac = get_current_mac(values.interface)
assert values.new_mac == new_mac, '[-] Failed to change MAC from {} to {}'.format(new_mac, values.new_mac)
print('[+] Success. The new MAC address is', new_mac)
