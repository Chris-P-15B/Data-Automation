#!/usr/bin/env python
# v1.0 - written by Chris Perkins in 2019
# Returns list of interfaces on switches specified in JSON file that have learnt a given MAC address

# v1.0 – initial release

# To Do:
# SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
# ARP lookup for MAC address
# Web frontend

import sys, re, json
from threading import Thread
from getpass import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler

def validate_mac_address(mac_address):
    """Validate MAC address & return it in correct format"""
    mac_address = mac_address.lower()
    for digit in mac_address:
        if digit in ".:-":
            mac_address = mac_address.replace(digit, '')
    if len(mac_address) != 12:
        return None
    for digit in mac_address:
        if digit not in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']:
            return None
    mac_address = mac_address[0:4] + '.' + mac_address[4:8] + '.' + mac_address[8:12]
    return mac_address

def find_mac_address(target_switch, switch_type, mac_address, results_list):
    """Updates list of interfaces that have learnt the specified MAC address"""
    try:
        device = ConnectHandler(device_type=switch_type, host=target_switch, username=target_username, password=target_password)

        # IOS, IOS XE & NX-OS
        if switch_type.lower() == "cisco_ios" or switch_type.lower() == "cisco_xe" or switch_type.lower() == "cisco_nxos":
            # Grab MAC address table & extract information
            cli_output = device.send_command("show mac address-table | include " + mac_address)
            if cli_output == None or len(cli_output) == 0:
                device.disconnect()
                return
            cli_output = cli_output.split("\n")
            # Iterate through results
            for cli_line in cli_output:
                cli_items = cli_line.split()
                cli_output2 = device.send_command("show interface " + cli_items[-1])
                if re.search(r"Description: ", cli_output2):
                    int_description = re.search(r"Description: (.+)", cli_output2)
                    int_description = int_description.group(1).rstrip()
                else:
                    int_description = ""
                if switch_type.lower() == "cisco_nxos":
                    results_list.append([target_switch, cli_items[-1], int_description, cli_items[1]])
                else:
                    results_list.append([target_switch, cli_items[-1], int_description, cli_items[0]])
            device.disconnect()

        # JunOS
        elif switch_type.lower() == "juniper" or switch_type.lower() == "juniper_junos":
            # Switch MAC address format from aaaa.bbbb.cccc to aa:aa:bb:bb:cc:cc
            junos_mac_address = mac_address
            for digit in junos_mac_address:
                if digit in ".:-":
                    junos_mac_address = junos_mac_address.replace(digit, '')
            junos_mac_address = junos_mac_address[0:2] + ':' + junos_mac_address[2:4] + ':' + junos_mac_address[4:6] + ':' \
             + junos_mac_address[6:8] + ':' + junos_mac_address[8:10] + ':' + junos_mac_address[10:12]
            # Grab MAC address table & extract information
            cli_output = device.send_command("show ethernet-switching table brief | match " + junos_mac_address)
            if cli_output == None or len(cli_output) <= 1:
                device.disconnect()
                return
            cli_output = cli_output.split("\n")
            # Iterate through results
            for cli_line in cli_output:
                if cli_line == None or len(cli_line) <= 1:
                    continue
                cli_items = cli_line.split()
                if re.search(r"\w.+\.\d+", cli_items[-1]):
                    int_name = re.search(r"(\w.+)\.\d+", cli_items[-1])
                    int_name = int_name.group(1)
                    cli_output2 = device.send_command("show interfaces " + int_name)
                    if re.search(r"Description: ", cli_output2):
                        int_description = re.search(r"Description: (.+)", cli_output2)
                        int_description = int_description.group(1).rstrip()
                    else:
                        int_description = ""
                else:
                    continue
                results_list.append([target_switch, cli_items[-1], int_description, cli_items[0]])
            device.disconnect()
    except(NetMikoAuthenticationException):
        print("Failed to execute CLI on " + target_switch + " due to incorrect credentials.")
        return
    except (NetMikoTimeoutException, SSHException):
        print("Failed to execute CLI on " + target_switch + " due to timeout or SSH not enabled.")
        return
    except ValueError:
        print("Unsupported platform " + target_switch + ", " + switch_type)
        return

if __name__ == "__main__":
    # Parse command line parameters
    if len(sys.argv) != 3:
        print("Please specify JSON file of switches & MAC address as parameters.")
        sys.exit(1)
    mac_address = validate_mac_address(sys.argv[2])
    if mac_address is None:
        print("Invalid MAC address specified " + sys.argv[2])
        sys.exit(1)
    try:
        with open(sys.argv[1]) as f:
            switch_list = json.load(f)
            for switch in switch_list:
                try:
                    if not switch['hostname']:
                        print("Switch hostname missing in JSON file " + sys.argv[1])
                        sys.exit(1)
                    if not switch['platform']:
                        print("Switch type missing in JSON file " + sys.argv[1])
                        sys.exit(1)
                except KeyError:
                    print("Unable to parse JSON file " + sys.argv[1])
                    sys.exit(1)
    except FileNotFoundError:
        print("Unable to open JSON file " + sys.argv[1])
        sys.exit(1)
    except json.decoder.JSONDecodeError:
        print("Unable to parse JSON file " + sys.argv[1])
        sys.exit(1)

    target_username = input("Username: ")
    target_password = getpass("Password: ")

    # Start a thread to log into each switch & locate the MAC address
    result_list = [["Switch", "Interface", "Description", "VLAN"]]
    threads = []
    for switch in switch_list:
        worker = Thread(target=find_mac_address, args=(switch['hostname'], switch['platform'], mac_address, result_list))
        worker.start()
        threads.append(worker)
    for worker in threads:
        worker.join()
    print(result_list)
    sys.exit(0)