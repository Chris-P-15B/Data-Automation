#!/usr/bin/env python
# (c) 2019 - 2020, Chris Perkins
# Licence: BSD 3-Clause

# Returns list of interfaces on switches specified in CSV file that have learnt a given MAC address

# v1.2 - added device auto-detection, added Arista support
# v1.1 - fixed edge case for empty show output
# v1.1 - code tidying
# v1.0 - initial release

# To Do:
# SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
# ARP lookup for MAC address
# Web frontend

import sys, re, csv
from pprint import pprint
from threading import Thread
from getpass import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler

def guess_device_type(remote_device):
    """Auto-detect device type"""
    try:
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
    except(NetMikoAuthenticationException):
        print(f"Failed to execute CLI on {remote_device['host']} due to incorrect credentials.")
        return None
    except (NetMikoTimeoutException, SSHException):
        print(f"Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled.")
        return None
    except ValueError:
        print(f"Unsupported platform {remote_device['host']}, {remote_device['device_type']}.")
        return None
    else:
        return best_match

def validate_mac_address(mac_address):
    """Validate MAC address & return it in correct format"""
    mac_address = mac_address.lower()
    for digit in mac_address:
        if digit in ".:-":
            mac_address = mac_address.replace(digit, "")
    if len(mac_address) != 12:
        return None
    for digit in mac_address:
        if digit not in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]:
            return None
    mac_address = mac_address[0:4] + "." + mac_address[4:8] + "." + mac_address[8:12]
    return mac_address

def find_mac_address(remote_device, mac_address, results_list):
    """Updates list of interfaces that have learnt the specified MAC address"""
    try:
        # Auto-detect device type & establish correct SSH connection
        best_match = guess_device_type(remote_device)
        if best_match is None:
            return
        else:
            remote_device["device_type"] = best_match
        device = ConnectHandler(**remote_device)
    except NetMikoAuthenticationException:
        print(f"Failed to execute CLI on {remote_device['host']} due to incorrect credentials.")
        return
    except (NetMikoTimeoutException, SSHException):
        print(f"Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled.")
        return
    except ValueError:
        print(f"Unsupported platform {remote_device['host']}, {remote_device['device_type']}.")
        return
    else:
        # IOS, IOS XE & NX-OS
        if best_match == "cisco_ios" or best_match == "cisco_xe" or best_match == "cisco_nxos":
            # Grab MAC address table & extract information
            cli_output = device.send_command(f"show mac address-table | include {mac_address}")
            if cli_output is None or len(cli_output) == 0:
                device.disconnect()
                return
            cli_output = cli_output.split("\n")
            # Iterate through results
            for cli_line in cli_output:
                cli_items = cli_line.split()
                # Skip empty result lines
                if not cli_items:
                    continue
                cli_output2 = device.send_command(f"show interface {cli_items[-1]}")
                int_description = re.search(r"Description: (.+)", cli_output2)
                int_description = int_description.group(1).rstrip() if int_description else ""
                if best_match == "cisco_nxos":
                    results_list.append([remote_device["host"], cli_items[-1], int_description, cli_items[1]])
                else:
                    results_list.append([remote_device["host"], cli_items[-1], int_description, cli_items[0]])
            device.disconnect()

        # JunOS
        elif best_match == "juniper" or best_match == "juniper_junos":
            # Switch MAC address format from aaaa.bbbb.cccc to aa:aa:bb:bb:cc:cc
            junos_mac_address = mac_address
            for digit in junos_mac_address:
                if digit in ".:-":
                    junos_mac_address = junos_mac_address.replace(digit, "")
            junos_mac_address = f"{junos_mac_address[0:2]}:{junos_mac_address[2:4]}:{junos_mac_address[4:6]}"\
                f":{junos_mac_address[6:8]}:{junos_mac_address[8:10]}:{junos_mac_address[10:12]}"
            # Grab MAC address table & extract information
            cli_output = device.send_command(f"show ethernet-switching table brief | match {junos_mac_address}")
            if cli_output is None or len(cli_output) <= 1:
                device.disconnect()
                return
            cli_output = cli_output.split("\n")
            # Iterate through results
            for cli_line in cli_output:
                # Skip empty result lines
                if cli_line is None or len(cli_line) <= 1:
                    continue
                cli_items = cli_line.split()
                if not cli_items:
                    continue
                int_name = re.search(r"(\w.+)\.\d+", cli_items[-1])
                if int_name:
                    int_name = int_name.group(1)
                    cli_output2 = device.send_command(f"show interfaces {int_name}")
                    int_description = re.search(r"Description: (.+)", cli_output2)
                    int_description = int_description.group(1).rstrip() if int_description else ""
                else:
                    continue
                results_list.append([remote_device["host"], cli_items[-1], int_description, cli_items[0]])
            device.disconnect()

        # Arista EOS
        elif best_match == "arista_eos":
            # Grab MAC address table & extract information
            cli_output = device.send_command(f"show mac address-table | include {mac_address}")
            if cli_output is None or len(cli_output) == 0:
                device.disconnect()
                return
            cli_output = cli_output.split("\n")
            # Iterate through results
            for cli_line in cli_output:
                cli_items = cli_line.split()
                # Skip empty result lines
                if not cli_items:
                    continue
                cli_output2 = device.send_command(f"show interfaces {cli_items[3]}")
                int_description = re.search(r"Description: (.+)", cli_output2)
                int_description = int_description.group(1).rstrip() if int_description else ""
                results_list.append([remote_device["host"], cli_items[3], int_description, cli_items[0]])
            device.disconnect()

        # Unsupported, disconnect
        else:
            device.disconnect()

def main():
    # Parse command line parameters
    if len(sys.argv) != 3:
        print("Please specify CSV file of switches & a MAC address as parameters.")
        sys.exit(1)
    mac_address = validate_mac_address(sys.argv[2])
    if mac_address is None:
        print(f"Invalid MAC address specified {sys.argv[2]}")
        sys.exit(1)

    # Pull inventory from CSV file
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    try:
        with open(sys.argv[1]) as f:
            reader = csv.reader(f)
            switch_list = [{"device_type": "autodetect", "host": row[0], "username": target_username, "password": target_password} for row in reader]
    except FileNotFoundError:
        print(f"Unable to open CSV file {sys.argv[1]}")
        sys.exit(1)

    # Start a thread to log into each switch & locate the MAC address
    result_list = [["Switch", "Interface", "Description", "VLAN"]]
    threads = []
    for switch in switch_list:
        worker = Thread(target=find_mac_address, args=(switch, mac_address, result_list))
        worker.start()
        threads.append(worker)
    for worker in threads:
        worker.join()

    pprint(result_list)
    sys.exit(0)

if __name__ == "__main__":
    main()