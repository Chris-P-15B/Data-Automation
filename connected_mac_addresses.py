#!/usr/bin/env python
# (c) 2019, Chris Perkins
# Licence: BSD 3-Clause

# Reports connected interface status & MAC address table for a Cisco switch, optionally output to CSV

# v1.2 - disabled fast_cli due to issues, fixed edge case for empty show output
# v1.1 - enabled fast_cli & use show interface for full description
# v1.0 - initial release

# To Do:
# Poll device via SNMP to determine device type & which code path to take to query interfaces
# SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
# Web frontend

import sys, re, csv
from getpass import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler

def main():
    target_switch = input("Target switch: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    try:
        device = ConnectHandler(device_type="cisco_ios", host=target_switch, username=target_username,
            password=target_password)
    except NetMikoAuthenticationException:
        print(f"Failed to execute CLI on {target_switch} due to incorrect credentials.")
        sys.exit(1)
    except (NetMikoTimeoutException, SSHException):
        print(f"Failed to execute CLI on {target_switch} due to timeout or SSH not enabled.")
        sys.exit(1)
    else:
        # Grab interface status
        cli_output = device.send_command("show interface status | include connected")
        if cli_output == None or len(cli_output) == 0:
            print(f"{target_switch} has no connected interfaces.")
            sys.exit(0)
        cli_output = cli_output.split("\n")
        interface_list = []
        # Iterate through interfaces to grab MAC addresses
        for cli_line in cli_output:
            cli_items = cli_line.split()
            # Skip empty result lines
            if not cli_items:
                continue
            cli_output2 = device.send_command(f"show mac address-table interface {cli_items[0]}")
            cli_output2 = cli_output2.split("\n")
            mac_addresses = []
            for mac_line in cli_output2:
                mac_address = re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", mac_line)
                if mac_address:
                    mac_address = mac_address.group(1)
                    # Exclude broadcast MAC
                    if mac_address != "ffff.ffff.ffff":
                        mac_addresses.append(mac_address)
            if len(mac_addresses) < 1:
                mac_addresses = ""

            # Handle port-channel interfaces
            if re.search(r"^Po\d+", cli_items[0]):
                if (len(cli_items) == 5):
                    # Handle no description
                    interface_dict = {"interface": cli_items[0], "description": "", "VLAN": cli_items[-3],
                        "speed": cli_items[-1], "duplex": cli_items[-2], "type": "", "macs": mac_addresses}
                    interface_list.append(interface_dict)
                else:
                    # Grab full description from show interface
                    cli_output3 = device.send_command(f"show interface {cli_items[0]}")
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    int_description = int_description.group(1).rstrip() if int_description else ""
                    interface_dict = {"interface": cli_items[0], "description": int_description,
                        "VLAN": cli_items[-3], "speed": cli_items[-1], "duplex": cli_items[-2],
                        "type": "", "macs": mac_addresses}
                    interface_list.append(interface_dict)
            # Handle interfaces with No XCVR, No Transceiver or No Connector
            elif (cli_items[-2] == "No" and (cli_items[-1] == "XCVR" or cli_items[-1] == "Transceiver"
                or cli_items[-1] == "Connector")):
                if (len(cli_items) == 6):
                    # Handle no description
                    interface_dict = {"interface": cli_items[0], "description": "", "VLAN": cli_items[-5],
                        "speed": cli_items[-3], "duplex": cli_items[-4], "type": "No Transceiver",
                        "macs": mac_addresses}
                    interface_list.append(interface_dict)
                else:
                    # Grab full description from show interface
                    cli_output3 = device.send_command(f"show interface {cli_items[0]}")
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    int_description = int_description.group(1).rstrip() if int_description else ""
                    interface_dict = {"interface": cli_items[0], "description": int_description,
                        "VLAN": cli_items[-5], "speed": cli_items[-3], "duplex": cli_items[-4],
                        "type": "No Transceiver", "macs": mac_addresses}
                    interface_list.append(interface_dict)
            # Handle regular interfaces
            else:
                if (len(cli_items) == 6):
                    # Handle no description
                    interface_dict = {"interface": cli_items[0], "description": "", "VLAN": cli_items[-4],
                        "speed": cli_items[-2], "duplex": cli_items[-3], "type": cli_items[-1],
                        "macs": mac_addresses}
                    interface_list.append(interface_dict)
                else:
                    # Grab full description from show interface
                    cli_output3 = device.send_command(f"show interface {cli_items[0]}")
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    int_description = int_description.group(1).rstrip() if int_description else ""
                    # Handle SFP with a space
                    if cli_items[-1] == "SFP":
                        interface_dict = {"interface": cli_items[0], "description": int_description,
                            "VLAN": cli_items[-5], "speed": cli_items[-3], "duplex": cli_items[-4],
                            "type": cli_items[-2] + " " + cli_items[-1], "macs": mac_addresses}
                    else:
                        interface_dict = {"interface": cli_items[0], "description": int_description,
                            "VLAN": cli_items[-4], "speed": cli_items[-2], "duplex": cli_items[-3],
                            "type": cli_items[-1], "macs": mac_addresses}
                    interface_list.append(interface_dict)

        # Output the results to CLI or CSV
        if len(sys.argv) == 2:
            # Output to CSV
            try:
                with open(sys.argv[1], "w", newline="") as csv_file:
                    writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
                    result_list = [["Interface", "Description", "VLAN", "Speed", "Duplex", "Type",
                        "MAC Addresses"]]
                    for interface in interface_list:
                        result_list.append([interface["interface"], interface["description"],
                            interface["VLAN"], interface["speed"], interface["duplex"], interface["type"],
                            ",".join(interface["macs"])])
                    writer.writerows(result_list)
            except OSError:
                print(f"Unable to write CSV file {sys.argv[1]}.")
                sys.exit(1)
        else:
            # Output to CLI
            print(f"{target_switch} Interface & MAC Address List:")
            for interface in interface_list:
                print(f"Interface: {interface['interface']}, Description: {interface['description']}, "
                    f"VLAN: {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}, "
                    f"Type: {interface['type']}, MAC Addresses: {', '.join(interface['macs'])}")

        # Done
        device.disconnect()
        sys.exit(0)

if __name__ == "__main__":
    main()