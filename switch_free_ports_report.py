#!/usr/bin/env python
# (c) 2019, Chris Perkins
# Checks a Cisco switch for interfaces that are currently not connected & reports relevant
# information, optionally output to CSV

# v1.4 - disabled fast_cli due to issues, fixed edge case for empty show output
# v1.3 - enabled fast_cli & use show interface for full description
# v1.2 - code tidying
# v1.1 - fixed switch uptime output to CSV
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

if __name__ == "__main__":
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
        # Grab show version & extract uptime
        cli_output = device.send_command("show version")
        switch_uptime = re.search(r"uptime is \d+.+\n", cli_output)
        if switch_uptime:
            switch_uptime = switch_uptime.group(0)
            switch_uptime = switch_uptime.strip('\n')
            switch_uptime = switch_uptime.replace(',', '')
        else:
            switch_uptime = "uptime is unknown"
        # Grab interface status
        cli_output = device.send_command("show interface status | include notconnect|xcvrAbsen")
        if cli_output == None or len(cli_output) == 0:
            print(f"{target_switch} has no interfaces not connected.")
            sys.exit(0)
        cli_output = cli_output.split("\n")
        interface_list = []
        # Iterate through interfaces to grab last input time
        for cli_line in cli_output:
            cli_items = cli_line.split()
            # Skip empty result lines
            if not cli_items:
                continue
            cli_output2 = device.send_command(f"show interface {cli_items[0]}")
            last_input = re.search(r"Last input ([0-9:a-z]+), ", cli_output2)
            if last_input:
                last_input = last_input.group(1)
            else:
                last_input = "unknown"

            # Ignore port-channel interface
            if re.search(r"^Po\d+", cli_items[0]):
                continue

            # Handle interfaces with No XCVR, No Transceiver or No Connector
            if cli_items[-2] == "No" and (cli_items[-1] == "XCVR" or cli_items[-1] == "Transceiver"
                or cli_items[-1] == "Connector"):
                if (len(cli_items) == 6):
                    # Handle no description
                    interface_dict = {'interface': cli_items[0], 'description': '', 'VLAN': cli_items[-5],
                        'speed': cli_items[-3], 'duplex': cli_items[-4], 'type': "No Transceiver",
                        'last_input': last_input}
                    interface_list.append(interface_dict)
                else:
                    # Grab full description from show interface
                    cli_output3 = device.send_command(f"show interface {cli_items[0]}")
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    if int_description:
                        int_description = int_description.group(1).rstrip()
                    else:
                        int_description = ''
                    interface_dict = {'interface': cli_items[0], 'description': int_description,
                        'VLAN': cli_items[-5], 'speed': cli_items[-3], 'duplex': cli_items[-4],
                        'type': "No Transceiver", 'last_input': last_input}
                    interface_list.append(interface_dict)
            # Handle regular interfaces
            else:
                if (len(cli_items) == 6):
                    # Handle no description
                    interface_dict = {'interface': cli_items[0], 'description': '', 'VLAN': cli_items[-4],
                        'speed': cli_items[-2], 'duplex': cli_items[-3], 'type': cli_items[-1],
                        'last_input': last_input}
                    interface_list.append(interface_dict)
                else:
                    # Grab full description from show interface
                    cli_output3 = device.send_command(f"show interface {cli_items[0]}")
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    if int_description:
                        int_description = int_description.group(1).rstrip()
                    else:
                        int_description = ''
                    # Handle SFP with a space
                    if cli_items[-1] == "SFP":
                        interface_dict = {'interface': cli_items[0], 'description': int_description,
                            'VLAN': cli_items[-5], 'speed': cli_items[-3], 'duplex': cli_items[-4],
                            'type': cli_items[-2] + ' ' + cli_items[-1], 'last_input': last_input}
                    else:
                        interface_dict = {'interface': cli_items[0], 'description': int_description,
                            'VLAN': cli_items[-4], 'speed': cli_items[-2], 'duplex': cli_items[-3],
                            'type': cli_items[-1], 'last_input': last_input}
                    interface_list.append(interface_dict)

        # Output the results to CLI or CSV
        if len(sys.argv) == 2:
            # Output to CSV
            try:
                with open(sys.argv[1], 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    result_list = [["Switch Uptime", "Interface", "Description", "VLAN", "Speed", "Duplex",
                        "Type", "Last Input"]]
                    for interface in interface_list:
                        result_list.append([target_switch + ' ' + switch_uptime, interface['interface'],
                            interface['description'], interface['VLAN'], interface['speed'],
                            interface['duplex'], interface['type'], interface['last_input']])
                    writer.writerows(result_list)
            except OSError:
                print(f"Unable to write CSV file {sys.argv[1]}.")
                sys.exit(1)
        else:
            # Output to CLI
            print(f"{target_switch} {switch_uptime}\n\nUnused Interface List:")
            for interface in interface_list:
                print(f"Interface: {interface['interface']}, Description: {interface['description']}, VLAN:"
                    f" {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}"
                    f", Type: {interface['type']}, Last Input: {interface['last_input']}")

        # Done
        device.disconnect()
        sys.exit(0)