#!/usr/bin/env python3

"""
(c) 2019 - 2021, Chris Perkins
Licence: BSD 3-Clause

Reports connected interface status & MAC address table for a Cisco switch, optionally output to CSV

v1.3 - bug fixes & improvements to output parsing
v1.2 - disabled fast_cli due to issues, fixed edge case for empty show output
v1.1 - enabled fast_cli & use show interface for full description
v1.0 - initial release

To Do:
Use SSHDetect to determine device type & which code path to take to query interfaces
SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
Web frontend
"""

import sys, re, csv
from getpass import getpass
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler


def main():
    target_switch = input("Target switch: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    try:
        device = ConnectHandler(
            device_type="cisco_ios",
            host=target_switch,
            username=target_username,
            password=target_password,
        )
    except NetMikoAuthenticationException:
        print(f"Failed to execute CLI on {target_switch} due to incorrect credentials.")
        sys.exit(1)
    except (NetMikoTimeoutException, SSHException):
        print(
            f"Failed to execute CLI on {target_switch} due to timeout or SSH not enabled."
        )
        sys.exit(1)
    else:
        # Grab interface status
        cli_output = device.send_command("show interface status")
        cli_output = cli_output.split("\n")
        interface_list = []
        # Find offsets for column headings in the output
        for cli_line in cli_output:
            PORT_COLUMN = cli_line.find("Port")
            NAME_COLUMN = cli_line.find("Name")
            STATUS_COLUMN = cli_line.find("Status")
            VLAN_COLUMN = cli_line.find("Vlan")
            DUPLEX_COLUMN = cli_line.find("Duplex")
            SPEED_COLUMN = cli_line.find("Speed")
            TYPE_COLUMN = cli_line.find("Type")

            if (
                PORT_COLUMN
                == NAME_COLUMN
                == STATUS_COLUMN
                == VLAN_COLUMN
                == DUPLEX_COLUMN
                == SPEED_COLUMN
                == TYPE_COLUMN
                == -1
            ):
                continue
            else:
                break

        # Parse output & retrieve information for interfaces that are connected
        for cli_line in cli_output:
            try:
                interface_dict = {
                    "interface": cli_line[PORT_COLUMN:NAME_COLUMN].strip(),
                    "description": cli_line[NAME_COLUMN:STATUS_COLUMN].strip(),
                    "status": cli_line[STATUS_COLUMN:VLAN_COLUMN].strip(),
                    "VLAN": cli_line[VLAN_COLUMN:DUPLEX_COLUMN].strip(),
                    "duplex": cli_line[DUPLEX_COLUMN : SPEED_COLUMN - 1].strip(),
                    "speed": cli_line[SPEED_COLUMN - 1 : TYPE_COLUMN].strip(),
                    "type": cli_line[TYPE_COLUMN:].strip(),
                }
                # Filter for interfaces that are connected
                if interface_dict["status"] and interface_dict["status"] in "connected":
                    cli_output2 = device.send_command(
                        f"show mac address-table interface {interface_dict['interface']}"
                    )
                    cli_output2 = cli_output2.split("\n")
                    mac_addresses = []
                    for mac_line in cli_output2:
                        mac_address = re.search(
                            r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", mac_line
                        )
                        if mac_address:
                            mac_address = mac_address.group(1)
                            # Exclude broadcast MAC
                            if mac_address != "ffff.ffff.ffff":
                                mac_addresses.append(mac_address)
                    interface_dict["macs"] = mac_addresses
                    # Grab full description from show interface
                    cli_output3 = device.send_command(
                        f"show interface {interface_dict['interface']}"
                    )
                    int_description = re.search(r"Description: (.+)\n", cli_output3)
                    int_description = (
                        int_description.group(1).rstrip() if int_description else ""
                    )
                    interface_dict["description"] = int_description
                    del interface_dict["status"]
                    interface_list.append(interface_dict)
            except IndexError:
                continue

        # Output the results to CLI or CSV
        if len(sys.argv) == 2:
            # Output to CSV
            try:
                with open(sys.argv[1], "w", newline="") as csv_file:
                    writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
                    result_list = [
                        [
                            "Interface",
                            "Description",
                            "VLAN",
                            "Speed",
                            "Duplex",
                            "Type",
                            "MAC Addresses",
                        ]
                    ]
                    for interface in interface_list:
                        line = [
                            interface["interface"],
                            interface["description"],
                            interface["VLAN"],
                            interface["speed"],
                            interface["duplex"],
                            interface["type"],
                        ]
                        line.extend(interface["macs"])
                        result_list.append(line)
                    writer.writerows(result_list)
            except OSError:
                print(f"Unable to write CSV file {sys.argv[1]}.")
                sys.exit(1)
        else:
            # Output to CLI
            print(f"{target_switch} Interface & MAC Address List:")
            for interface in interface_list:
                print(
                    f"Interface: {interface['interface']}, Description: {interface['description']}, "
                    f"VLAN: {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}, "
                    f"Type: {interface['type']}, MAC Addresses: {', '.join(interface['macs'])}"
                )

        # Done
        device.disconnect()
        sys.exit(0)


if __name__ == "__main__":
    main()
