#!/usr/bin/env python3

"""
(c) 2019 - 2021, Chris Perkins
Licence: BSD 3-Clause

Checks a Cisco switch for interfaces that are currently not connected & reports relevant
information, optionally output to CSV

v1.5 - bug fixes & improvements to output parsing
v1.4 - disabled fast_cli due to issues, fixed edge case for empty show output
v1.3 - enabled fast_cli & use show interface for full description
v1.2 - code tidying
v1.1 - fixed switch uptime output to CSV
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
        # Grab show version & extract uptime
        cli_output = device.send_command("show version")
        switch_uptime = re.search(r"uptime is \d+.+\n", cli_output)
        if switch_uptime:
            switch_uptime = switch_uptime.group(0)
            switch_uptime = switch_uptime.strip("\n")
            switch_uptime = switch_uptime.replace(",", "")
        else:
            switch_uptime = "uptime is unknown"
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

        # Parse output & retrieve information for interfaces that aren't connected
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
                # Ignore port-channel interfaces
                if re.search(r"^Po\d+", interface_dict["interface"]):
                    continue
                # Filter for interfaces that aren't connected
                if interface_dict["status"] and interface_dict["status"] in (
                    "notconnec",
                    "notconnect",
                    "xcvrAbsen",
                    "sfpAbsent",
                    "disabled",
                ):
                    # Grab last input time
                    cli_output2 = device.send_command(
                        f"show interface {interface_dict['interface']}"
                    )
                    last_input = re.search(r"Last input ([0-9:a-z]+), ", cli_output2)
                    last_input = last_input.group(1) if last_input else "unknown"
                    interface_dict["last_input"] = last_input
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
                    writer = csv.writer(csv_file)
                    result_list = [
                        [
                            "Switch Uptime",
                            "Interface",
                            "Description",
                            "VLAN",
                            "Speed",
                            "Duplex",
                            "Type",
                            "Last Input",
                        ]
                    ]
                    for interface in interface_list:
                        result_list.append(
                            [
                                target_switch + " " + switch_uptime,
                                interface["interface"],
                                interface["description"],
                                interface["VLAN"],
                                interface["speed"],
                                interface["duplex"],
                                interface["type"],
                                interface["last_input"],
                            ]
                        )
                    writer.writerows(result_list)
            except OSError:
                print(f"Unable to write CSV file {sys.argv[1]}.")
                sys.exit(1)
        else:
            # Output to CLI
            print(f"{target_switch} {switch_uptime}\n\nUnused Interface List:")
            for interface in interface_list:
                print(
                    f"Interface: {interface['interface']}, Description: {interface['description']}, VLAN:"
                    f" {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}"
                    f", Type: {interface['type']}, Last Input: {interface['last_input']}"
                )

        # Done
        device.disconnect()
        sys.exit(0)


if __name__ == "__main__":
    main()