#!/usr/bin/env python3

"""
Copyright (c) 2019 - 2023, Chris Perkins
Licence: BSD 3-Clause

Reports switch's connected interface status & details (MAC address, IP address & hostname) of connected hosts.
Results are displayed & also output to a CSV file named after each device.

v1.4 - rewritten to handle multiple switches, with ARP & DNS lookup details & Arista support also
v1.3 - bug fixes & improvements to output parsing
v1.2 - disabled fast_cli due to issues, fixed edge case for empty show output
v1.1 - enabled fast_cli & use show interface for full description
v1.0 - initial release

To Do:
SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
Web frontend
"""


import sys
import re
import socket
import csv
from cryptography.fernet import Fernet
from getpass import getpass
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
from threading import Thread


def guess_device_type(remote_device):
    """Auto-detect device type"""
    try:
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
    except (NetMikoAuthenticationException):
        print(
            f"Failed to execute CLI on {remote_device['host']} due to incorrect credentials."
        )
        return None
    except (NetMikoTimeoutException, SSHException):
        print(
            f"Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled."
        )
        return None
    except ValueError:
        print(
            f"Unsupported platform {remote_device['host']}, {remote_device['device_type']}."
        )
        return None
    else:
        return best_match


def dns_reverse_lookup(ip_address, dns_table):
    """DNS reverse lookup, update dictionary with result"""
    try:
        reversed_dns = socket.gethostbyaddr(ip_address)
    except socket.herror:
        # No DNS record, don't store in dictionary
        pass
    else:
        dns_table[ip_address] = reversed_dns[0]


def validate_mac_address(mac_address):
    """Validate MAC address & return it in standard format"""
    mac_address = mac_address.lower()
    for digit in mac_address:
        if digit in ".:-":
            mac_address = mac_address.replace(digit, "")
    if len(mac_address) != 12:
        return None
    for digit in mac_address:
        if digit not in [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
        ]:
            return None
    mac_address = mac_address[0:4] + "." + mac_address[4:8] + "." + mac_address[8:12]
    return mac_address


def scrape_switch_details(target_device, target_username, target_password, output_text):
    """Connect to a switch & parse outputs to retrieve connected interface's MAC, ARP & hostname details"""
    output_messages = ""
    try:
        # Auto-detect device type & establish correct SSH connection
        best_match = guess_device_type(
            {
                "device_type": "autodetect",
                "host": target_device,
                "username": target_username,
                "password": target_password,
                "read_timeout_override": 60,
                "fast_cli": False,
            }
        )
        if best_match is None:
            output_messages += f"Error: Unknown platform for {target_device}.\n"
            output_text.append(output_messages)
            return

        output_messages += (
            f"\nConnecting to device: {target_device}, type: {best_match}\n"
        )
        device = ConnectHandler(
            device_type=best_match,
            host=target_device,
            username=target_username,
            password=target_password,
            secret=target_password,
            read_timeout_override=25,
            fast_cli=False,
            global_cmd_verify=False,
        )
    except (NetMikoAuthenticationException):
        output_messages += (
            f"Failed to execute CLI on {target_device} due to incorrect credentials.\n"
        )
        output_text.append(output_messages)
        return
    except (NetMikoTimeoutException, SSHException):
        output_messages += f"Failed to execute CLI on {target_device} due to timeout or SSH not enabled.\n"
        output_text.append(output_messages)
        return
    except ValueError:
        output_messages += f"Unsupported platform {target_device}, {best_match}.\n"
        output_text.append(output_messages)
        return
    else:
        device.enable()
        interface_list = []

        # Cisco IOS, IOS XE & NX-OS
        if (
            best_match == "cisco_ios"
            or best_match == "cisco_xe"
            or best_match == "cisco_nxos"
        ):
            # Parse ARP table into dictionary to refer back to
            arp_table = {}
            cli_output = device.send_command("show ip arp")
            for cli_line in cli_output.split("\n"):
                if best_match == "cisco_nxos":
                    arp_entry = re.search(
                        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                        cli_line,
                    )
                else:
                    arp_entry = re.search(
                        r"^Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                        cli_line,
                    )
                if arp_entry:
                    ip_address = arp_entry.group(1)
                    mac_address = validate_mac_address(arp_entry.group(2))
                    arp_table[mac_address] = ip_address

            # Multi-threaded DNS reverse lookup, store in dictionary to refer back to
            dns_table = {}
            dns_threads = []
            for ip_address in arp_table.values():
                dns_worker = Thread(
                    target=dns_reverse_lookup, args=(ip_address, dns_table)
                )
                dns_worker.start()
                dns_threads.append(dns_worker)
            for dns_worker in dns_threads:
                dns_worker.join()

            # Grab interface status
            cli_output = device.send_command("show interface status")
            cli_output = cli_output.split("\n")
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
                    if (
                        interface_dict["status"]
                        and interface_dict["status"] in "connected"
                    ):
                        cli_output2 = device.send_command(
                            f"show mac address-table interface {interface_dict['interface']}"
                        )
                        cli_output2 = cli_output2.split("\n")
                        connected_hosts = []
                        for mac_line in cli_output2:
                            mac_address = re.search(
                                r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                                mac_line,
                            )
                            if mac_address:
                                mac_address = validate_mac_address(mac_address.group(1))
                                # Exclude broadcast MAC
                                if mac_address != "ffff.ffff.ffff":
                                    # Lookup IP address & hostname in stored tables
                                    if arp_table.get(mac_address, None):
                                        ip_address = arp_table[mac_address]
                                        if dns_table.get(ip_address, None):
                                            hostname = dns_table[ip_address]
                                        else:
                                            hostname = ""
                                    else:
                                        ip_address = ""
                                        hostname = ""
                                    connected_hosts.append(
                                        {
                                            "mac": mac_address,
                                            "ip": ip_address,
                                            "dns": hostname,
                                        }
                                    )
                        interface_dict["hosts"] = connected_hosts
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

            device.disconnect()

        # Juniper JunOs
        elif best_match == "juniper" or best_match == "juniper_junos":
            # Do something
            device.disconnect()

        # Arista EOS
        elif best_match == "arista_eos":
            # Parse ARP table into dictionary to refer back to
            arp_table = {}
            cli_output = device.send_command("show ip arp")
            for cli_line in cli_output.split("\n"):
                arp_entry = re.search(
                    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                    cli_line,
                )
                if arp_entry:
                    ip_address = arp_entry.group(1)
                    mac_address = validate_mac_address(arp_entry.group(2))
                    arp_table[mac_address] = ip_address

            # Multi-threaded DNS reverse lookup, store in dictionary to refer back to
            dns_table = {}
            dns_threads = []
            for ip_address in arp_table.values():
                dns_worker = Thread(
                    target=dns_reverse_lookup, args=(ip_address, dns_table)
                )
                dns_worker.start()
                dns_threads.append(dns_worker)
            for dns_worker in dns_threads:
                dns_worker.join()

            # Grab interface status
            cli_output = device.send_command("show interface status")
            cli_output = cli_output.split("\n")
            # Find offsets for column headings in the output
            for cli_line in cli_output:
                PORT_COLUMN = cli_line.find("Port")
                NAME_COLUMN = cli_line.find("Name")
                STATUS_COLUMN = cli_line.find("Status")
                VLAN_COLUMN = cli_line.find("Vlan")
                DUPLEX_COLUMN = cli_line.find("Duplex")
                SPEED_COLUMN = cli_line.find("Speed")
                TYPE_COLUMN = cli_line.find("Type")
                FLAGS_COLUMN = cli_line.find("Flags")

                if (
                    PORT_COLUMN
                    == NAME_COLUMN
                    == STATUS_COLUMN
                    == VLAN_COLUMN
                    == DUPLEX_COLUMN
                    == SPEED_COLUMN
                    == TYPE_COLUMN
                    == FLAGS_COLUMN
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
                        "duplex": cli_line[DUPLEX_COLUMN:SPEED_COLUMN].strip(),
                        "speed": cli_line[SPEED_COLUMN:TYPE_COLUMN].strip(),
                        "type": cli_line[TYPE_COLUMN:FLAGS_COLUMN].strip(),
                    }
                    # Filter for interfaces that are connected
                    if (
                        interface_dict["status"]
                        and interface_dict["status"] in "connected"
                    ):
                        cli_output2 = device.send_command(
                            f"show mac address-table interface {interface_dict['interface']}"
                        )
                        cli_output2 = cli_output2.split("\n")
                        connected_hosts = []
                        for mac_line in cli_output2:
                            mac_address = re.search(
                                r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                                mac_line,
                            )
                            if mac_address:
                                mac_address = validate_mac_address(mac_address.group(1))
                                # Exclude broadcast MAC
                                if mac_address != "ffff.ffff.ffff":
                                    # Lookup IP address & hostname in stored tables
                                    if arp_table.get(mac_address, None):
                                        ip_address = arp_table[mac_address]
                                        if dns_table.get(ip_address, None):
                                            hostname = dns_table[ip_address]
                                        else:
                                            hostname = ""
                                    else:
                                        ip_address = ""
                                        hostname = ""
                                    connected_hosts.append(
                                        {
                                            "mac": mac_address,
                                            "ip": ip_address,
                                            "dns": hostname,
                                        }
                                    )
                        interface_dict["hosts"] = connected_hosts
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

            device.disconnect()

        # Unsupported, disconnect
        else:
            output_messages += f"Unsupported platform {target_device}, {best_match}.\n"
            device.disconnect()
            return

        # Output the results to console & CSV file
        output_messages += f"\n{target_device} Interface & Connected Host List:\n\n"
        try:
            with open(f"{target_device}.csv", "w", newline="") as csv_file:
                writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
                result_list = [
                    [
                        "Interface",
                        "Description",
                        "VLAN",
                        "Speed",
                        "Duplex",
                        "Type",
                        "Hosts",
                    ]
                ]
                for interface in interface_list:
                    hosts = ""
                    for host in interface["hosts"]:
                        hosts += f"{host['mac']}"
                        if host["ip"]:
                            hosts += f" {host['ip']}"
                        if host["dns"]:
                            hosts += f" {host['dns']}"
                        hosts += ", "

                    hosts = hosts.strip(", ")
                    output_messages += (
                        f"Interface: {interface['interface']}, Description: {interface['description']}, "
                        f"VLAN: {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}, "
                        f"Type: {interface['type']}, Hosts: {hosts}\n"
                    )
                    line = [
                        interface["interface"],
                        interface["description"],
                        interface["VLAN"],
                        interface["speed"],
                        interface["duplex"],
                        interface["type"],
                    ]
                    line.extend(hosts.split(", "))
                    result_list.append(line)
                writer.writerows(result_list)
        except OSError:
            output_messages += f"Unable to write CSV file for {target_device}.\n"

        output_text.append(output_messages)


def main(device_list, target_username, target_password):
    device_threads = []
    output_text = []
    # Connect to each device in a separate thread
    for target_device in device_list:
        device_worker = Thread(
            target=scrape_switch_details,
            args=(target_device, target_username, target_password, output_text),
        )
        device_worker.start()
        device_threads.append(device_worker)
    for device_worker in device_threads:
        device_worker.join()

    # Display results
    for message in output_text:
        print(message)
    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Error: Usage '{sys.argv[0]} [target device list]'.")
        print(
            "Where target device list is a space delimited list of devices to connect to."
        )
        sys.exit(1)
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    main(sys.argv[1:], target_username, target_password)
