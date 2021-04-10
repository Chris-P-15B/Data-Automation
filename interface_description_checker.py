#!/usr/bin/env python3

"""
(c) 2020 - 2021, Chris Perkins
Licence: BSD 3-Clause

Logs into a seed device then generates interface descriptions based upon CDP or LLDP neighbours & checks
if the interface description contains this. If not, creates config to fix the interface description.
Then logs into the neighbours found to repeat the process. Suggested interface config is displayed.

Portions of this code from cdpneighbors.py, (c) 2017 Greg Mueller, https://github.com/grelleum/youtube-network-automation/tree/master/10.Refactoring_CDP_Neighbors
& used under the MIT licence.

v1.3 - small bug fix
v1.2 - added device auto-detection, Juniper & Arista support. Fixed Cisco multi-line neighbor output parsing.
v1.1 - bug fixes & added validating existing interface descriptions
v1.0 - initial release

To Do:
SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
"""

import sys, re
from getpass import getpass
from netmiko.ssh_exception import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler


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


def main():
    seed_device = input("Seed device: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    device_list = [seed_device]
    # Regex to match the start of neighbor hostname, use this to filter non-infrastucture devices, e.g. phones
    # Update this regex as needed to match your environment
    valid_neighbors = r"^(BBR|DLR|CUBE|ECR|EISA|EOFR|EOFS|FWR|FWS|ICR|ILO|ISA|OFR|OFS|SBC|SDWANR|SFS|UFS|VGG|VGR|WANR)"
    for target_device in device_list:
        try:
            # Auto-detect device type & establish correct SSH connection
            best_match = guess_device_type(
                {
                    "device_type": "autodetect",
                    "host": target_device,
                    "username": target_username,
                    "password": target_password,
                }
            )
            if best_match is None:
                continue

            print(f"\nConnecting to device: {target_device}, type: {best_match}")
            device = ConnectHandler(
                device_type=best_match,
                host=target_device,
                username=target_username,
                password=target_password,
            )
        except (NetMikoAuthenticationException):
            print(
                f"Failed to execute CLI on {target_device} due to incorrect credentials."
            )
            continue
        except (NetMikoTimeoutException, SSHException):
            print(
                f"Failed to execute CLI on {target_device} due to timeout or SSH not enabled."
            )
            continue
        except ValueError:
            print(f"Unsupported platform {target_device}, {best_match}.")
            continue
        else:
            # Cisco IOS, IOS XE & NX-OS
            if (
                best_match == "cisco_ios"
                or best_match == "cisco_xe"
                or best_match == "cisco_nxos"
            ):
                # Grab CDP neighbours & parse
                cli_output = device.send_command("show cdp neighbors")
                lines = cli_output.splitlines()
                # Find column heading line
                cntr = 0
                for line in lines:
                    cntr += 1
                    if "Device ID" in line or "Device-ID" in line:
                        break
                lines = cli_output.splitlines()[cntr:]
                hostname = None
                config = []
                for line in lines:
                    words = line.split()
                    # Only parse valid CDP neighbours entries
                    if not re.search(r"Total (cdp )?entries", line) and words:
                        if hostname is None:
                            hostname = words.pop(0).split(".")[0]
                        # If line is more than just hostname, parse interfaces
                        if len(words) > 1:
                            # Skip non-network infrastucture neighbours by checking start of hostname
                            if not re.search(valid_neighbors, hostname.upper()):
                                hostname = None
                                continue
                            # Generate interface description
                            # Kludge for NX-OS support
                            if re.search(r"\d", words[0]):
                                # NX-OS
                                local = words[0]
                                remote = words[-1]
                            else:
                                # IOS / IOS-XE
                                local = "".join(words[0:2])
                                # Interface names without / don't have a space (e.g. mgmt0)
                                if "/" not in words[-1]:
                                    remote = words[-1]
                                else:
                                    remote = "".join(words[-2:])
                            description = f"{hostname} {remote}"
                            # Grab full description from show interface & check if it contains description
                            # generated from CDP neighbours (case insensitive), if not then create config
                            cli_output2 = device.send_command(f"show interface {local}")
                            int_description = re.search(
                                r"Description: (.+)\n", cli_output2
                            )
                            int_description = (
                                int_description.group(1).rstrip()
                                if int_description
                                else ""
                            )
                            if not description.upper() in int_description.upper():
                                config.append(f"interface {local}")
                                config.append(f" description {description}")
                                config.append("!")
                            # Add newly found devices to the list
                            if (
                                (not hostname in device_list)
                                and (not hostname.upper() in device_list)
                                and (not hostname.lower() in device_list)
                            ):
                                device_list.append(hostname)
                            hostname = None

                # Grab LLDP neighbours & parse
                cli_output = device.send_command("show lldp neighbors")
                lines = cli_output.splitlines()
                # Find column heading line
                cntr = 0
                for line in lines:
                    cntr += 1
                    if "Device ID" in line:
                        break
                lines = cli_output.splitlines()[cntr:]
                hostname = None
                for line in lines:
                    words = line.split()
                    # Only parse valid LLDP neighbours entries
                    if not re.search(r"Total entries displayed", line) and words:
                        if hostname is None:
                            hostname = words[0].split(".")[0]
                        # If line is more than just hostname, parse interfaces
                        if len(words) > 1:
                            # Skip non-network infrastucture neighbours by checking start of hostname
                            if not re.search(valid_neighbors, hostname.upper()):
                                hostname = None
                                continue
                            # Generate interface description
                            # Kludge for if there's no gap between hostname & local interface, IOS & IOS XE only
                            if best_match == "cisco_nxos" or len(words) != 4:
                                local = words[0]
                                remote = words[-1]
                            else:
                                local = words[0][20:].strip()
                                remote = words[-1]
                            description = f"{hostname} {remote}"
                            # Grab full description from show interface & check if it contains description
                            # generated from LLDP neighbours (case insensitive), if not then create config
                            cli_output2 = device.send_command(f"show interface {local}")
                            int_description = re.search(
                                r"Description: (.+)\n", cli_output2
                            )
                            int_description = (
                                int_description.group(1).rstrip()
                                if int_description
                                else ""
                            )
                            if not description.upper() in int_description.upper():
                                config.append(f"interface {local}")
                                config.append(f" description {description}")
                                config.append("!")
                            # Add newly found devices to the list
                            if (
                                (not hostname in device_list)
                                and (not hostname.upper() in device_list)
                                and (not hostname.lower() in device_list)
                            ):
                                device_list.append(hostname)
                            hostname = None
                print("\n".join(config))
                device.disconnect()

            # Juniper JunOs
            elif best_match == "juniper" or best_match == "juniper_junos":
                # Grab LLDP neighbours & parse
                cli_output = device.send_command("show lldp neighbors")
                lines = cli_output.splitlines()
                # Find column heading line
                cntr = 0
                for line in lines:
                    cntr += 1
                    if "Local Interface" in line:
                        break
                lines = cli_output.splitlines()[cntr:]
                hostname = None
                config = []
                for line in lines:
                    words = line.split()
                    # Only parse valid LLDP neighbours entries
                    if not re.search(r"master", line) and words:
                        if hostname is None:
                            hostname = words.pop(-1).split(".")[0]
                        if len(words) > 0:
                            # Skip non-network infrastucture neighbours by checking start of hostname
                            if not re.search(valid_neighbors, hostname.upper()):
                                hostname = None
                                continue
                            # Generate interface description
                            local = words[0]
                            remote = words[-1]
                            description = f"{hostname} {remote}"
                            # Grab full description from show interface & check if it contains description
                            # generated from LLDP neighbours (case insensitive), if not then create config
                            cli_output2 = device.send_command(f"show interface {local}")
                            int_description = re.search(
                                r"Description: (.+)\n", cli_output2
                            )
                            int_description = (
                                int_description.group(1).rstrip()
                                if int_description
                                else ""
                            )
                            if not description.upper() in int_description.upper():
                                config.append(
                                    f"set interface {local} description {description}"
                                )
                            # Add newly found devices to the list
                            if (
                                (not hostname in device_list)
                                and (not hostname.upper() in device_list)
                                and (not hostname.lower() in device_list)
                            ):
                                device_list.append(hostname)
                            hostname = None
                print("\n".join(config))
                device.disconnect()

            # Arista EOS
            elif best_match == "arista_eos":
                # Grab LLDP neighbours & parse
                cli_output = device.send_command("show lldp neighbors")
                lines = cli_output.splitlines()
                # Find column heading line
                cntr = 0
                for line in lines:
                    cntr += 1
                    if "Neighbor Device ID" in line:
                        break
                lines = cli_output.splitlines()[cntr:]
                hostname = None
                config = []
                for line in lines:
                    words = line.split()
                    # Only parse valid LLDP neighbours entries
                    if words:
                        if hostname is None:
                            hostname = words.pop(1).split(".")[0]
                        if len(words) > 0:
                            # Skip non-network infrastucture neighbours by checking start of hostname
                            if not re.search(valid_neighbors, hostname.upper()):
                                hostname = None
                                continue
                            # Generate interface description
                            local = words[0]
                            remote = words[-2]
                            description = f"{hostname} {remote}"
                            # Grab full description from show interface & check if it contains description
                            # generated from LLDP neighbours (case insensitive), if not then create config
                            cli_output2 = device.send_command(f"show interface {local}")
                            int_description = re.search(
                                r"Description: (.+)\n", cli_output2
                            )
                            int_description = (
                                int_description.group(1).rstrip()
                                if int_description
                                else ""
                            )
                            if not description.upper() in int_description.upper():
                                config.append(f"interface {local}")
                                config.append(f" description {description}")
                                config.append("!")
                            # Add newly found devices to the list
                            if (
                                (not hostname in device_list)
                                and (not hostname.upper() in device_list)
                                and (not hostname.lower() in device_list)
                            ):
                                device_list.append(hostname)
                            hostname = None
                print("\n".join(config))
                device.disconnect()

            # Unsupported, disconnect
            else:
                device.disconnect()

    sys.exit(0)


if __name__ == "__main__":
    main()