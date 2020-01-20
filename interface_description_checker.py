#!/usr/bin/env python
# (c) 2020, Chris Perkins
# Licence: BSD 3-Clause

# Logs into a seed Cisco device then generates interface descriptions based upon CDP neighbours & checks
# if the interface description contains this. If not, creates config to fix the interface description.
# Then logs into the neighbours found to repeat the process. Suggested interface config is displayed.

# Portions of this code from cdpneighbors.py, (c) 2017 Greg Mueller, https://github.com/grelleum/youtube-network-automation/tree/master/10.Refactoring_CDP_Neighbors
# & used under the MIT licence.

# v1.1 - bug fixes & added validating existing interface descriptions
# v1.0 - initial release

# To Do:
# Poll device via SNMP to determine device type & which code path to take to query CDP or LLDP neighbours
# SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271

import sys, re
from getpass import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler

def main():
    seed_device = input("Seed device: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    device_list = [seed_device]
    for target_device in device_list:
        print(f"\nConnecting to device: {target_device}")
        try:
            device = ConnectHandler(device_type="cisco_ios", host=target_device, username=target_username,
                password=target_password)
        except NetMikoAuthenticationException:
            print(f"Failed to execute CLI on {target_device} due to incorrect credentials.")
            continue
        except (NetMikoTimeoutException, SSHException):
            print(f"Failed to execute CLI on {target_device} due to timeout or SSH not enabled.")
            continue
        else:
            # Grab CDP neighbours & parse
            cli_output = device.send_command("show cdp neighbors")
            lines = cli_output.splitlines()
            # Find column heading line
            cntr = 0
            for line in lines:
                cntr += 1
                if ("Device ID" in line) or ("Device-ID" in line):
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
                    if len(words) > 0:
                        # Skip non-network infrastucture neighbours by checking start of hostname,
                        # update regex as needed
                        if not re.search(r"^(BBR|DLR|CUBE|ECR|EISA|EOFR|EOFS|FWR|FWS|ICR|ILO|ISA|OFR|"
                            r"OFS|SBC|SDWANR|SFS|UFS|VGG|VGR|WANR)", hostname.upper()):
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
                            remote = "".join(words[-2:])
                        description = f"{hostname} {remote}"
                        # Grab full description from show interface & check if it contains description
                        # generated from CDP neighbours (case insensitive), if not then create config
                        cli_output2 = device.send_command(f"show interface {local}")
                        int_description = re.search(r"Description: (.+)\n", cli_output2)
                        int_description = int_description.group(1).rstrip() if int_description else ""
                        if not description.upper() in int_description.upper():
                            config.append(f"interface {local}")
                            config.append(f" description {description}")
                            config.append("!")
                        # Add newly found devices to the list
                        if ((not hostname in device_list) and (not hostname.upper() in device_list) and
                            (not hostname.lower() in device_list)):
                            device_list.append(hostname)
                        hostname = None
            print("\n".join(config))
            device.disconnect()
    sys.exit(0)

if __name__ == "__main__":
    main()