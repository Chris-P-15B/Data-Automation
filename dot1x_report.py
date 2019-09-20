#!/usr/bin/env python
# (c) 2019, Chris Perkins
# Reports on .1x authentication sessions on a Cisco switch, optionally output to CSV

# v1.0 - initial release

# To Do:
# SSH tunnelling, seems to be broken on Windows: https://github.com/paramiko/paramiko/issues/1271
# Web frontend
# IPv6 support

import sys, re, csv, socket
from getpass import getpass
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
from netmiko import ConnectHandler

if __name__ == "__main__":
    target_switch = input("Target switch: ")
    target_username = input("Username: ")
    target_password = getpass("Password: ")
    authentication_list = []
    try:
        device = ConnectHandler(device_type="cisco_ios", host=target_switch, username=target_username,
            password=target_password, fast_cli=True)
    except NetMikoAuthenticationException:
        print(f"Failed to execute CLI on {target_switch} due to incorrect credentials.")
        sys.exit(1)
    except (NetMikoTimeoutException, SSHException):
        print(f"Failed to execute CLI on {target_switch} due to timeout or SSH not enabled.")
        sys.exit(1)
    else:
        # Grab authentication session status
        cli_output = device.send_command("show authentication sessions | inc Auth|Fail|Unauth")
        if cli_output == None or len(cli_output) == 0:
            print(f"{target_switch} has no .1x authentication sessions.")
            sys.exit(0)
        cli_output = cli_output.split("\n")
        # Iterate through authentication sessions to information
        for cli_line in cli_output:
            cli_items = cli_line.split()
            interface = cli_items[0]
            mac_address = cli_items[1]
            auth_method = cli_items[2]
            auth_domain = cli_items[3]
            auth_status = cli_items[4]
            # Retrieving IP address & hostname requires extra steps
            cli_output2 = device.send_command(f"show ip arp {mac_address}")
            if cli_output2 != None or len(cli_output2) != 0:
                ip_address = re.search(r"Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", cli_output2)
                if ip_address:
                    ip_address = ip_address.group(1)
                    try:
                        reversed_dns = socket.gethostbyaddr(ip_address)
                    except socket.herror:
                        hostname = ''
                    else:
                        hostname = reversed_dns[0]
                else:
                    ip_address = ''
                    hostname = ''
            authentication_dict = {"interface": interface, "mac_address": mac_address, "ip_address": ip_address,
                "hostname": hostname, "auth_method": auth_method, "auth_domain": auth_domain,
                "auth_status": auth_status}
            authentication_list.append(authentication_dict)

        # Output the results to CLI or CSV
        if len(sys.argv) == 2:
            # Output to CSV
            try:
                with open(sys.argv[1], 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    result_list = [["Interface", "MAC Address", "IP Address", "Hostname", "Auth Method",
                        "Auth Domain", "Auth Status"]]
                    for auth in authentication_list:
                        result_list.append([auth['interface'], auth['mac_address'], auth['ip_address'],
                            auth['hostname'], auth['auth_method'], auth['auth_domain'], auth['auth_status']])
                    writer.writerows(result_list)
            except OSError:
                print(f"Unable to write CSV file {sys.argv[1]}.")
                sys.exit(1)
        else:
            # Output to CLI
            print(f"{target_switch} .1x Authentication Report:")
            for auth in authentication_list:
                print(f"Interface: {auth['interface']}, MAC Address: {auth['mac_address']}, IP Address: {auth['ip_address']},"
                    f" Hostname: {auth['hostname']}, Auth Method: {auth['auth_method']}, Auth Domain: {auth['auth_domain']},"
                    f" Auth Status: {auth['auth_status']}")

    # Done
    device.disconnect()
    sys.exit(0)