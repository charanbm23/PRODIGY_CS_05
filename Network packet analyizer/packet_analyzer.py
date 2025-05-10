#!/usr/bin/env python3

import sys
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import init, Fore, Style
import argparse
import binascii

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    filename='packet_log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class PacketAnalyzer:
    def __init__(self, protocol_filter=None, show_payload=False, log_file='packet_log.csv'):
        self.packet_count = 0
        self.protocol_filter = protocol_filter
        self.show_payload = show_payload
        self.log_file = log_file
        # Set up CSV logging
        self.logger = logging.getLogger('PacketLogger')
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(self.log_file, 'w', encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.handlers = [handler]
        # Write CSV header
        self.logger.info('No,Timestamp,Source IP,Destination IP,Protocol,Source Port,Destination Port,Payload')

    def process_packet(self, packet):
        """Process and analyze each captured packet."""
        self.packet_count += 1
        
        # Extract basic packet information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            
            # Get protocol name
            if TCP in packet:
                protocol_name = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol_name = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                protocol_name = "ICMP"
                src_port = dst_port = "N/A"
            else:
                protocol_name = "Other"
                src_port = dst_port = "N/A"

            # Protocol filter
            if self.protocol_filter and protocol_name != self.protocol_filter.upper():
                return

            # Extract payload
            payload = ""
            if self.show_payload:
                if TCP in packet or UDP in packet:
                    raw = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
                    if raw:
                        try:
                            payload = raw.decode(errors='replace')
                        except Exception:
                            payload = binascii.hexlify(raw).decode()

            # Create packet info string
            packet_info = (
                f"\n{Fore.CYAN}[*] Packet #{self.packet_count}{Style.RESET_ALL}\n"
                f"{Fore.GREEN}Source IP: {src_ip}{Style.RESET_ALL}\n"
                f"{Fore.GREEN}Destination IP: {dst_ip}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Protocol: {protocol_name}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Source Port: {src_port}{Style.RESET_ALL}\n"
                f"{Fore.YELLOW}Destination Port: {dst_port}{Style.RESET_ALL}\n"
            )
            if self.show_payload and payload:
                packet_info += f"{Fore.MAGENTA}Payload: {payload}{Style.RESET_ALL}\n"
            print(packet_info)
            
            # Log packet information
            logging.info(
                f"Packet #{self.packet_count} | "
                f"Source: {src_ip}:{src_port} | "
                f"Destination: {dst_ip}:{dst_port} | "
                f"Protocol: {protocol_name}"
            )

            # Log packet info as CSV
            timestamp = datetime.now().isoformat()
            csv_line = f'{self.packet_count},{timestamp},{src_ip},{dst_ip},{protocol_name},{src_port},{dst_port},"{payload.replace('"', '""')}"'
            self.logger.info(csv_line)

    def start_sniffing(self, interface=None, count=0):
        """Start packet sniffing on the specified interface."""
        print(f"{Fore.CYAN}[*] Starting packet capture...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Press Ctrl+C to stop{Style.RESET_ALL}")
        
        try:
            sniff(
                iface=interface,
                prn=self.process_packet,
                count=count,
                store=0
            )
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Stopping packet capture...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Total packets captured: {self.packet_count}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Network Packet Analyzer')
    parser.add_argument('--interface', '-i', help='Network interface to sniff on')
    parser.add_argument('--protocol', '-p', help='Filter by protocol (TCP, UDP, ICMP)')
    parser.add_argument('--show-payload', action='store_true', help='Display packet payloads')
    parser.add_argument('--log-file', default='packet_log.csv', help='Log file name (CSV format)')
    args = parser.parse_args()
    analyzer = PacketAnalyzer(protocol_filter=args.protocol, show_payload=args.show_payload, log_file=args.log_file)
    analyzer.start_sniffing(interface=args.interface)

if __name__ == "__main__":
    main() 