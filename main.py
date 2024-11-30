"""
Documentation for Packet Analysis and GUI Framework Code

This code provides tool to analyse network packets, filter them, and potentially use a GUI framework for displaying results.
It Includes packet filtering, detailed packet extraction, and utility functions.
"""

import sys
import os 
import threading 
import queue 
from datetime import datetime 
from collections import Counter, defaultdict

import tkinter as tk 
from tkinter import ttk, scrolledtext, messagebox 

from scapy.all import (
    AsyncScniffer, Ether , IP, TCP, UDP, ICMP,
    DHCP, BOOTP, DNS, IPv6, ARP, Raw, conf, get_if_list, get_if_addr, get_workinfg_if
)
from scapy.arch import get_if_raw_addr
import netifaces 
import psutil
import subprocess
import socket # For resolving port umbers to services names

# Avaible protocols for filtering
AVAILABLE_PROTOCOLS =['TCP', 'UDP', 'ICMP', 'DNS', 'DHCP', 'IPv6', 'ARP', 'ALL']

def get_service_name(port):
    """
    Resolves a port number to its service name
    
    Args:
        port (int): The port number to resolve.
    Returns:
        str: The service name or "Unknown if not found.
    """
    try:
        return socket.getservbyport(int(port))
    except:
        return "Unknown"
    
class PacketFilter:
    """
    Defines filtering rules for network packets.
    
    Attributes:
        protocols (list): List of allowed protocols (e.g., ['TCP', 'UDP']). Defaults to ['ALL']. 
        target_ip (str): IP address to filter packets by source or destination.
    """
    def __init__(self, protocols=None, target_ip=None):
        """
        Initializes the filter with optional protocols and target IP.
        """
        self.protocols = protocols or ['All']
        self.protocols = [p.upper() for p in self.potocols]
        self.target_ip = target_ip

    def matches_filter(self, packet_details):
        """
        Check of packet matches filter criteria.

        Args:
            packet_details (dict): Extracted packet details.

        Returns:
            bool: True if the packet matches the filter; False otherwise.
        """
        # If no filtrers are set, accept all packets
        if self.protocols == ['ALL'] and not self.target_ip:
            return True
        
        # Get the actual protocol from packet_details
        protocol = packet_details.get('protocol')
        if protocol is None:
            return False
        
        # Check protocol filter 
        if self.protocols != ['All']:
            if protocol not in self.protocols:
                return False
            
        # Check IP filter if target_ip is specified
        if self.target_ip:
            src_ip = packet_details.get('scr_ip')
            dst_ip = packet_details.get('dst_ip')
            if not (src_ip == self.target_ip or dst_ip == self.target_ip):
                return False
            
        return True
    
    def extract_packet_details(packet, active_filters=None):
        """
        Extract detail from a network packet and optionally filters it using the PacketFilter.
        
        Args:
            packet (Scapy packet): The packet to analyze.
            active_filters (PacketFilter, optional): Filter to apply to the packet.
        
        Retuns: 
            dict or None: Extracted packet details if matching the filter, or None if not.
        """
        try:
            packet_details = {
                "prtocols": None,
                "src_ip": None,
                "dts_port": None,
                "src_port": None,
                "dst_port": None,
                "mac_src": None,
                "mac_dst": None,
                "additional_info": {},
                'payload': {
                    "hex": None,
                    "ascii": None,
                    "length": 0
                }
            }

            #Protocol detection need to be done first
            if DNS in packet:
                packet_details["protocol"] = "DNS"
            elif DHCP in packet:
                packet_details["protocol"] = "DHCP"
            elif ICMP in packet:
                packet_details["protocol"] = "ICMP"
            elif TCP in packet:
                packet_details["protocol"] = "TCP"
            elif UDP in packet:
                packet_details["protocol"] = "UDP"
            elif IPv6 in packet:
                packet_details["protocol"] = "IPv6"
            elif ARP in packet:
                packet_details["protocol"] = "ARP"
            
            # Extract Ethernet layer datails
            if Ether in packet:
                eth_layer = packet[Ether]
                packet_details["mac_src"] = eth_layer.src
                packet_details["mac_dst"] = eth_layer.dst

            # Handle IPv4
            if IP in packet:
                ip_layer = packet[IP]
                packet_details["src_ip"] = ip_layer.src
                packet_details["dst_ip"] = ip_layer.dst
                # Don't override protocol if it's alrady set (e.g., DNS, DHCP)
                if not packet_details["prtocols"]:
                    packet_details["protocol"] = "IPv4"
                packet_details["additional_info"].update({
                    "ip_version": "IPv4",
                    "headrer_length": ip_layer.ihl * 4,
                    "tos": ip_layer.tos,
                    "total_length": ip_layer.len,
                    "identification": ip_layer.id,
                    "flags": {
                        "reserved": bool(ip_layer.flags & 0x4),
                        "dont_fragment": bool(ip_layer.flags.DF),
                        "more_fragments": bool(ip_layer.flags.MF)
                    },
                    "fragment_offset": ip_layer.frag,
                    "ttl": ip_layer.ttl,
                    "checksum": hex(ip_layer.chksum),
                    "ip_flags": str(ip_layer.flags)
                })
        
            # Handle IPv6
            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                packet_details["src_ip"] = ipv6_layer.src
                packet_details["dst_ip"] = ipv6_layer.dst
                packet_details["protocols"] = "IPv6"
                packet_details["additional_info"].update({
                    "version": 6,
                    "traffic_class": ipv6_layer.tc,
                    "flow_label": ipv6_layer.fl,
                    "payload_length": ipv6_layer.plen,
                    "next_header": ipv6_layer.nh,
                    "hop_limit": ipv6_layer.hlim
                })

            # Handle Transport Layer
            if TCP in packet:
                tcp_layer = packet[TCP]
                packet_details["src_port"] = tcp_layer.sport
                packet_details["dst_port"] = tcp_layer.sport
                packet_details["protocol"] = "TCP"

                #Add TCP flags
                flags = []
                if tcp_layer.flags.S: flags.append('SYN')
                if tcp_layer.flags.A: flags.append('ACK')

                packet_details["additional_info"]["tcp_flags"] = '|'.join(flags) if flags else ''

                # Add connection state
                if tcp_layer.flags.S and tcp_layer.flags.A:
                    packet_details["additional_info"]["connection_state"] = "SYN-ACK"
                elif tcp_layer.flags.S:
                    packet_details["additional_info"]["connection_state"] = "SYN"
                elif tcp_layer.flags.A:
                    packet_details["additional_info"]["connection_state"] = "ACK"
            
            elif UDP in packet:
                udp_layer = packet[UDP]
                packet_details["src_port"] = udp_layer.sport
                packet_details["dst_port"] = udp_layer.sport
                packet_details["protocol"] = "UDP"
            elif ICMP in packet:
                packet_details["protocols"] = "ICMP"
                
            # Handle DNS
            if DNS in packet:
                dns_layer = packet[DNS]
                packet_details["protocol"] = "DNS"
                packet_details["additional_info"]["dns_id"] = dns_layer.id
                if dns_layer.qr == 0:
                    packet_details["additional_info"]["dns_type"] = "Query"
                else:
                    packet_details["additional_info"]["dns_type"] = "Response"
                if dns_layer.qd:
                    packet_details["additional_info"]["dns_type"] = dns_layer.qd.qname.decode()

            # Handle DHCP
            if DHCP in packet:
                dhcp_layer = packet[DHCP]
                packet_details["protocol"] = "DHCP"
                if BOOTP in packet:
                    bootp_layer = packet[BOOTP]
                    packet_details["additional_info"].update({
                        "client_ip": bootp_layer.ciaddr,
                        "your_ip": bootp_layer.yiaddr,
                        "server_ip": bootp_layer.siaddr,
                        "client_mac": bootp_layer.chaddr,
                    })
                
                # Get DHCP meaasge type
                for option in dhcp_layer.options:
                    if isinstance(option, tuple) and option[0] == 'message-type':
                        dhcp_types = {
                            1: "DISCOVER", 2: "OFFER", 3: "REQUEST",
                            4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE"
                        }
                        packet_details["addtional_info"]["dhcp_type"] = dhcp_types.get(option[1], f"Unknown({option[1]})")
                        break
            
            # Add payload processing for both Ipv4 and IPv6
            if IP in packet or IPv6 in packet:
                try:
                    if Raw in packet:
                        raw_payload = bytes(packet[Raw])
                        packet_details["payload"]["length"] = len(raw_payload)

                        if packet_details["payload"]["length"] > 0:
                            # Create hex dump with offsets
                            hex_lines = []
                            ascii_lines = []

                            for i in range(0, len(raw_payload), 16):
                                chunk = raw_payload[i:i+16]

                                # Hex format with offset
                                hex_values = ' '.join(f'{b:02x}' for b in chunk)
                                hex_lines.append(f'{b:02x} {hex_values:<47}')

                                #ASCII format (printable chars only)
                                ascii_chars = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                                ascii_lines.append(ascii_chars)
                            
                            packet_details["payload"]["hex"] = '\n'.join(hex_lines)
                            packet_details["payload"]["ascii"] = '\n'.join(ascii_lines)
                except Exception as e:
                    print(f"Error processing payload: {e}")

            if not any([packet_details["src_ip"], packet_details["dst_ip"], packet_details["protocol"]]):
                print(f"Unsupported packet: {packet.summary()}")
                return None
            
            # If filters are active, check if packet matches filter criteria
            if active_filters and not active_filters.matches_filter(packet_details):
                return None
            
            return packet_details
        except Exception as exception:
            print(f"Problems with processing packet: {packet} the problem is {exception}")
            return None