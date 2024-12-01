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
    DHCP, BOOTP, DNS, IPv6, ARP, Raw, conf, get_if_list, get_if_addr, get_working_if
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
        


    def format_packet_data(packet_details):
        try:
            #making names for user to use
            field_mapping = {
                "protocol" : "Protocol",
                "src_ip" : "Source IP",
                "dest_ip" : "Destination IP",
                "src_port" : "Source Port",
                "dst_port" : "Destination Port",
                "mac_src" : "Source MAC",
                "mac_dst" : "Destination MAC"
            }

            #formating the packet data with defined mapping
            formated_data = {
                display_name: packet_details.get(field, "N/A")
                for field, display_name in field_mapping.items()
            }

            #additional info if avaible with keys
            if packet_details.get("additional_info"):
                for key, value in packet_details["additional_info"].items():
                    #replaceing underscores with spaces and capitalize
                    formated_data[key,replace("_", " ").title()] = value
            return formated_data

        except Exception as exception: #error handling during formating
            print(f"Problem formatting: {packet_details}.Error: {exception}")
            return None



    def handle_corrupted_packets(packet, required_layers = None):
        try: 
            # default for layer ethernet
            if required_layers is None:
                required_layers = [Ether] # modified to only require Ether for IPv6 support
            

            #checking if all requered layers are present
            for layer in required_layers:
                if not packet.haslayer(layer):
                    print(f"Packet missing layer: {layer.__name__}")
                    return False
            return True
        
        except Exception as exception: #error handling durig validation
            print(f"Problem validating packet: {packet.summary() if packet else 'None'}.Exception: {exception}")
            return False



    def summarize_packet(packet_details, summary_format = None):
        try:
            if not packet_details:
                return "Invalid packet details" # handle case where packet details missing

            if summary_format is None:
                summary_format = "[{protocol}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            #Preparing database with default values
            defaults = {
                "protocol" : "Unknown",
                "src_ip" : "N/A",
                "src_port" : "N/A",
                "dest_ip" : "N/A",
                "dst_port" : "N/A"
            }

            #populate data
            data = {key:packet_details.get(key, default) for key, default in defaults.items()}
            
            #Protocol info added to summary
            additional_info = packet_details.get("additional_info", {})
            if additional_info:
                #TCP handeled with SYN/ACK flags and IP info
                if data["protocol"] == "TCP":
                    #Adding TCP flags if there are some
                    if "tcp_flags" in additional_info and additional_info["tcp_flags"]:
                        summary_format += "[{tcp_flags}]"
                        data["tcp_flags"] = additional_info["tcp_flags"]
                        if "connection_state" in additional_info: #append DNS to dummstx
                            summary_format += "({connection_state})"
                            data["connection_state"] = additional_info["connection_state"]


                    #Adding IP header info
                    ip_info_parts = []
                    if "ttl" in additional_info:
                        ip_info_parts.append("TTL: {ttl}")
                        data["ttl"] = additional_info["ttl"]
                    if "checksum" in additional_info:
                        ip_info_parts.append("Checksum: {checksum}")
                        data["checksum"] = additional_info["checksum"]
                    if "ip_flags" in additional_info:
                        ip_info_parts.append("Flags: {ip_flags}")
                        data["ip_flags"] = additional_info["ip_flags"]

                    if ip_info_parts:
                        summary_format += f"[{', '.join(ip_info_parts)}]"

                    
                #Handle DNS
                elif data["protocol"] == "DNS" and "dns_type" in additional_info:
                    summary_format += "({dns_type})"
                    data["dns_type"] = additional_info["dns_type"]
                    if "dns_query" in additional_info:
                        summary_format += "Query: {dns_query}"
                        data["dns_query"] = additional_info["dns_query"]


                #Handle DHCP
                elif data["protocol"] == "DHCP" and "dhcp_type" in additional_info:
                    summary_format += "({dhcp_type})"
                    data["dhcp_type"] = additional_info["dhcp_type"]

                
                #Handle IPv6
                elif data["protocol"] == "IPv6":
                    summary_format += "[Hop Limit: {hop_limit}]"
                    data["hop_limit"] = additional_info.get["hop_limit", "N/A"]


                #Handle UDP with IP info
                elif data["protocol"] == "UDP":
                    ip_info_parts = []
                    if "ttl" in additional_info:
                        ip_info_parts.append("TTL: {ttl}")
                        data["ttl"] = additional_info["ttl"]
                    if "checksum" in additional_info:
                        ip_info_parts.append("Checksum: {checksum}")
                        data["checksum"] = additional_info["checksum"]

                    if ip_info_parts:
                        summary_format += f"[{', '.join(ip_info_parts)}]"


            #summary generaed
            return summary_format.format(**data)


        except Exception as exception: #error handling during creation of summary
            print(f"Error with summarizing packet: {packet_details}. Exception: {exception}")
            return "Problem with creating summary of packet"

    
class NetworkMonitor:
    @staticmethod
    def get_interface_details():
        #Geting detailed info about all network interfaces
        interfaces = {}

        #Get all interfaces
        for iface in get_if_list():
            try: 
                #get interface addresses
                addrs = netifaces.ifaddresses(iface)

                #get status
                if_stats = psutil.net_if_stats().get(iface)
                is_up = if_stats.isup if if_stats else False

                interfaces[iface] = {
                    'ip': get_if_addr(iface),
                    'mac': addrs.get(netifaces.AF_LINK, [{'addr': 'Unknown'}])[0]['addr'],
                    'is_up': is_up,
                    'speed': if_stats.speed if if_stats else 0,
                    'mtu': if_stats.mtu if if_stats else 0
                }

                #Get additional IPv4 info if possible
                if netifaces.AF_INET in addrs:
                    ipv4_info = addrs[netifaces.AF_INET][0]
                    interfaces[iface].update({
                        'netmask': ipv4_info.get('netmask', 'Unknown'),
                        'broadcast': ipv4_info.get('broadcast', 'Unknown')
                    })

            except Exception as e:
                print(f"Error getting details for {iface}: {e}")
                continue
        
        return interfaces

    @staticmethod
    def get_best_interface():
        #get the best interface for capturing
        #we try to get interface first
        default_iface = conf.iface

        #if not possible then get the first working interface
        if not default_iface:
            default_iface = get_working_if

        return default_iface

    @staticmethod
    def verify_interface(interface):
        #verify if an interface exists and is suitable for capture
        interfaces = NetworkMonitor.get_interface_details()

        if interface not in interface:
            print(f"Error: Interface '{interface}' not found")
            return False

        details = interfaces[interface]
        if not details ['is_up']:
            print(f"Warning: Interface '{interface}' is down")
            return False
        
        return True

    
class PacketStats: # tracks and manages statistics for captured network packets
    def __init__ (self):
        self.packet_counts = Counter()
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = datetime.now()
        self.current_packet_number = 0
        self.ip_stats = {
            'src': defaultdict(int),
            'dst': defaultdict(int)
        }
        self.port_stats = {
            'src': defaultdict(int),
            'dst': defaultdict(int)
        }
        self.protocol_bytes = defaultdict(int)

def process_packet_gui(packet, active_filters = None, stats = None, output_queue = None):
    try:
        #Extract details with filtering
        packet_details = extract_packet_details(packet, active_filters)

        if packet_details is None: # if details dont match filter skip
            return


        if stats is not None: #incrementing couts for protocols
            stats.total_packets += 1
            stats.current_packet_number += 1
            stats.packet_counts[packet_details['protocol']] += 1

        
            #track total bytes
            stats.total_bytes += len(packet)

            #track bytes per protocol
            stats.protocol_bytes[packet_details['protocol']] += len(packet)


            #track IP stats
            if packet_details.get('src_ip'):
                stats.ip_stats['src'][packet_details['src_ip']] += 1
            if packet_details.get('dst_ip'):
                stats.ip_stats['dst'][packet_details['dst_ip']] += 1
            
            #track port statistics
            if packet_details.get('src_ip'):
                src_port = int(packet_details['src_port'])
                stats.port_stats['src'][src_port] += 1
            if packet_details.get('dst_ip'):
                dst_ip = int(packet_details['dst_ip'])
                stats.port_stats['dst'][dst_ip] += 1

            output_lines = []

            output_lines.append(f"\nPacket #{stats.current_packet_number}")
            output_lines.append(f"Info: {packet.summary()}")


            if not handle_corrupted_packets(packet):
                output_lines.append(f"Corrupted or unsupported packet is skipped: {packet.summary()}")
                return

            formatted_data = format_packet_data(packet_details)
            if not formatted_data:
                output_lines.append("Failed to format packet details")
                return

            summary = sumarize_packet(packet_details)

            #create a more detailed output based on protocol type
            output_lines.append("\n" + "="*60)
            output_lines.append(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%m:%S.%f')[:-3]}")
            output_lines.append("-"*60)


            #basic protocol info
            output_lines.append(f"Protocol: {formatted_data['Protocol']}")


            #network layer info
            output_lines.append("\nNetwork Layer:")
            output_lines.append(f"Source IP:       {formatted_data['Source IP']}")
            output_lines.append(f"Destination IP:  {formatted_data['Destination IP']}")


            #transport layer info
            if formatted_data['Protocol'] != 'ARP' and (formatted_data.get('Source Port') != 'N/A' or formatted_data.get('Destination Port') != 'N/A'):
                output_lines.append("\Transport Layer:")
                output_lines.append(f"Source Port:       {formatted_data['Source Port']}")
                output_lines.append(f"Destination Port:  {formatted_data['Destination Port']}")


            #link layer info
            output_lines.append("\Link Layer:")
            output_lines.append(f"Source MAC:       {formatted_data['Source MAC']}")
            output_lines.append(f"Destination MAC:  {formatted_data['Destination MAC']}")


            #protocol spec. info
            protocol_specific = {k: v for k, v in formatted_data.items()
                                if k not in ['Protocol', 'Source IP', 'Destination IP',
                                            'Source Port', 'Destination Port', 
                                            'Source MAC', 'Destination MAC']}

            if protocol_specific:
                output_lines.append("\nProtocol Details:")
                for key, value in protocol_specific.items():
                    output_lines.append(f"{key}: {value}")

            
            #Payload info
            if packet_details["payload"]["length"] > 0:
                output_lines.append("\nPayload Information:")
                output_lines.append(f"Length: {packet_details['payload']['length']} bytes")


                if packet_details["payload"]["hex"]:
                    output_lines.append("\nHexadecimal dump:")
                    output_lines.append("-"*60)
                    output_lines.append(packet_details["payload"]["hex"])

                
                if packet_details["payload"]["ascii"]:
                    output_lines.append("\nASCII dump:")
                    output_lines.append("-"*60)
                    output_lines.append(packet_details["payload"]["ascii"])

                
                output_lines.append("\nSummary:")
                output_lines.append(summary)
                output_lines.append("="*60)

                #put the output lines into the queue
                if output_queue:
                    output_queue.put('\n'.join(output_lines))


    except Exception as exception:
        print(f"Error with processing packet: {exception}")


def enable_promiscous_mode(interface): #enable promiscuous mode
    try: 
        if os.name == 'posix': #linux 
            subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'],
                check = True, capture_output= True)
            print(f"Enabled promiscuous mode on {interface}")
    
            #verify
            result = subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'],
                    check = True, capture_output= True)
            if 'PROMISC' in result.stdout:
                print("Verified: Promiscous mode is active")
            else: 
                print("Warning: Could not verify promiscuos mode")

        elif os.name == 'nt' : #Windows
            print(f"Promiscuos mode handling is automatic on Windows")
        return True
    
    except subprocess.CalledProcessError as e:
        print(f"Error enabling promiscous mode: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error enabling promiscuos mode: {e}")
        return False


def disable_promiscous_mode(interface): #disable promiscuos mode
    try: 
        if os.name == 'posix': #linux 
            subprocess.run(['ip', 'link', 'set', interface, 'promisc', 'on'],
                check = True, capture_output= True)
            print(f"Disabled promiscuous mode on {interface}")
            return True
    
    except subprocess.CalledProcessError as e:
        print(f"Error disabling promiscous mode: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error disabling promiscuos mode: {e}")
        return False