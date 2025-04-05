#!/usr/bin/env python3

import os
import sys
from scapy.all import IP, TCP  # Ensure Scapy imports are here
from PacketCapture import PacketCapture
from TrafficAnalyzer import TrafficAnalyzer
from DetectionEngine import DetectionEngine
from AlertSystem import AlertSystem

def check_root():
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for packet capture.")
        print("Please run with: sudo python3 main.py")
        sys.exit(1)

def get_network_interface():
    for interface in ["eth0", "wlan0", "tun0"]:
        if os.path.exists(f"/sys/class/net/{interface}"):
            return interface
    return "eth0"  # fallback

def main():
    check_root()
    print("Starting IDS on Kali Linux...")
    
    interface = get_network_interface()
    print(f"Using network interface: {interface}")
    
    # Initialize components
    packet_capture = PacketCapture()
    traffic_analyzer = TrafficAnalyzer()
    detection_engine = DetectionEngine()
    alert_system = AlertSystem()

    # Start packet capture
    packet_capture.start_capture(interface=interface)

    try:
        print("IDS running. Press Ctrl+C to stop...")
        while True:
            if not packet_capture.packet_queue.empty():
                packet = packet_capture.packet_queue.get()
                features = traffic_analyzer.analyze_packet(packet)
                
                if features:  # Only process if features were extracted
                    threats = detection_engine.detect_threats(features)
                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst
                        }
                        alert_system.generate_alert(threat, packet_info)
                        print(f"Alert: {threat['type']} from {packet_info['source_ip']}")

    except KeyboardInterrupt:
        packet_capture.stop()
        print("\nIDS stopped successfully.")

if __name__ == "__main__":
    main()