"""
Test script to trigger specific detections in the Lesh agent.
This provides a more targeted test than the general simulation script.
"""

import socket
import time
import os
import random
import sys

def test_port_scanning():
    """Create activity that resembles port scanning."""
    print("Testing port scanning detection...")
    
    # Scan a range of ports on localhost
    target = "127.0.0.1"
    start_port = 1
    end_port = 100
    
    print(f"Scanning {end_port - start_port + 1} ports on {target}...")
    
    # Open connections to many ports in rapid succession
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"Port {port} open")
            sock.close()
        except:
            pass
        
        # Don't scan too fast or we might crash
        time.sleep(0.01)
    
    print("Port scanning test completed")

def test_suspicious_file():
    """Create a suspicious file that should trigger detection."""
    print("Testing suspicious file detection...")
    
    # Create a file with suspicious name and content
    filename = "suspicious_payload.bin"
    
    with open(filename, "wb") as f:
        # Generate 1KB of random data
        data = bytearray(random.getrandbits(8) for _ in range(1024))
        f.write(data)
    
    print(f"Created suspicious file: {filename}")
    
    # Keep the file around for a bit so the scanner can detect it
    print("Waiting for file to be detected...")
    time.sleep(5)
    
    # Clean up
    if os.path.exists(filename):
        os.remove(filename)
    
    print("Suspicious file test completed")

def test_known_bad_ip():
    """Attempt to connect to known bad IPs from the detection module."""
    print("Testing connection to known bad IPs...")
    
    # List must match IPs in the detector
    bad_ips = ["192.168.1.100", "10.0.0.99", "172.16.0.200"]
    
    for ip in bad_ips:
        print(f"Attempting connection to {ip}...")
        try:
            # Just try to connect, will likely fail but detection should see the attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect_ex((ip, 80))
            sock.close()
        except:
            pass
    
    print("Known bad IP test completed")

def main():
    """Run all tests."""
    print("=== LESH AGENT DETECTION TEST ===")
    
    # Run tests
    test_port_scanning()
    print()
    
    test_suspicious_file()  
    print()
    
    test_known_bad_ip()
    print()
    
    print("All tests completed. Check the Lesh agent for detections.")
    print("Wait a few seconds and run a scan in the agent.")

if __name__ == "__main__":
    main()
