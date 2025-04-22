"""
Comprehensive test script for validating Lesh agent functionality.
"""
import subprocess
import time
import socket
import os
import random
import sys
import threading

def print_header(text):
    """Print a section header."""
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def run_port_scan_test():
    """Test port scanning detection."""
    print_header("PORT SCANNING TEST")
    print("Testing rapid connections to multiple ports...")
    
    # Establish connections to many ports in quick succession
    for port in range(1000, 1050):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex(('127.0.0.1', port))
            sock.close()
        except:
            pass
            
    print("Port scan test completed")

def create_suspicious_file_test():
    """Create suspicious looking files."""
    print_header("SUSPICIOUS FILE TEST")
    
    suspicious_files = [
        "suspicious_payload.bin",
        "malware_sample.exe",
        "ransomware.dat"
    ]
    
    for filename in suspicious_files:
        print(f"Creating suspicious file: {filename}")
        with open(filename, "wb") as f:
            # Create random binary data
            data = bytearray(random.getrandbits(8) for _ in range(2048))
            f.write(data)
            
        # Let it exist for a moment to be detected
        time.sleep(1)
        
        # Remove file
        if os.path.exists(filename):
            os.remove(filename)
            
    print("Suspicious file test completed")

def simulate_brute_force():
    """Simulate a brute force login attempt."""
    print_header("BRUTE FORCE ATTACK TEST")
    
    target_port = 22  # SSH port
    attempts = 20
    
    print(f"Simulating {attempts} rapid connection attempts to port {target_port}...")
    
    for i in range(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex(('127.0.0.1', target_port))
            sock.close()
            time.sleep(0.1)  # Very short delay between attempts
        except:
            pass
    
    print("Brute force test completed")

def attempt_connections_to_known_bad_ips():
    """Test connections to IPs known to be suspicious."""
    print_header("BAD IP CONNECTION TEST")
    
    suspicious_ips = ["192.168.1.100", "10.0.0.99", "172.16.0.200"]
    
    for ip in suspicious_ips:
        print(f"Attempting connection to suspicious IP: {ip}")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect_ex((ip, 80))
            sock.close()
        except:
            pass
    
    print("Bad IP connection test completed")
    
def test_high_cpu_load():
    """Generate high CPU load to test system anomaly detection."""
    print_header("SYSTEM LOAD TEST")
    print("Generating high CPU load for 5 seconds...")
    
    # Function to consume CPU
    def cpu_load():
        end_time = time.time() + 5  # Run for 5 seconds
        while time.time() < end_time:
            _ = [i*i for i in range(10000)]
    
    # Create multiple threads to increase load
    threads = []
    for _ in range(os.cpu_count()):
        t = threading.Thread(target=cpu_load)
        threads.append(t)
        t.start()
        
    # Wait for threads to complete
    for t in threads:
        t.join()
    
    print("System load test completed")

def run_all_tests():
    """Run all test functions."""
    print_header("STARTING COMPREHENSIVE LESH AGENT TEST")
    print("This script will simulate various malicious activities.")
    print("Ensure the Lesh agent is running before continuing.")
    
    input("Press Enter to start the tests...")
    
    # Run all tests
    run_port_scan_test()
    time.sleep(2)
    
    create_suspicious_file_test()
    time.sleep(2)
    
    simulate_brute_force()
    time.sleep(2)
    
    attempt_connections_to_known_bad_ips()
    time.sleep(2)
    
    test_high_cpu_load()
    
    print_header("ALL TESTS COMPLETED")
    print("Check the Lesh agent to see if any threats were detected.")
    print("Recommended: Run 'scan' command in the Lesh interactive shell")

if __name__ == "__main__":
    run_all_tests()
