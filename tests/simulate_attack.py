"""
Script to simulate malicious behavior for testing the Lesh security agent.
This script performs activities that might be flagged as suspicious,
such as port scanning, suspicious file operations, and unusual network activity.

WARNING: This is for testing purposes only within a controlled environment.
"""

import socket
import random
import time
import os
import sys
import subprocess
import threading

def simulate_port_scan(target_ip='127.0.0.1', ports_to_scan=20):
    """Simulate a basic port scan on localhost."""
    print(f"[*] Simulating port scan on {target_ip}...")
    
    # Random selection of ports to make it look suspicious
    ports = random.sample(range(1, 10000), ports_to_scan)
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Port {port} is open")
        sock.close()
        
    print(f"[*] Port scan complete: {ports_to_scan} ports scanned")
    return True

def simulate_suspicious_file_operations():
    """Simulate suspicious file operations."""
    print("[*] Simulating suspicious file operations...")
    
    try:
        # Create a suspicious-looking file
        with open("suspicious_payload.bin", "wb") as f:
            # Generate some random binary content
            random_bytes = bytearray(random.getrandbits(8) for _ in range(1024))
            f.write(random_bytes)
        
        # Try to make it executable (will be detected on some systems)
        try:
            os.chmod("suspicious_payload.bin", 0o755)
        except:
            pass
            
        # Delete the file quickly after creation (suspicious pattern)
        time.sleep(1)
        os.remove("suspicious_payload.bin")
        
        print("[+] File operations complete")
        return True
        
    except Exception as e:
        print(f"[!] Error in file operations: {e}")
        return False

def simulate_unusual_network_traffic(packets=50):
    """Simulate unusual network traffic patterns."""
    print("[*] Simulating unusual network traffic...")
    
    try:
        # Random destination IPs that look suspicious
        destinations = [
            "192.168.1.100", 
            "10.0.0.99",
            "172.16.0.200"
        ]
        
        # Randomly pick a destination
        target_ip = random.choice(destinations)
        
        # Create a socket for raw traffic
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Send random packets
        for i in range(packets):
            # Generate random data that looks like a payload
            data = bytearray(random.getrandbits(8) for _ in range(64))
            
            # Random target port
            port = random.randint(1, 65535)
            
            try:
                sock.sendto(data, (target_ip, port))
            except:
                # IP might not be reachable, just continue
                pass
                
            time.sleep(0.05)
        
        sock.close()
        print(f"[+] Sent {packets} unusual packets")
        return True
        
    except Exception as e:
        print(f"[!] Error in network traffic simulation: {e}")
        return False

def simulate_brute_force(target_ip='127.0.0.1', port=22, attempts=10):
    """Simulate a basic brute force login attempt."""
    print(f"[*] Simulating brute force attempt to {target_ip}:{port}...")
    
    try:
        for i in range(attempts):
            # Try to connect rapidly (suspicious pattern)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                # Send some gibberish that looks like auth attempts
                auth_attempt = f"USER admin\nPASS {random.randint(100000, 999999)}\n"
                try:
                    sock.send(auth_attempt.encode())
                    time.sleep(0.1)
                    sock.recv(1024)
                except:
                    pass
            
            sock.close()
            
        print(f"[+] Completed {attempts} brute force attempts")
        return True
        
    except Exception as e:
        print(f"[!] Error in brute force simulation: {e}")
        return False

def run_attack_simulation():
    """Run all attack simulations in sequence."""
    print("\n==== STARTING ATTACK SIMULATION ====")
    print("WARNING: This is a test script for the Lesh security agent.")
    print("         No actual malicious activity is performed.\n")
    
    # Run the simulations
    simulate_port_scan()
    time.sleep(1)
    
    simulate_suspicious_file_operations()
    time.sleep(1)
    
    simulate_unusual_network_traffic()
    time.sleep(1)
    
    simulate_brute_force()
    
    print("\n==== ATTACK SIMULATION COMPLETE ====")
    print("Check the Lesh agent to see if threats were detected.")

if __name__ == "__main__":
    run_attack_simulation()
