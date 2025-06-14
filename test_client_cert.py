#!/usr/bin/env python3
"""
Test script to demonstrate client certificate verification
This script shows how to use the client certificate to avoid SSL warnings
"""

import requests
import subprocess
import time
import threading
import os
import sys

def start_server():
    """Start the HTTPS server with client certificate generation"""
    try:
        # Generate certificates and start server
        subprocess.run([
            sys.executable, "-m", "https.server", 
            "--save-cert", "--client-cert", "8443"
        ], check=True, timeout=5)
    except subprocess.TimeoutExpired:
        # Server started successfully (timeout expected for server)
        pass
    except Exception as e:
        print(f"Error starting server: {e}")

def test_client_verification():
    """Test client certificate verification"""
    print("Testing client certificate verification...")
    
    # Wait a moment for server to start
    time.sleep(2)
    
    try:
        # Test with client certificate (should work without warnings)
        print("\n1. Testing with client certificate (secure):")
        if os.path.exists("client-cert.pem"):
            response = requests.get('https://localhost:8443', verify='client-cert.pem', timeout=5)
            print(f"   Status: {response.status_code}")
            print("   ✓ SSL verification successful with client certificate!")
        else:
            print("   ✗ client-cert.pem not found")
        
        # Test without verification (insecure, for comparison)
        print("\n2. Testing without verification (insecure):")
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.get('https://localhost:8443', verify=False, timeout=5)
        print(f"   Status: {response.status_code}")
        print("   ⚠ SSL verification disabled (insecure)")
        
    except requests.exceptions.RequestException as e:
        print(f"   Request failed: {e}")
    except Exception as e:
        print(f"   Error: {e}")

if __name__ == "__main__":
    print("HTTPS Server Client Certificate Test")
    print("=" * 40)
    
    # Start server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Test client verification
    test_client_verification()
    
    print("\nTest completed. Check for client-cert.pem and cert.pem files.")
    print("You can now use 'client-cert.pem' for SSL verification in your applications.")