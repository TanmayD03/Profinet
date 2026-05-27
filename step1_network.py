import os, time, struct, socket
from scapy.all import *

# --- HARDCODED TEST PARAMETERS ---
IFACE = "Realtek PCIe GbE Family Controller"
TARGET_IP = "192.168.000.061"
TARGET_MAC = "88:01:F9:35:D9:A2"  # Converted from your decimal format
PN_ETYPE = 0x8892

def print_hdr(msg):
    print(f"\n{'='*60}\n{msg}\n{'='*60}")

def test_1_windows_ping():
    print_hdr("TEST 1: Standard Windows ICMP Ping (Layer 3)")
    print(f"Pinging {TARGET_IP}...")
    response = os.system(f"ping -n 1 -w 2000 {TARGET_IP} > nul")
    if response == 0:
        print("[SUCCESS] Windows can route to the IP address.")
        return True
    else:
        print("[FAIL] Windows ping timed out. Check PC IP settings (must be 192.168.0.x).")
        return False

def test_2_scapy_arp():
    print_hdr("TEST 2: Scapy ARP Ping (Layer 2.5)")
    print(f"Sending ARP request for {TARGET_IP} on {IFACE}...")
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=TARGET_IP), 
                         iface=IFACE, timeout=2, verbose=False)
        if ans:
            recv_mac = ans[0][1].hwsrc
            print(f"[SUCCESS] ARP Reply received! MAC Address is: {recv_mac}")
            if recv_mac.lower() == TARGET_MAC.lower():
                print("          -> MAC matches expected TeSys Tera MAC.")
            return True
        else:
            print("[FAIL] No ARP reply. Scapy cannot reach the device at Layer 2.")
            return False
    except Exception as e:
        print(f"[ERROR] Scapy failed to bind to adapter: {e}")
        return False

def test_3_unicast_dcp():
    print_hdr("TEST 3: Targeted Unicast PROFINET DCP (Layer 2)")
    print(f"Sending DCP Identify directly to {TARGET_MAC}...")
    
    # Build minimal DCP Identify Request (borrowed from main script)
    dcp_req = struct.pack("!HBBIHH", 0xFEFE, 0x05, 0x00, 1, 0, 4) + b"\xff\xff\x00\x00"
    
    try:
        # We send to the specific MAC, not the multicast MAC
        pkt = Ether(dst=TARGET_MAC, type=PN_ETYPE) / Raw(load=dcp_req)
        
        # Send and wait for 1 response
        ans, unans = srp(pkt, iface=IFACE, timeout=3, verbose=False, multi=False)
        
        if ans:
            resp_bytes = bytes(ans[0][1])
            print(f"[SUCCESS] TeSys Tera responded to PROFINET DCP!")
            print(f"          Raw bytes received: {resp_bytes[:20].hex()}...")
            return True
        else:
            print("[FAIL] No DCP response. Multicast is bypassed, so the device is ignoring the PN packet.")
            return False
    except Exception as e:
        print(f"[ERROR] Scapy injection failed: {e}")
        return False

if __name__ == "__main__":
    print("Starting Step 1 Diagnostics...\n")
    t1 = test_1_windows_ping()
    time.sleep(1)
    t2 = test_2_scapy_arp()
    time.sleep(1)
    t3 = test_3_unicast_dcp()
    
    print_hdr("DIAGNOSTIC SUMMARY")
    print(f"Test 1 (IP Routing):   {'PASS' if t1 else 'FAIL'}")
    print(f"Test 2 (Scapy ARP):    {'PASS' if t2 else 'FAIL'}")
    print(f"Test 3 (PN Unicast):   {'PASS' if t3 else 'FAIL'}")
    
    if t1 and t2 and t3:
        print("\nCONCLUSION: Network and Scapy are perfect. The main script failure is likely due to strict multicast blocking.")
    elif t1 and not t2:
        print("\nCONCLUSION: Windows can see the relay, but Scapy cannot bind to the adapter correctly.")
    elif t2 and not t3:
        print("\nCONCLUSION: Scapy works, but the relay is rejecting PROFINET DCP packets. Check relay configuration.")