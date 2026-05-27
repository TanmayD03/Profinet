import socket, struct, time
from scapy.all import sniff, sendp, Ether, Raw

print("\n" + "="*60)
print("PHASE 12: The DCP Interrogator (Layer 2 Discovery)")
print("="*60)

CTRL_MAC_STR = "18:3d:2d:61:f9:70"
IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"
DCP_MULTICAST = "01:0e:cf:00:00:00"

# Construct a pure PROFINET DCP Identify Request
dcp_req = Ether(dst=DCP_MULTICAST, src=CTRL_MAC_STR, type=0x8892)

# FrameID(0xFEFE), Service(5=Identify), Type(0=Req), XID(0x11223344), Delay(1), DataLen(4)
payload = struct.pack(">H B B I H H", 0xFEFE, 5, 0, 0x11223344, 1, 4)

# BlockHeader: Option(255=All), Suboption(255=All), Length(0)
payload += struct.pack(">B B H", 255, 255, 0)
pkt = dcp_req / Raw(load=payload)

print("Broadcasting PROFINET DCP Identify Request...")
sendp(pkt, iface=IFACE, verbose=False)

print("Listening for DCP Responses from the TeSys Tera...")
captured = sniff(iface=IFACE, filter="ether proto 0x8892", count=5, timeout=4.0)

found = False
for frame in captured:
    raw_bytes = bytes(frame)
    offset = 12
    if raw_bytes[12:14] == b"\x81\x00": # Handle VLAN priority tags if present
        offset += 4
    
    if raw_bytes[offset:offset+2] == b"\x88\x92":
        fid = struct.unpack(">H", raw_bytes[offset+2:offset+4])[0]
        
        if fid == 0xFEFF: # 0xFEFF is the official DCP Identify Response
            found = True
            mac = ":".join(f"{b:02x}" for b in raw_bytes[6:12])
            print(f"\n[SUCCESS] Device Responded! MAC: {mac}")
            
            # Extract and Parse the DCP Data Blocks
            idx = offset + 14 
            while idx + 4 <= len(raw_bytes):
                opt = raw_bytes[idx]
                subopt = raw_bytes[idx+1]
                length = struct.unpack(">H", raw_bytes[idx+2:idx+4])[0]
                idx += 4
                
                # Protect against malformed blocks
                if idx + length > len(raw_bytes): break 
                data = raw_bytes[idx:idx+length]
                
                if opt == 1 and subopt == 2: # IP Address Block
                    ip = ".".join(str(b) for b in data[2:6])
                    print(f"  -> Configured IP: {ip}")
                elif opt == 2 and subopt == 2: # Device Name Block
                    name = data[2:].decode('ascii', errors='ignore').strip('\x00')
                    print(f"  -> Station Name:  '{name}'")
                elif opt == 2 and subopt == 1: # Device ID Block
                    vendor = data[2:4].hex()
                    dev_id = data[4:6].hex()
                    print(f"  -> Vendor ID:     {vendor} | Device ID: {dev_id}")
                    
                # DCP blocks are always padded to 16-bit boundaries
                idx += length + (length % 2) 

if not found:
    print("\n[FAIL] No response. Windows might be blocking Layer 2 Multicast.")