import socket, uuid, struct

print("\n" + "="*60)
print("PHASE 2.5: The Endian-Corrected RPC Handshake")
print("="*60)

TARGET_IP = "192.168.0.61"
TARGET_PORT = 34964
CTRL_IP = "192.168.0.100"  # We will explicitly bind to this!
CTRL_MAC = bytes.fromhex("183d2d61f970")

def build_perfect_rpc():
    ar_uuid = uuid.uuid4()
    
    # ---------------------------------------------------------
    # 1. PROFINET PAYLOAD (Strictly BIG-ENDIAN '!')
    # ---------------------------------------------------------
    station_name = b"ctrl-pc"
    ar_data = struct.pack("!H", 1)              
    ar_data += ar_uuid.bytes                    
    ar_data += struct.pack("!H", 1)             
    ar_data += CTRL_MAC                         
    ar_data += ar_uuid.bytes                    
    ar_data += struct.pack("!I", 0x00000008)    
    ar_data += struct.pack("!H", 100)           
    ar_data += socket.inet_aton(CTRL_IP)        
    ar_data += struct.pack("!H", len(station_name)) + station_name
    
    if len(ar_data) % 4 != 0:                   
        ar_data += b'\x00' * (4 - (len(ar_data) % 4))
    ar_block = struct.pack("!HHBB", 0x0101, len(ar_data), 1, 0) + ar_data

    def make_iocr(iocr_type, ref, fid, dlen):
        data = struct.pack("!H H H", iocr_type, ref, 0x8892)
        data += struct.pack("!I H H", 0, dlen, fid)
        data += struct.pack("!H H H H", 32, 16, 1, 0) 
        data += struct.pack("!I H H H I", 0xFFFFFFFF, 3, 0, 0, 0)
        data += struct.pack("!H I", 1, 0)             
        data += struct.pack("!H H H H", 1, 1, 1, 0)   
        data += struct.pack("!H H H H", 1, 1, 1, dlen)
        return struct.pack("!HHBB", 0x0102, len(data), 1, 0) + data

    icr_block = make_iocr(1, 1, 0x8001, 40)
    ocr_block = make_iocr(2, 2, 0x8002, 4)

    esm_data = struct.pack("!H I", 1, 0)                   
    esm_data += struct.pack("!H I H", 1, 0x10400000, 0)    
    esm_data += struct.pack("!H H I H", 1, 1, 0x10400003, 0)
    esm_data += struct.pack("!H H B B", 1, 40, 1, 1)       
    esm_data += struct.pack("!H H B B", 2, 4, 1, 1)        
    esm_block = struct.pack("!HHBB", 0x0104, len(esm_data), 1, 0) + esm_data

    payload = ar_block + icr_block + ocr_block + esm_block

    # ---------------------------------------------------------
    # 2. DCE/RPC HEADER (Strictly LITTLE-ENDIAN '<')
    # ---------------------------------------------------------
    # Data Rep: 0x10 = Little Endian Ints, Char ASCII, IEEE Float
    rpc_hdr = struct.pack("!BBBB 3s B", 4, 0, 0x20, 0, b'\x10\x00\x00', 0)
    
    # UUIDs must be transmitted with Little-Endian byte order for first 3 chunks
    rpc_hdr += uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le 
    rpc_hdr += uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le 
    
    activity_uuid = uuid.uuid4()
    rpc_hdr += activity_uuid.bytes_le                               
    
    # Packed using '<' for Little-Endian!
    rpc_hdr += struct.pack("<I I I H H H H H B B",
        0, 1, 1, 0, 0xFFFF, 0xFFFF, len(payload), 0, 0, 0)       
    
    return rpc_hdr + payload, ar_uuid

packet, ar_uuid = build_perfect_rpc()

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # CRITICAL FIX: Force Windows to use the correct Ethernet adapter IP!
    print(f"Binding UDP socket explicitly to {CTRL_IP} ...")
    s.bind((CTRL_IP, 0))
    
    s.settimeout(3.0)
    print(f"Sending 80-byte RPC Header + AR Payload to {TARGET_IP}:{TARGET_PORT} ...")
    s.sendto(packet, (TARGET_IP, TARGET_PORT))
    
    resp, addr = s.recvfrom(65536)
    print(f"\n[SUCCESS] Response received! Length: {len(resp)} bytes.")
    
    if len(resp) > 80:
        # RPC responses are also little-endian
        status = struct.unpack("<H", resp[68:70])[0]
        if status == 0:
            print("          -> Handshake ACCEPTED! Application Relation (AR) is established.")
        else:
            print(f"          -> Device Rejected the config (Status code: {status}). But communication WORKS.")
            
    # Clean release
    rel_hdr = struct.pack("!BBBB 3s B", 4, 1, 0x20, 0, b'\x10\x00\x00', 0)
    rel_hdr += uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le 
    rel_hdr += uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le 
    rel_hdr += activity_uuid.bytes_le 
    rel_hdr += struct.pack("<I I I H H H H H B B", 0, 1, 1, 0, 0xFFFF, 0xFFFF, 0, 0, 0, 0)
    s.sendto(rel_hdr, (TARGET_IP, TARGET_PORT))
    
except socket.timeout:
    print("\n[FAIL] RPC Request timed out. Check Wireshark to ensure the Src IP is now 192.168.0.100.")
except Exception as e:
    print(f"\n[ERROR] Network error: {e}")