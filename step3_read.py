import socket, uuid, struct, time, threading
from scapy.all import sniff, sendp, Ether, Raw

print("\n" + "="*60)
print("PHASE 3.5: Master/Slave Cyclic Exchange (Layer 2)")
print("="*60)

TARGET_IP = "192.168.0.61"
TARGET_PORT = 34964
CTRL_IP = "192.168.0.100" 
CTRL_MAC = bytes.fromhex("183d2d61f970")
TARGET_MAC = "88:01:f9:35:d9:a2"

# CRITICAL FIX: Using the raw Windows NPF GUID extracted from your Wireshark dump!
IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

def build_perfect_rpc():
    ar_uuid = uuid.uuid4()
    activity_uuid = uuid.uuid4() 
    
    # PROFINET PAYLOAD
    station_name = b"ctrl-pc"
    ar_data = struct.pack("!H", 1) + ar_uuid.bytes + struct.pack("!H", 1) + CTRL_MAC + ar_uuid.bytes + struct.pack("!I", 0x00000008) + struct.pack("!H", 100) + socket.inet_aton(CTRL_IP) + struct.pack("!H", len(station_name)) + station_name
    if len(ar_data) % 4 != 0: ar_data += b'\x00' * (4 - (len(ar_data) % 4))
    ar_block = struct.pack("!HHBB", 0x0101, len(ar_data), 1, 0) + ar_data

    def make_iocr(iocr_type, ref, fid, dlen):
        data = struct.pack("!H H H", iocr_type, ref, 0x8892) + struct.pack("!I H H", 0, dlen, fid) + struct.pack("!H H H H", 32, 16, 1, 0) + struct.pack("!I H H H I", 0xFFFFFFFF, 3, 0, 0, 0) + struct.pack("!H I", 1, 0) + struct.pack("!H H H H", 1, 1, 1, 0) + struct.pack("!H H H H", 1, 1, 1, dlen)
        return struct.pack("!HHBB", 0x0102, len(data), 1, 0) + data

    icr_block = make_iocr(1, 1, 0x8001, 40)
    ocr_block = make_iocr(2, 2, 0x8002, 4)

    esm_data = struct.pack("!H I", 1, 0) + struct.pack("!H I H", 1, 0x10400000, 0) + struct.pack("!H H I H", 1, 1, 0x10400003, 0) + struct.pack("!H H B B", 1, 40, 1, 1) + struct.pack("!H H B B", 2, 4, 1, 1)        
    esm_block = struct.pack("!HHBB", 0x0104, len(esm_data), 1, 0) + esm_data
    payload = ar_block + icr_block + ocr_block + esm_block

    # DCE/RPC HEADER (LITTLE ENDIAN)
    rpc_hdr = struct.pack("!BBBB 3s B", 4, 0, 0x20, 0, b'\x10\x00\x00', 0)
    rpc_hdr += uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le 
    rpc_hdr += uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le 
    rpc_hdr += activity_uuid.bytes_le                               
    rpc_hdr += struct.pack("<I I I H H H H H B B", 0, 1, 1, 0, 0xFFFF, 0xFFFF, len(payload), 0, 0, 0)       
    return rpc_hdr + payload, ar_uuid, activity_uuid

# --- BACKGROUND CYCLIC SENDER ---
def cyclic_tx_loop(stop_event):
    cyc = 1
    while not stop_event.is_set():
        cyc = (cyc + 1) % 65536
        # PROFINET Payload: FrameID (0x8002) + 4 bytes out data (all 0) + IOPS (0x80)
        pn_data = struct.pack("!H", 0x8002) + b"\x00\x00\x00\x00" + b"\x80"
        # PROFINET Trailer: Cycle Counter + DataStatus (0x25 = Operate) + TransferStatus (0)
        pn_trail = struct.pack("!H B B", cyc, 0x25, 0x00)
        pkt = Ether(dst=TARGET_MAC, src=CTRL_MAC, type=0x8892) / Raw(load=pn_data + pn_trail)
        
        try:
            sendp(pkt, iface=IFACE, verbose=False)
        except Exception:
            pass
        time.sleep(0.032) # Send every 32ms

packet, ar_uuid, act_uuid = build_perfect_rpc()
stop_tx = threading.Event()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    print(f"Binding UDP socket explicitly to {CTRL_IP} ...")
    s.bind((CTRL_IP, 0))
    s.settimeout(3.0)
    
    print(f"Sending AR Request to {TARGET_IP} ...")
    s.sendto(packet, (TARGET_IP, TARGET_PORT))
    resp, addr = s.recvfrom(65536)
    
    if len(resp) > 80 and struct.unpack("<H", resp[68:70])[0] == 0:
        print("[SUCCESS] AR Established!\n")
        
        # 1. Start blasting the master cyclic frames to wake the relay up
        print("Starting Master Cyclic TX Thread...")
        tx_thread = threading.Thread(target=cyclic_tx_loop, args=(stop_tx,))
        tx_thread.start()
        
        # 2. Sniff for the relay's response (Relaxed filter to ignore VLAN tags)
        print("Listening for TeSys Tera cyclic responses...")
        bpf_filter = f"ether src {TARGET_MAC}"
        
        # We listen for 5 seconds or until we catch 5 frames
        captured = sniff(iface=IFACE, filter=bpf_filter, count=5, timeout=5.0)
        
        if len(captured) > 0:
            print(f"\n[SUCCESS] Caught {len(captured)} live frames from the relay!")
            for i, frame in enumerate(captured):
                raw_bytes = bytes(frame)
                
                # Strip Ethernet/VLAN headers to find the actual PROFINET payload
                pn_start = 14
                if raw_bytes[12:14] == b"\x81\x00":  # If it has a VLAN tag, skip 4 bytes
                    pn_start += 4
                
                # TeSys Tera Module 1 sends 40 bytes of input data
                payload_hex = raw_bytes[pn_start+2 : pn_start+2+40].hex()
                print(f"  Frame {i+1} Raw 40-byte Payload: {payload_hex}")
        else:
            print("\n[FAIL] Scapy sniffed on the NPF GUID but caught nothing. Firewalls might be blocking Scapy's listener.")
            
    else:
        print("\n[FAIL] Handshake rejected or malformed.")

finally:
    stop_tx.set()
    time.sleep(0.1) # Let the TX thread exit cleanly
    print("\nSending Clean RPC Release...")
    rel_hdr = struct.pack("!BBBB 3s B", 4, 1, 0x20, 0, b'\x10\x00\x00', 0)
    rel_hdr += uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le 
    rel_hdr += uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le 
    rel_hdr += act_uuid.bytes_le 
    rel_hdr += struct.pack("<I I I H H H H H B B", 0, 1, 1, 0, 0xFFFF, 0xFFFF, 0, 0, 0, 0)
    s.sendto(rel_hdr, (TARGET_IP, TARGET_PORT))
    s.close()