import socket, uuid, struct, time, threading
from scapy.all import sniff, sendp, Ether, Dot1Q, Raw

print("\n" + "="*60)
print("PHASE 9: The Final Victory (Null Object UUID)")
print("="*60)

TARGET_IP = "192.168.0.61"
TARGET_PORT = 34964
CTRL_IP = "192.168.0.100" 
CTRL_MAC_BYTES = bytes.fromhex("183d2d61f970")
CTRL_MAC_STR = "18:3d:2d:61:f9:70"
TARGET_MAC = "88:01:f9:35:d9:a2"
IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

def build_rpc_header(activity_uuid, seq_num, opnum, payload_len):
    hdr = struct.pack("!BBBB 3s B", 4, 0, 0x20, 0, b'\x10\x00\x00', 0)
    
    # CRITICAL FIX: We MUST use the Null UUID, otherwise it hits the wrong Endpoint Mapper!
    hdr += b'\x00' * 16 
    
    hdr += uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le # PNIO CM Interface
    hdr += activity_uuid.bytes_le                               
    hdr += struct.pack("<I I I H H H H H B B", 0, 1, seq_num, opnum, 0xFFFF, 0xFFFF, payload_len, 0, 0, 0)       
    return hdr

def build_connect_req(ar_uuid, activity_uuid, seq):
    station_name = b"ctrl-pc"
    ar_data = struct.pack("!H", 1) + ar_uuid.bytes + struct.pack("!H", 1) + CTRL_MAC_BYTES + ar_uuid.bytes + struct.pack("!I", 0x00000008) + struct.pack("!H", 100) + socket.inet_aton(CTRL_IP) + struct.pack("!H", len(station_name)) + station_name
    if len(ar_data) % 4 != 0: ar_data += b'\x00' * (4 - (len(ar_data) % 4))
    ar_block = struct.pack("!HHBB", 0x0101, len(ar_data), 1, 0) + ar_data

    def make_iocr(iocr_type, ref, fid, dlen):
        data = struct.pack("!H H H", iocr_type, ref, 0x8892) + struct.pack("!I H H", 0, dlen+2, fid) + struct.pack("!H H H H", 32, 16, 1, 0) + struct.pack("!I H H H I", 0xFFFFFFFF, 3, 0, 0, 0) + struct.pack("!H I", 1, 0) + struct.pack("!H H H H", 1, 1, 1, 0) + struct.pack("!H H H H", 1, 1, 1, dlen)
        return struct.pack("!HHBB", 0x0102, len(data), 1, 0) + data

    icr_block = make_iocr(1, 1, 0x8001, 40)
    ocr_block = make_iocr(2, 2, 0x8002, 4)

    esm_data = struct.pack("!H I", 1, 0) + struct.pack("!H I H", 1, 0x10400000, 0) + struct.pack("!H H I H", 1, 1, 0x10400003, 0) + struct.pack("!H H B B", 1, 40, 1, 1) + struct.pack("!H H B B", 2, 4, 1, 1)        
    esm_block = struct.pack("!HHBB", 0x0104, len(esm_data), 1, 0) + esm_data
    payload = ar_block + icr_block + ocr_block + esm_block

    return build_rpc_header(activity_uuid, seq, 0, len(payload)) + payload

def build_control_req(ar_uuid, activity_uuid, command, seq):
    ctrl_data = ar_uuid.bytes + struct.pack("!H H H H", 1, 0, command, 0)
    ctrl_block = struct.pack("!H H B B", 0x0110, len(ctrl_data)+2, 1, 0) + ctrl_data
    return build_rpc_header(activity_uuid, seq, 4, len(ctrl_block)) + ctrl_block

def cyclic_tx_loop(stop_event):
    cyc = 1
    padding = b"\x00" * 30 
    while not stop_event.is_set():
        cyc = (cyc + 1) % 65536
        pn_payload = struct.pack("!H", 0x8002) + b"\x00\x00\x00\x00" + b"\x80\x80" + padding + struct.pack("!H", cyc) + b"\x35\x00"
        pkt = Ether(dst=TARGET_MAC, src=CTRL_MAC_STR) / Dot1Q(vlan=0, prio=6, type=0x8892) / Raw(load=pn_payload)
        try: sendp(pkt, iface=IFACE, verbose=False)
        except Exception: pass
        time.sleep(0.032)

def decode_tesys_tera(payload):
    if len(payload) < 40: return "Payload too short"
    byte_0, byte_1 = payload[0], payload[1]
    ready = "Yes" if (byte_0 & 0x01) else "No"
    tripped = "Yes" if (byte_0 & 0x08) else "No"
    motor_running = "Yes" if (byte_1 & 0x01) else "No"
    volts = struct.unpack(">I", payload[24:28])[0] * 0.1
    amps = struct.unpack(">I", payload[4:8])[0] * 0.1
    freq = struct.unpack(">H", payload[36:38])[0] * 0.01
    return f"V: {volts:5.1f} | A: {amps:5.1f}% | Hz: {freq:5.2f} | Rdy: {ready} | Trip: {tripped} | Run: {motor_running}"

def check_rpc_response(resp, step_name):
    if len(resp) < 10: return False, "Malformed packet"
    ptype = resp[1]
    if ptype == 0x02: return True, "Accepted"
    elif ptype == 0x06:
        # We now extract the TRUE 4-byte reject code from the absolute end of the packet
        code = struct.unpack("<I", resp[80:84])[0] if len(resp) >= 84 else 0
        reasons = {
            0x1c010017: "nca_unk_if (Object UUID Mismatch - STILL hitting wrong interface)",
            0x1c01000b: "nca_wrong_boot_time (Ghost AR Lock - Unplug device to fix)"
        }
        return False, f"REJECTED. Code: {hex(code)} -> {reasons.get(code, 'Unknown Fault')}"
    elif ptype == 0x03: return False, "FAULT (Device crashed)"
    return False, f"Unknown PTYPE {ptype}"

ar_uuid = uuid.uuid4()
act_uuid = uuid.uuid4() 
stop_tx = threading.Event()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    s.bind((CTRL_IP, 0))
    s.settimeout(3.0)
    
    print(f"1. Sending AR Connect to Null Object...")
    s.sendto(build_connect_req(ar_uuid, act_uuid, 1), (TARGET_IP, TARGET_PORT))
    resp, _ = s.recvfrom(65536)
    success, msg = check_rpc_response(resp, "AR Connect")
    if not success: raise Exception(f"AR Connect Failed: {msg}")
    print(f"   -> {msg}")
    
    print(f"2. Sending PrmEnd...")
    s.sendto(build_control_req(ar_uuid, act_uuid, 2), (TARGET_IP, TARGET_PORT))
    resp, _ = s.recvfrom(65536)
    success, msg = check_rpc_response(resp, "PrmEnd")
    if not success: raise Exception(f"PrmEnd Failed: {msg}")
    print(f"   -> {msg}")
        
    print(f"3. Sending ApplicationReady...")
    s.sendto(build_control_req(ar_uuid, act_uuid, 3), (TARGET_IP, TARGET_PORT))
    resp, _ = s.recvfrom(65536)
    success, msg = check_rpc_response(resp, "ApplicationReady")
    if not success: raise Exception(f"AppReady Failed: {msg}")
    print(f"   -> {msg}")
        
    print("\n[SUCCESS] AR Established! Launching Master TX and capturing live data...")
    tx_thread = threading.Thread(target=cyclic_tx_loop, args=(stop_tx,))
    tx_thread.start()
    
    bpf_filter = f"ether src {TARGET_MAC}"
    captured = sniff(iface=IFACE, filter=bpf_filter, count=15, timeout=4.0)
    
    valid_frames = 0
    print("\n--- LIVE ELECTRICAL DATA ---")
    for frame in captured:
        raw_bytes = bytes(frame)
        offset = 12
        if raw_bytes[12:14] == b"\x81\x00": offset += 4
        
        if raw_bytes[offset:offset+2] == b"\x88\x92":
            fid = struct.unpack(">H", raw_bytes[offset+2 : offset+4])[0]
            if fid == 0x8001:
                payload = raw_bytes[offset+4 : offset+4+40]
                print(f"  Live: {decode_tesys_tera(payload)}")
                # Also print the raw hex just in case the mapping is shifted!
                print(f"  Raw:  {payload.hex()}")
                valid_frames += 1
                if valid_frames >= 5: break
    
    if valid_frames == 0:
        print("[FAIL] Relay unlocked, but no cyclic data captured.")

except Exception as e:
    print(f"\n[ABORT] {e}")
finally:
    stop_tx.set()
    time.sleep(0.1) 
    print("\nSending Clean Release...")
    rel_hdr = build_rpc_header(act_uuid, 4, 1, 0) # OpNum 1 = Release
    s.sendto(rel_hdr, (TARGET_IP, TARGET_PORT))
    s.close()