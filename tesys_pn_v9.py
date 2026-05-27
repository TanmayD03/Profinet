#!/usr/bin/env python3
"""
PROFINET IO Controller — TeSys Tera Motor Management Relay  [v9]
===========================================================
Transport: Scapy raw Ethernet for EVERYTHING (DCE/RPC + cyclic RT frames).
This bypasses the Windows networking stack, firewall, and routing table
completely — which is why the UDP socket approach gets a timeout even
when the packet structure is perfectly correct.

Protocol sequence (all DCE/RPC v4, UDP port 34964, raw Ethernet):
  seq=0  IODConnectReq    (opnum 0) → ConnectRes
  seq=1  IODControlReq    (opnum 2, ControlCommand=0x0008 PrmEnd) → ControlRes
  seq=2  IODControlReq    (opnum 2, ControlCommand=0x0010 AppReady) → ControlRes
  seq≥3  IODReadReq/Res   (opnum 3) — acyclic reads
  seq≥3  IODWriteReq/Res  (opnum 4) — acyclic writes
  RT     Cyclic output frames (Scapy raw, 32ms period)
  RT     Cyclic input  frames (Scapy sniff)

Hardware (from DCP discovery):
  Target     : 192.168.0.61    88:01:f9:35:d9:a2   tesys-tera-pn
  Controller : 192.168.0.100   18:3d:2d:61:f9:70
  Module 1   : 40 B input (device→ctrl), 4 B output (ctrl→device)

v5 — Three root-cause fixes for the "TIMEOUT — no response to Connect" error:

  FIX 1  ICMP Port Unreachable poisoning  ← most likely cause of the timeout
    When Scapy injects a raw UDP frame the device sends its DCE/RPC response
    back to CONTROLLER_IP:34964.  Because no OS process owns that UDP port,
    Windows immediately sends ICMP "Port Unreachable" back to the device.
    TeSys Tera interprets that as the controller going offline and silently
    aborts the AR — which looks like a pure timeout on our end.
    Fix: ScapyTransport now binds a dummy UDP socket on port 34964 so that
    Windows never generates the ICMP.  (We still receive via raw sniffer.)

  FIX 2  Npcap sniffer startup race condition
    Npcap on Windows takes up to 150–200 ms to attach a BPF filter to the
    adapter driver.  The previous 50 ms delay meant the device's response
    could arrive before the sniffer was armed and be silently lost.
    Fix: startup delay raised to 200 ms.

  FIX 3  No Layer-2 connectivity check before DCE/RPC
    A DCP Identify probe (pure EtherType 0x8892, no IP) now runs before any
    DCE/RPC.  If the device doesn't answer DCP, the problem is the NIC /
    cable selection — not the protocol — and the script aborts early with a
    clear message.  list_interfaces() is also printed at startup to make it
    easy to identify the correct SCAPY_IFACE GUID.

Before running:
  1. Power-cycle TeSys Tera (10 s off) to clear any ghost AR lock
  2. Confirm ipconfig shows 192.168.0.100 on the correct NIC
  3. Update SCAPY_IFACE below to match your NPF GUID:
       python -c "from scapy.all import get_if_list; print(get_if_list())"
     OR just run the script — list_interfaces() now prints a table at startup.
  4. Run as Administrator (Npcap/WinPcap requires elevated privileges)
  5. Install scapy:  pip install scapy
"""

# ── stdlib ───────────────────────────────────────────────────────────────────
import queue
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional

# ── scapy ────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        AsyncSniffer, Ether, IP, UDP, ICMP, ARP, Dot1Q, Raw,
        sendp, get_if_hwaddr, conf as scapy_conf
    )
    scapy_conf.verb = 0          # suppress scapy noise
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-5s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("PNIO")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# USER CONFIGURATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET_IP          = "192.168.0.61"
TARGET_MAC         = "88:01:f9:35:d9:a2"
CONTROLLER_IP      = "192.168.0.100"
CONTROLLER_MAC     = "18:3d:2d:61:f9:70"
# IMPORTANT: CMInitiatorStationName in ARBlock is the CONTROLLER name,
# not the device's NameOfStation.
CONTROLLER_STATION_NAME = "ctrl-pc"
INPUT_LEN          = 40        # process input bytes (device → controller)
OUTPUT_LEN         = 4         # process output bytes (controller → device)
CYCLIC_DURATION_S  = 60.0

# Set True to skip the DCP Identify pre-flight and go straight to AR Connect.
# Useful if the device is connected and responding but doesn't answer DCP
# (e.g. it already holds an AR with another controller).
SKIP_DCP_PREFLIGHT = False

# Windows NPF adapter GUID.  Find yours with:
#   python -c "from scapy.all import get_if_list; print(get_if_list())"
SCAPY_IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROTOCOL CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PNIO_UDP_PORT   = 34964
EPM_TCP_PORT    = 135
PROFINET_ETYPE  = 0x8892

# Object UUID of the device's Context Manager endpoint (Anybus/HMS stack)
PNIO_CM_OBJ_UUID  = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
# Interface UUID — fixed by PROFINET standard
PNIO_CM_IF_UUID   = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
# Controller's own Object UUID — placed in ARBlock.CMInitiatorObjectUUID
PNIO_CTRL_OBJ_UUID = uuid.UUID("dea00002-6c97-11d1-8271-00a02442df7d")
# Commander reference capture (known-good) constants
PNIO_CMD_OBJ_UUID      = uuid.UUID("dea00000-6c97-11d1-8271-000107010129")
PNIO_CMD_CTRL_OBJ_UUID = uuid.UUID("0000a0de-976c-d111-8271-00640008002a")
CMD_AR_PROPS           = 0x60000011
CMD_TIMEOUT_F          = 0x00C8
CMD_CM_UDP_PORT        = 0x8892
CMD_IOCR_PROPS         = 0x00000002
CMD_SCF                = 128
CMD_RR                 = 8
CMD_WDF                = 3
CMD_DHF                = 3
CMD_FRAME_ID_IN        = 0xBBF0
CMD_FRAME_ID_OUT       = 0xFFFF
EPM_IF_UUID       = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
NDR_SYNTAX_UUID   = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

# DCE/RPC v4 CL-PDU packet types  (byte 1 of 80-byte header)
PKT_REQUEST  = 0x00
PKT_RESPONSE = 0x02
PKT_FAULT    = 0x03

# PFC flags  (byte 2)
PFC_FIRST    = 0x01
PFC_LAST     = 0x02
PFC_OBJ_UUID = 0x80   # Object UUID field is present and valid

# PROFINET CM opnums  (IEC 61158-6-10 §6.3)
OP_CONNECT = 0
OP_RELEASE = 1
OP_CONTROL = 2   # both PrmEnd and ApplicationReady use opnum 2
OP_READ    = 3
OP_WRITE   = 4

# IODControlReq ControlCommand bits  (IEC 61158-6-10 Table 566)
CTRL_PRM_END   = 0x0008   # bit 3 = end of parameterisation
CTRL_APP_READY = 0x0010   # bit 4 = controller is ready for data exchange

# PROFINET block types
BT_AR_REQ      = 0x0101
BT_IOCR_REQ    = 0x0102
BT_ALARM_CR    = 0x0103
BT_EXP_SUB    = 0x0104
BT_IOCTRL_REQ  = 0x0110

IOCR_INPUT  = 0x0001
IOCR_OUTPUT = 0x0002
AR_IOCAR_SINGLE = 0x0001

FRAME_ID_IN  = 0x8000   # cyclic input frames  (device → controller)
FRAME_ID_OUT = 0x8001   # cyclic output frames (controller → device)
DEFAULT_SESSION_KEY = 0x0001
DEFAULT_PROCESS_SUBSLOT = 0x0001

FAULT_CODES = {
    0x1c010003: "nca_unk_if        — wrong Object UUID (device endpoint not found)",
    0x1c010002: "nca_op_rng_error  — opnum not registered on this interface",
    0x1c000009: "nca_s_fault_ill_inst — malformed stub (block structure error)",
    0x1c000008: "nca_s_fault_cancel",
    0x1c010001: "nca_s_unsupported_type — transfer syntax mismatch",
    0x1c00000e: "nca_wrong_boot_time — ghost AR lock: POWER-CYCLE THE DEVICE",
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# UUID helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _u(u: uuid.UUID) -> bytes:
    """UUID → 16-byte DCE/RPC little-endian wire encoding."""
    return u.bytes_le

def _pu(b: bytes, off: int = 0) -> uuid.UUID:
    """16 wire bytes → UUID."""
    return uuid.UUID(bytes_le=b[off:off + 16])

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# EPM lookup (DCE/RPC v5 over TCP/135) for dynamic Object UUID discovery
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RPC5_PKT_REQUEST   = 0x00
RPC5_PKT_FAULT     = 0x03
RPC5_PKT_BIND      = 0x0B
RPC5_PKT_BIND_ACK  = 0x0C
_epm_call_id = 0


def _next_epm_call_id() -> int:
    global _epm_call_id
    _epm_call_id += 1
    return _epm_call_id


def build_rpc5_bind(if_uuid: uuid.UUID,
                    if_ver_major: int = 3,
                    if_ver_minor: int = 0) -> bytes:
    """Build DCE/RPC v5 BIND PDU."""
    call_id = _next_epm_call_id()
    ctx = b""
    ctx += struct.pack("<H", 0)                      # p_cont_id
    ctx += struct.pack("<H", 1)                      # n_transfer_syn
    ctx += struct.pack("<H", 0)                      # reserved
    ctx += _u(if_uuid)                               # abstract syntax UUID
    ctx += struct.pack("<HH", if_ver_major, if_ver_minor)
    ctx += _u(NDR_SYNTAX_UUID)                       # transfer syntax UUID
    ctx += struct.pack("<HH", 2, 0)                  # NDR v2.0

    body = b""
    body += struct.pack("<H", 4096)                  # max_xmit_frag
    body += struct.pack("<H", 4096)                  # max_recv_frag
    body += struct.pack("<I", 0)                     # assoc_group_id
    body += struct.pack("<B", 1)                     # n_context_items
    body += struct.pack("<BBH", 0, 0, 0)             # reserved/pad
    body += ctx

    frag_len = 16 + len(body)
    hdr = b""
    hdr += struct.pack("<BB", 5, 0)                  # rpc v5.0
    hdr += struct.pack("<BB", RPC5_PKT_BIND, PFC_FIRST | PFC_LAST)
    hdr += struct.pack("<BBBB", 0x10, 0x00, 0x00, 0x00)
    hdr += struct.pack("<H", frag_len)
    hdr += struct.pack("<H", 0)                      # auth_len
    hdr += struct.pack("<I", call_id)
    return hdr + body


def build_epm_map_req(target_ip: str) -> bytes:
    """Build EPM map request (opnum=3) for PNIO_CM_IF_UUID."""
    call_id = _next_epm_call_id()

    # Build RPC tower for PNIO CM interface.
    fl1 = struct.pack("<H", 19) + struct.pack("<B", 0x0D) + _u(PNIO_CM_IF_UUID) + struct.pack("<H", 1) + struct.pack("<H", 2) + struct.pack("<H", 0)
    fl2 = struct.pack("<H", 19) + struct.pack("<B", 0x0D) + _u(NDR_SYNTAX_UUID) + struct.pack("<H", 2) + struct.pack("<H", 2) + struct.pack("<H", 0)
    fl3 = struct.pack("<H", 1) + struct.pack("<B", 0x0B) + struct.pack("<H", 2) + struct.pack(">H", 135)
    fl4 = struct.pack("<H", 1) + struct.pack("<B", 0x07) + struct.pack("<H", 2) + struct.pack(">H", 0)
    fl5 = struct.pack("<H", 1) + struct.pack("<B", 0x09) + struct.pack("<H", 4) + socket.inet_aton(target_ip)
    twr = struct.pack("<H", 5) + fl1 + fl2 + fl3 + fl4 + fl5

    tower_ndr = b""
    tower_ndr += struct.pack("<I", 0x00020000)       # referent ID
    tower_ndr += struct.pack("<I", len(twr))         # max_count
    tower_ndr += twr
    tower_ndr += b"\x00" * ((4 - (len(twr) % 4)) % 4)

    stub = b""
    stub += b"\x00" * 16                             # object UUID = any
    stub += tower_ndr
    stub += b"\x00" * 20                             # entry_handle
    stub += struct.pack("<I", 10)                    # max_ents

    alloc_hint = len(stub)
    frag_len = 16 + 8 + alloc_hint
    hdr = b""
    hdr += struct.pack("<BB", 5, 0)
    hdr += struct.pack("<BB", RPC5_PKT_REQUEST, PFC_FIRST | PFC_LAST)
    hdr += struct.pack("<BBBB", 0x10, 0x00, 0x00, 0x00)
    hdr += struct.pack("<H", frag_len)
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<I", call_id)
    hdr += struct.pack("<I", alloc_hint)
    hdr += struct.pack("<H", 0)                      # context id
    hdr += struct.pack("<H", 3)                      # opnum = ept_map
    return hdr + stub


def parse_epm_map_rsp(data: bytes) -> Optional[uuid.UUID]:
    """Extract likely CM Object UUID from EPM map response."""
    if len(data) < 24:
        return None
    if data[2] == RPC5_PKT_FAULT:
        return None
    stub = data[24:]
    if len(stub) < 20:
        return None

    # Look for interface UUID floor and take preceding UUID as object candidate.
    target_prefix = PNIO_CM_IF_UUID.bytes_le[:4]
    for i in range(0, len(stub) - 16):
        if stub[i:i+4] != target_prefix:
            continue
        cand_if = _pu(stub, i)
        if cand_if != PNIO_CM_IF_UUID:
            continue
        if i >= 16:
            obj = _pu(stub, i - 16)
            if obj.int != 0 and obj not in (PNIO_CM_IF_UUID, NDR_SYNTAX_UUID, EPM_IF_UUID):
                return obj
    return None


def query_epm_object_uuid(target_ip: str, timeout: float = 4.0) -> Optional[uuid.UUID]:
    """Query endpoint mapper on TCP/135 for device-specific PNIO CM object UUID."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target_ip, EPM_TCP_PORT))

        bind_pkt = build_rpc5_bind(EPM_IF_UUID, if_ver_major=3, if_ver_minor=0)
        s.sendall(bind_pkt)
        rsp = s.recv(4096)
        if len(rsp) < 3 or rsp[2] != RPC5_PKT_BIND_ACK:
            s.close()
            return None

        req = build_epm_map_req(target_ip)
        s.sendall(req)
        rsp2 = b""
        end_t = time.monotonic() + timeout
        while time.monotonic() < end_t:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                rsp2 += chunk
                if len(rsp2) >= 16:
                    fl = struct.unpack_from("<H", rsp2, 8)[0]
                    if len(rsp2) >= fl:
                        break
            except socket.timeout:
                break
        s.close()
        return parse_epm_map_rsp(rsp2)
    except Exception:
        return None

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DCE/RPC v4 CL-PDU builder
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def build_request(seq_num: int,
                  opnum: int,
                  obj_uuid: uuid.UUID,
                  if_uuid: uuid.UUID,
                  act_uuid: uuid.UUID,
                  stub: bytes,
                  wire_profile: Optional["WireProfile"] = None) -> bytes:
    """
    Build a DCE/RPC v4 connectionless (CL) Request PDU.

    80-byte header layout — all integers little-endian (drep[0]=0x10):
      [0]     rpc_vers   = 4
      [1]     pkt_type   = 0x00 (REQUEST)        ← byte 1, not byte 2
      [2]     flags1     = FIRST|LAST|OBJ_UUID   ← 0x83
      [3]     flags2     = 0
      [4-6]   drep[3]    = 0x10,0x00,0x00
      [7]     serial_hi  = 0
      [8-23]  object_uuid                        ← device checks this
      [24-39] if_uuid
      [40-55] act_uuid
      [56-59] server_boot = 0
      [60-63] if_version  = 0x00010000           ← v1.0 little-endian
      [64-67] seq_num                             ← 0 for Connect, +1 each call
      [68-69] opnum                               ← 0/2/3/4
      [70-71] ihint       = 0xFFFF
      [72-73] ahint       = 0xFFFF
      [74-75] frag_len    (LE)
      [76-77] frag_num    = 0
      [78]    auth_proto  = 0
      [79]    serial_lo   = 0
    """
    if wire_profile is None:
        wire_profile = DEFAULT_WIRE_PROFILE
    frag_len = len(stub) if not wire_profile.frag_len_includes_header else 80 + len(stub)
    h  = struct.pack("<B", 4)
    h += struct.pack("<B", PKT_REQUEST)
    h += struct.pack("<B", wire_profile.flags1)
    h += struct.pack("<B", 0)
    h += struct.pack("<BBB", 0x10, 0x00, 0x00)
    h += struct.pack("<B", 0)
    h += _u(obj_uuid)
    h += _u(if_uuid)
    h += _u(act_uuid)
    h += struct.pack("<I", 0)             # server_boot
    h += struct.pack("<I", wire_profile.if_version)
    h += struct.pack("<I", seq_num)
    h += struct.pack("<H", opnum)
    h += struct.pack("<H", 0xFFFF)        # ihint
    h += struct.pack("<H", 0xFFFF)        # ahint
    h += struct.pack("<H", frag_len)
    h += struct.pack("<H", 0)             # frag_num
    h += struct.pack("<B", 0)             # auth_proto
    h += struct.pack("<B", 0)             # serial_lo
    assert len(h) == 80, f"CL-PDU header = {len(h)} bytes (must be 80)"
    return h + stub

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROFINET block builder helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _block(btype: int, body: bytes) -> bytes:
    """
    Wrap body in a PROFINET block envelope.

    Wire: BlockType(2) BlockLength(2) BlockVersionHigh(1) BlockVersionLow(1) body
    BlockLength = 2 + len(body)  [counts the two version bytes, not type/length]
    """
    return struct.pack(">HH BB", btype, 2 + len(body), 1, 0) + body


CMD_ESM1_BODY_HEX = (
    "0001000000000000101000000000000300011011000000000001000001018000"
    "1011000100000001000001018001101100020000000100000101"
)
CMD_ESM2_BODY_HEX = (
    "0001000000000001104000000000000100011040000300030001002801010002"
    "00040101"
)
CMD_ESM_BLOCKS = [
    _block(BT_EXP_SUB, bytes.fromhex(CMD_ESM1_BODY_HEX)),
    _block(BT_EXP_SUB, bytes.fromhex(CMD_ESM2_BODY_HEX)),
]
CMD_IOCR_IN_BODY_HEX = (
    "00010001889200000002002dbbf00080000800010000ffffffff00030003c000"
    "0000000000000001000000000004000000010000000080000001000080010002"
    "000100010003000100010001002c"
)
CMD_IOCR_OUT_BODY_HEX = (
    "000200028892000000020028ffff0080000800010000ffffffff00030003c000"
    "0000000000000001000000000001000100010004000400000001000000008000"
    "0001000080010002000100010003"
)
CMD_IOCR_BLOCKS = [
    _block(BT_IOCR_REQ, bytes.fromhex(CMD_IOCR_IN_BODY_HEX)),
    _block(BT_IOCR_REQ, bytes.fromhex(CMD_IOCR_OUT_BODY_HEX)),
]


def build_ar_block(ar_uuid: uuid.UUID,
                   ctrl_mac: str,
                   station_name: str,
                   session_key: int = DEFAULT_SESSION_KEY,
                   cm_obj_uuid: uuid.UUID = PNIO_CTRL_OBJ_UUID,
                   ar_props: int = 0x00000000,
                   timeout_factor: int = 0x0064,
                   cm_udp_port: int = PNIO_UDP_PORT) -> bytes:
    """
    ARBlockReq  (0x0101) — IEC 61158-6-10 §6.3.5.1.1

    Bugs fixed vs previous versions:
      C:  ARProperties = 0x00000000  (was 0x00000001 = PullModule — wrong mode)
      D:  CMInitiatorActivityTimeoutFactor = 0x0064  (was 0x8892 = ethertype!)
      E:  CMInitiatorObjectUUID = PNIO_CTRL_OBJ_UUID dea00002...
              (was PNIO_CM_IF_UUID dea00001... — device's own UUID, not ours)
    """
    mac_b  = bytes(int(x, 16) for x in ctrl_mac.split(":"))
    name_b = station_name.encode("ascii")
    body   = b""
    body  += struct.pack(">H", AR_IOCAR_SINGLE)    # ARType
    body  += _u(ar_uuid)                            # ARUUID  (LE per PNIO spec)
    body  += struct.pack(">H", session_key)         # SessionKey
    body  += mac_b                                  # CMInitiatorMACAdd  (6 B)
    body  += _u(cm_obj_uuid)                        # CMInitiatorObjectUUID  [FIX E]
    body  += struct.pack(">I", ar_props)            # ARProperties  [FIX C]
    body  += struct.pack(">H", timeout_factor)      # CMInitiatorActivityTimeoutFactor [FIX D]
    body  += struct.pack(">H", cm_udp_port)         # CMInitiatorUDPRTPort
    body  += struct.pack(">H", len(name_b))         # StationNameLength
    body  += name_b
    if len(name_b) % 2:
        body += b'\x00'                             # pad station name to even length
    return _block(BT_AR_REQ, body)


@dataclass
class IODataObject:
    slot: int
    subslot: int
    frame_offset: int = 0


@dataclass
class IOCS:
    slot: int
    subslot: int


@dataclass
class IOCRSpec:
    cr_type:  int           # IOCR_INPUT or IOCR_OUTPUT
    cr_ref:   int           # 1 = input, 2 = output
    frame_id: int           # FRAME_ID_IN or FRAME_ID_OUT
    data_len: int           # payload bytes (process data + IOPS/IOCS)
    slot:     int = 1
    subslot:  int = DEFAULT_PROCESS_SUBSLOT
    api:      int = 0
    lt:       int = PROFINET_ETYPE
    iocr_props: int = 0x00000000
    scf:      int = 32
    rr:       int = 32
    phase:    int = 1
    seq:      int = 0
    fso:      int = 0xFFFFFFFF
    wdf:      int = 5
    dhf:      int = 5
    tag_header: int = 0xC000
    io_data_objects: Optional[list[IODataObject]] = None
    iocs: Optional[list[IOCS]] = None


@dataclass
class WireProfile:
    name: str
    flags1: int = (PFC_FIRST | PFC_LAST | PFC_OBJ_UUID)
    if_version: int = 0x00010000
    frag_len_includes_header: bool = True
    add_connect_prefix: bool = False
    ar_props: int = 0x00000000
    ar_timeout_factor: int = 0x0064
    cm_udp_port: int = PNIO_UDP_PORT
    cm_initiator_obj: uuid.UUID = PNIO_CTRL_OBJ_UUID
    station_name: Optional[str] = None
    use_uuid1_activity: bool = False
    use_ephemeral_sport: bool = False
    iocr_props: int = 0x00000000
    iocr_lt: int = PROFINET_ETYPE
    send_clock_factor: int = 32
    reduction_ratio: int = 32
    watchdog_factor: int = 5
    data_hold_factor: int = 5
    tag_header: int = 0xC000
    frame_id_in: int = FRAME_ID_IN
    frame_id_out: int = FRAME_ID_OUT
    data_len_in: Optional[int] = None
    data_len_out: Optional[int] = None
    expected_submodules: Optional[list[bytes]] = None
    iocr_blocks: Optional[list[bytes]] = None
    rt_input_total_len: Optional[int] = None
    rt_input_data_offset: int = 0
    rt_input_frame_ids: Optional[list[int]] = None
    rt_input_iops_positions: Optional[list[int]] = None
    rt_output_total_len: Optional[int] = None
    rt_output_data_offset: int = 0
    rt_output_iops_positions: Optional[list[int]] = None
    rt_output_frame_id: Optional[int] = None
    rt_send_tagged: bool = True
    rt_send_untagged: bool = False
    rt_iops_value: int = 0x80


DEFAULT_WIRE_PROFILE = WireProfile(name="default")
COMMANDER_WIRE_PROFILE = WireProfile(
    name="commander",
    flags1=0x20,
    if_version=1,
    frag_len_includes_header=False,
    add_connect_prefix=True,
    ar_props=CMD_AR_PROPS,
    ar_timeout_factor=CMD_TIMEOUT_F,
    cm_udp_port=CMD_CM_UDP_PORT,
    cm_initiator_obj=PNIO_CMD_CTRL_OBJ_UUID,
    use_uuid1_activity=True,
    use_ephemeral_sport=True,
    iocr_props=CMD_IOCR_PROPS,
    iocr_lt=PROFINET_ETYPE,
    send_clock_factor=CMD_SCF,
    reduction_ratio=CMD_RR,
    watchdog_factor=CMD_WDF,
    data_hold_factor=CMD_DHF,
    tag_header=0xC000,
    frame_id_in=CMD_FRAME_ID_IN,
    frame_id_out=CMD_FRAME_ID_OUT,
    data_len_in=45,
    data_len_out=40,
    expected_submodules=CMD_ESM_BLOCKS,
    iocr_blocks=CMD_IOCR_BLOCKS,
    rt_input_total_len=45,
    rt_input_data_offset=3,
    rt_input_frame_ids=[CMD_FRAME_ID_IN],
    rt_input_iops_positions=[0, 1, 2, 43, 44],
    rt_output_total_len=40,
    rt_output_data_offset=4,
    rt_output_iops_positions=[0, 1, 2, 3, 8],
    rt_output_frame_id=FRAME_ID_IN,
    rt_send_tagged=True,
    rt_send_untagged=True,
)

def build_iocr_block(spec: IOCRSpec) -> bytes:
    """
    IOCRBlockReq  (0x0102) — IEC 61158-6-10 §6.3.5.1.3

    Bug fixed:
      F:  LT field is UINT16 (2 bytes).  Was packed as UINT32 (4 bytes),
          shifting DataLength, FrameID and every subsequent field by +2 bytes.
    """
    io_data_objects = spec.io_data_objects or [IODataObject(spec.slot, spec.subslot, 0)]
    iocs = spec.iocs or []

    api_blk  = struct.pack(">I", spec.api)     # API
    api_blk += struct.pack(">H", len(io_data_objects))  # NumberOfIODataObjects
    api_blk += struct.pack(">H", len(iocs))             # NumberOfIOCS
    for obj in io_data_objects:
        api_blk += struct.pack(">H", obj.slot)
        api_blk += struct.pack(">H", obj.subslot)
        api_blk += struct.pack(">H", obj.frame_offset)
    for io in iocs:
        api_blk += struct.pack(">H", io.slot)
        api_blk += struct.pack(">H", io.subslot)

    body  = struct.pack(">H", spec.cr_type)    # IOCRType
    body += struct.pack(">H", spec.cr_ref)     # IOCRReference
    body += struct.pack(">H", spec.lt)         # LT  [FIX F: 2 bytes not 4]
    body += struct.pack(">I", spec.iocr_props) # IOCRProperties
    body += struct.pack(">H", spec.data_len)   # DataLength
    body += struct.pack(">H", spec.frame_id)   # FrameID
    body += struct.pack(">H", spec.scf)        # SendClockFactor
    body += struct.pack(">H", spec.rr)         # ReductionRatio
    body += struct.pack(">H", spec.phase)      # Phase
    body += struct.pack(">H", spec.seq)        # Sequence
    body += struct.pack(">I", spec.fso)        # FrameSendOffset = best effort
    body += struct.pack(">H", spec.wdf)        # WatchdogFactor
    body += struct.pack(">H", spec.dhf)        # DataHoldFactor
    body += struct.pack(">H", spec.tag_header) # IOCRTagHeader
    body += b'\x00\x00\x00\x00\x00\x00'      # IOCRMulticastMACAdd (unicast = zeros)
    body += struct.pack(">H", 1)              # NumberOfAPIs
    body += api_blk
    return _block(BT_IOCR_REQ, body)


def build_expected_submodule_block(in_len: int, out_len: int,
                                   subslot: int = DEFAULT_PROCESS_SUBSLOT) -> bytes:
    """
    ExpectedSubmoduleBlockReq  (0x0104)

    Bugs fixed:
      NEW-1:  SubmoduleProperties was 0x0000 (NO_IO) → now 0x0003 (INPUT_OUTPUT)
      NEW-2:  OUTPUT DataDescription block was missing entirely.
              Both INPUT and OUTPUT descriptions are required when a submodule
              has process data in both directions.
    """
    # SubmoduleDataDescription for INPUT (device → controller)
    ddi  = struct.pack(">H", 0x0001)           # DataDirection = INPUT
    ddi += struct.pack(">H", in_len)           # SubmoduleDataLength
    ddi += struct.pack(">B", 1)               # LengthIOCS
    ddi += struct.pack(">B", 1)               # LengthIOPS

    # SubmoduleDataDescription for OUTPUT (controller → device)
    ddo  = struct.pack(">H", 0x0002)           # DataDirection = OUTPUT
    ddo += struct.pack(">H", out_len)          # SubmoduleDataLength
    ddo += struct.pack(">B", 1)               # LengthIOCS
    ddo += struct.pack(">B", 1)               # LengthIOPS

    # Submodule descriptor
    sub  = struct.pack(">H", subslot)          # SubslotNumber (matches IOCR)
    sub += struct.pack(">I", 0x00000001)       # SubmoduleIdentNumber
    sub += struct.pack(">H", 0x0003)           # SubmoduleProperties: INPUT_OUTPUT [FIX NEW-1]
    sub += ddi                                  # INPUT data description  [FIX NEW-2]
    sub += ddo                                  # OUTPUT data description [FIX NEW-2]

    # Module at slot 1
    mod  = struct.pack(">H", 1)               # SlotNumber
    mod += struct.pack(">I", 0x00001503)       # ModuleIdentNumber (TeSys Tera device ID)
    mod += struct.pack(">H", 0x0000)           # ModuleProperties
    mod += struct.pack(">H", 1)               # NumberOfSubmodules
    mod += sub

    # API wrapper
    api  = struct.pack(">I", 0)               # API = 0
    api += struct.pack(">H", 1)               # NumberOfModules
    api += mod

    body = struct.pack(">H", 1) + api         # NumberOfAPIs = 1
    return _block(BT_EXP_SUB, body)


def build_alarm_cr_block() -> bytes:
    """
    AlarmCRBlockReq  (0x0103) — alarm channel parameters.

    Values verified against reference pcap (tesysprofinetdemo.pcapng):
      REF body: 000188920000000000010003000000c8c000a000

    Previous v7 values vs corrected values:
      RTATimeoutFactor:    200  → 1      (1 × 1 ms = 1 ms, device requires minimum)
      LocalAlarmReference: 1   → 0      (controller-assigned ref; device expects 0)
      AlarmCRTagHeaderHigh:0x0000 → 0xc000  (VLAN priority bits for alarm frames)
      AlarmCRTagHeaderLow: 0x0000 → 0xa000  (VLAN ID bits for alarm frames)
    These four mismatches caused the device to return PNIO error 0x010181db
    (ErrorCode1=0x81 = AlarmCR configuration error) in the ConnectRes stub,
    silently failing the connection while our code reported "ConnectRes OK".
    """
    body  = struct.pack(">H", 0x0001)         # AlarmCRType = Alarm CR
    body += struct.pack(">H", PROFINET_ETYPE) # LT          = 0x8892
    body += struct.pack(">I", 0x00000000)     # AlarmCRProperties
    body += struct.pack(">H", 1)              # RTATimeoutFactor  (1 × 1 ms = 1 ms)
    body += struct.pack(">H", 3)              # RTARetries
    body += struct.pack(">H", 0)              # LocalAlarmReference  (0 = controller assigns)
    body += struct.pack(">H", 200)            # MaxAlarmDataLength   (200 bytes)
    body += struct.pack(">H", 0xc000)         # AlarmCRTagHeaderHigh (VLAN PCP=6)
    body += struct.pack(">H", 0xa000)         # AlarmCRTagHeaderLow  (VLAN VID=0, DEI=1)
    return _block(BT_ALARM_CR, body)


def build_connect_stub(ar_uuid: uuid.UUID,
                       ctrl_mac: str,
                       controller_station_name: str,
                       in_len: int,
                       out_len: int,
                       subslot: int = DEFAULT_PROCESS_SUBSLOT,
                       session_key: int = DEFAULT_SESSION_KEY,
                       wire_profile: WireProfile = DEFAULT_WIRE_PROFILE) -> bytes:
    """Full NDR stub for IODConnectReq (opnum 0). Blocks concatenated directly."""
    station_name = wire_profile.station_name or controller_station_name
    ar = build_ar_block(
        ar_uuid, ctrl_mac, station_name,
        session_key=session_key,
        cm_obj_uuid=wire_profile.cm_initiator_obj,
        ar_props=wire_profile.ar_props,
        timeout_factor=wire_profile.ar_timeout_factor,
        cm_udp_port=wire_profile.cm_udp_port,
    )
    in_len_eff = wire_profile.data_len_in if wire_profile.data_len_in is not None else in_len + 1
    out_len_eff = wire_profile.data_len_out if wire_profile.data_len_out is not None else out_len + 1
    if wire_profile.iocr_blocks:
        iocr_blocks = wire_profile.iocr_blocks
    else:
        in_cr = build_iocr_block(IOCRSpec(
            IOCR_INPUT, 1, wire_profile.frame_id_in, in_len_eff,
            subslot=subslot,
            lt=wire_profile.iocr_lt,
            iocr_props=wire_profile.iocr_props,
            scf=wire_profile.send_clock_factor,
            rr=wire_profile.reduction_ratio,
            wdf=wire_profile.watchdog_factor,
            dhf=wire_profile.data_hold_factor,
            tag_header=wire_profile.tag_header,
        ))
        ou_cr = build_iocr_block(IOCRSpec(
            IOCR_OUTPUT, 2, wire_profile.frame_id_out, out_len_eff,
            subslot=subslot,
            lt=wire_profile.iocr_lt,
            iocr_props=wire_profile.iocr_props,
            scf=wire_profile.send_clock_factor,
            rr=wire_profile.reduction_ratio,
            wdf=wire_profile.watchdog_factor,
            dhf=wire_profile.data_hold_factor,
            tag_header=wire_profile.tag_header,
        ))
        iocr_blocks = [in_cr, ou_cr]
    if wire_profile.expected_submodules:
        esm = b"".join(wire_profile.expected_submodules)
    else:
        esm = build_expected_submodule_block(in_len, out_len, subslot=subslot)
    alarm = build_alarm_cr_block()
    stub = ar + b"".join(iocr_blocks) + esm + alarm
    if wire_profile.add_connect_prefix:
        blen = len(stub)
        prefix = struct.pack("<IIIII", blen + 0x2A, blen, blen + 0x2A, 0, blen)
        stub = prefix + stub
    return stub


def build_control_stub(ar_uuid: uuid.UUID, ctrl_cmd: int,
                       session_key: int = DEFAULT_SESSION_KEY) -> bytes:
    """
    IODControlReq stub (opnum 2) — used for BOTH PrmEnd and ApplicationReady.

    Block structure (IEC 61158-6-10 §6.3.10.1):
      BlockType    (2B): 0x0110
      BlockLength  (2B): 26  [= 2 + 24-byte body]
      Version      (2B): 1.0
      Padding      (2B): 0x0000  ← was MISSING in previous versions (bug I)
      ARUUID      (16B): LE
      SessionKey   (2B): 0x0001
      Padding      (2B): 0x0000
      ControlCommand (2B): 0x0008=PrmEnd  0x0010=AppReady  (bugs H/K)
      ControlBlockProperties (2B): 0x0000

    opnum = 2 for both  (bugs G/J: was 4 = IODWriteReq)
    """
    body  = struct.pack(">H", 0x0000)          # Padding  [FIX I]
    body += _u(ar_uuid)                         # ARUUID
    body += struct.pack(">H", session_key)      # SessionKey
    body += struct.pack(">H", 0x0000)          # Padding
    body += struct.pack(">H", ctrl_cmd)         # ControlCommand  [FIX H / FIX K]
    body += struct.pack(">H", 0x0000)          # ControlBlockProperties
    return _block(BT_IOCTRL_REQ, body)


def build_read_stub(ar_uuid: uuid.UUID,
                    slot: int, subslot: int, index: int,
                    max_len: int = 0x8000) -> bytes:
    """IODReadReq stub (opnum 3)."""
    s  = struct.pack(">HH", 0, 0)              # SeqNum, Padding
    s += _u(ar_uuid)
    s += struct.pack(">I", 0)                  # API
    s += struct.pack(">H", slot)
    s += struct.pack(">H", subslot)
    s += struct.pack(">H", 0)                  # Padding
    s += struct.pack(">H", index)
    s += struct.pack(">I", max_len)
    s += _u(uuid.UUID(int=0))                  # TargetARUUID (unused)
    s += b'\x00' * 20                          # Reserved
    return s


def build_write_stub(ar_uuid: uuid.UUID,
                     slot: int, subslot: int, index: int,
                     data: bytes) -> bytes:
    """IODWriteReq stub (opnum 4)."""
    s  = struct.pack(">HH", 0, 0)
    s += _u(ar_uuid)
    s += struct.pack(">I", 0)
    s += struct.pack(">H", slot)
    s += struct.pack(">H", subslot)
    s += struct.pack(">H", 0)
    s += struct.pack(">H", index)
    s += struct.pack(">I", len(data))
    s += _u(uuid.UUID(int=0))
    s += b'\x00' * 20
    s += data
    s += b'\x00' * ((4 - len(data) % 4) % 4)  # align to 4 bytes
    return s

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Cyclic RT frame helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_output_rt_frame(out_data: bytes, cycle: int,
                           src_mac: str, dst_mac: str,
                           frame_id_out: int = FRAME_ID_OUT,
                           data_total_len: Optional[int] = None,
                           data_offset: int = 0,
                           iops_positions: Optional[list[int]] = None,
                           iops_value: int = 0x80,
                           tagged: bool = True):
    """
    Cyclic output frame (controller → device).

    Ethernet header  (Scapy)
    VLAN tag         prio=6, VID=0
    PROFINET payload:
      FrameID        (2B): 0x8001  [FIX L: was 0x8002]
      OutputData     (n B)
      IOPS           (1B): 0x80 = GOOD
      CycleCounter   (2B)
      DataStatus     (1B): 0x35
      TransferStatus (1B): 0x00    [FIX M: no phantom 30-byte padding]
    """
    if data_total_len is None:
        data_section = out_data + struct.pack(">B", iops_value)
    else:
        if data_offset + len(out_data) > data_total_len:
            raise ValueError("output data exceeds RT data section length")
        data_section = bytearray(b"\x00" * data_total_len)
        if iops_positions:
            for pos in iops_positions:
                if 0 <= pos < data_total_len:
                    data_section[pos] = iops_value
        elif data_total_len == len(out_data) + 1:
            data_section[-1] = iops_value
        data_section[data_offset:data_offset + len(out_data)] = out_data
        data_section = bytes(data_section)

    payload  = struct.pack(">H", frame_id_out)   # [FIX L]
    payload += data_section
    payload += struct.pack(">H", cycle)
    payload += struct.pack(">B", 0x35)            # DataStatus
    payload += struct.pack(">B", 0x00)            # TransferStatus
    if tagged:
        return (Ether(dst=dst_mac, src=src_mac) /
                Dot1Q(prio=6, id=0, vlan=0, type=PROFINET_ETYPE) /
                Raw(load=payload))
    return (Ether(dst=dst_mac, src=src_mac, type=PROFINET_ETYPE) /
            Raw(load=payload))


def parse_input_rt_frame(raw: bytes, in_len: int,
                         frame_id_in: int | list[int] = FRAME_ID_IN,
                         data_total_len: Optional[int] = None,
                         data_offset: int = 0) -> Optional[bytes]:
    """
    Extract process input data from a captured Ethernet frame.
    Returns in_len bytes, or None if not a valid PROFINET input frame.

    [FIX N]: FrameID filter is now 0x8000 (input from device),
             was 0x8001 (that's the output direction — our own frames).
    """
    off = 12
    if raw[12:14] == b'\x81\x00':   # VLAN tag
        off += 4
    if len(raw) < off + 4:
        return None
    if struct.unpack_from(">H", raw, off)[0] != PROFINET_ETYPE:
        return None
    off += 2
    fid = struct.unpack_from(">H", raw, off)[0]
    if isinstance(frame_id_in, list):
        if fid not in frame_id_in:
            return None
    else:
        if fid != frame_id_in:  # [FIX N]
            return None
    off += 2
    if data_total_len is None:
        if len(raw) < off + in_len:
            return None
        return raw[off: off + in_len]
    if len(raw) < off + data_total_len + 4:
        return None
    data_section = raw[off: off + data_total_len]
    if data_offset + in_len > len(data_section):
        return None
    return data_section[data_offset: data_offset + in_len]


def decode_tesys_input(data: bytes) -> dict:
    """
    Decode TeSys Tera Module 1 process input  (40 bytes).
    Byte offsets from Schneider PROFINET mapping document.
    Adjust if your GSD / firmware revision differs.
    """
    if len(data) < 40:
        return {"error": f"short ({len(data)} B, need 40)"}
    return {
        "status_word_1":    struct.unpack_from(">H", data, 0)[0],
        "status_word_2":    struct.unpack_from(">H", data, 2)[0],
        "current_pct_flc":  struct.unpack_from(">I", data, 4)[0] * 0.1,
        "thermal_state":    struct.unpack_from(">H", data, 8)[0],
        "last_trip_cause":  data[10],
        "motor_state":      data[11],
        "voltage_V":        struct.unpack_from(">I", data, 24)[0] * 0.1,
        "power_kW":         struct.unpack_from(">I", data, 28)[0] * 0.001,
    }

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scapy transport layer — replaces Python UDP socket entirely
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScapyTransport:
    """
    Sends DCE/RPC payloads as Ether/IP/UDP frames via Scapy sendp,
    and receives responses via AsyncSniffer — bypassing the Windows
    networking stack, firewall, and routing table completely.

    This is the fix for the silent TIMEOUT symptom.  The device WAS
    receiving the (correctly-formed) packet and sending a response back,
    but Windows Firewall / the UDP receive path was silently discarding
    the inbound response.  Raw Ethernet capture via Npcap ignores all of
    that — we see every frame on the wire.
    """

    def __init__(self, iface: str,
                 src_mac: str, src_ip: str,
                 dst_mac: str, dst_ip: str,
                 sport: int, dport: int):
        self.iface   = iface
        self.src_mac = src_mac
        self.src_ip  = src_ip
        self.dst_mac = dst_mac
        self.dst_ip  = dst_ip
        self.sport   = sport
        self.dport   = dport
        self._host_diag_done = False

        # Capture every frame from the target MAC, then validate DCE/RPC in Python.
        # This avoids false negatives from strict BPF assumptions (VLAN tags, atypical
        # UDP source ports, or stack-specific encapsulation details).
        self._bpf = f"ether src {dst_mac}"

        # ── FIX 1: Suppress ICMP "Port Unreachable" ──────────────────────────
        # When Scapy injects a raw UDP frame (src_ip:sport → dst_ip:dport) the
        # device sends its DCE/RPC response back to src_ip:sport.  Because no
        # real process owns that UDP port, Windows immediately sends an ICMP
        # "Port Unreachable" back to the device.  TeSys Tera interprets that
        # as the controller going offline and silently aborts the AR without
        # ever completing the handshake — which looks exactly like a timeout.
        # Binding a dummy UDP socket on sport claims the port so Windows never
        # generates the ICMP.  We never read from this socket; all receives are
        # done via the Scapy raw sniffer below.
        self._dummy_sock: Optional[socket.socket] = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((src_ip, sport))
            self._dummy_sock = s
            log.debug("Dummy UDP socket bound on %s:%d — ICMP port-unreachable suppressed",
                      src_ip, sport)
        except OSError as exc:
            log.warning(
                "Could not bind dummy UDP socket on %s:%d (%s). "
                "Windows may send ICMP port-unreachable to the device, "
                "which can cause silent AR abort.  "
                "Try running as Administrator.", src_ip, sport, exc
            )

    def close(self) -> None:
        if self._dummy_sock is not None:
            try:
                self._dummy_sock.close()
            except Exception:
                pass
            self._dummy_sock = None

    @staticmethod
    def _run_cmd(args: list[str], timeout: float = 8.0) -> str:
        try:
            cp = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            out = (cp.stdout or "").strip()
            err = (cp.stderr or "").strip()
            if err:
                out = (out + "\n" + err).strip()
            return out or "(no output)"
        except Exception as exc:
            return f"(command failed: {exc})"

    def _run_host_network_diagnostics(self) -> None:
        log.info("  Host diagnostics (one-time) for deeper troubleshooting:")
        diag_cmds = [
            ["ping", "-n", "1", self.dst_ip],
            ["arp", "-a", self.dst_ip],
            ["route", "print", self.dst_ip],
            ["netsh", "interface", "ipv4", "show", "interfaces"],
        ]
        for cmd in diag_cmds:
            log.info("    $ %s", " ".join(cmd))
            out = self._run_cmd(cmd)
            for line in out.splitlines()[:30]:
                log.info("      %s", line)

    @staticmethod
    def _summarize_diag_frames(frames: list, target_mac: str, target_ip: str) -> None:
        if not frames:
            return
        from_target = 0
        to_target = 0
        arp_frames = 0
        icmp_frames = 0
        udp_frames = 0
        udp_34964 = 0
        for f in frames:
            if f.haslayer(Ether):
                sm = f[Ether].src.lower()
                dm = f[Ether].dst.lower()
                if sm == target_mac.lower():
                    from_target += 1
                if dm == target_mac.lower():
                    to_target += 1
            if f.haslayer(ARP):
                arp_frames += 1
            if f.haslayer(ICMP):
                icmp_frames += 1
            if f.haslayer(UDP):
                udp_frames += 1
                sp, dp = int(f[UDP].sport), int(f[UDP].dport)
                if sp == 34964 or dp == 34964:
                    udp_34964 += 1

        log.warning("  Diag summary: total=%d from_target=%d to_target=%d arp=%d icmp=%d udp=%d udp34964=%d",
                    len(frames), from_target, to_target, arp_frames, icmp_frames, udp_frames, udp_34964)

        for frm in frames[:8]:
            try:
                if not frm.haslayer(Ether):
                    continue
                e = frm[Ether]
                line = f"    eth {e.src}->{e.dst} type=0x{int(e.type):04x}"
                if frm.haslayer(IP):
                    ip = frm[IP]
                    line += f" ip {ip.src}->{ip.dst} proto={int(ip.proto)}"
                if frm.haslayer(UDP):
                    u = frm[UDP]
                    line += f" udp {int(u.sport)}->{int(u.dport)}"
                if frm.haslayer(ARP):
                    a = frm[ARP]
                    line += f" arp op={int(a.op)} {a.psrc}->{a.pdst}"
                if frm.haslayer(ICMP):
                    i = frm[ICMP]
                    line += f" icmp type={int(i.type)} code={int(i.code)}"
                if frm.haslayer(Raw):
                    rb = bytes(frm[Raw].load)
                    line += f" raw0_16={rb[:16].hex()}"
                log.warning(line)
            except Exception as exc:
                log.warning("    frame decode error: %s", exc)

    def send_recv(self, payload: bytes, label: str,
                  timeout: float = 3.0) -> Optional[bytes]:
        """
        Send a DCE/RPC payload, wait up to `timeout` seconds for a response.
        Returns the raw DCE/RPC bytes (without Ethernet/IP/UDP headers), or None.
        """
        resp_q: queue.Queue = queue.Queue()
        expected_seq: Optional[int] = None
        expected_act: bytes = b""
        if len(payload) >= 68:
            expected_seq = struct.unpack_from("<I", payload, 64)[0]
        if len(payload) >= 56:
            expected_act = payload[40:56]
        seen_any = 0
        seen_dcerpc = 0
        seen_udp_ports = set()

        def _handler(pkt):
            nonlocal seen_any, seen_dcerpc
            if pkt.haslayer(UDP):
                try:
                    seen_udp_ports.add((int(pkt[UDP].sport), int(pkt[UDP].dport)))
                except Exception:
                    pass
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                seen_any += 1
                # DCE/RPC v4 sanity checks
                if len(raw) < 80 or raw[0] != 4 or raw[4] != 0x10:
                    return
                if raw[1] not in (PKT_RESPONSE, PKT_FAULT):
                    return
                seen_dcerpc += 1

                # Match the in-flight request by activity UUID and sequence number.
                if expected_act and raw[40:56] != expected_act:
                    return
                if expected_seq is not None:
                    try:
                        resp_seq = struct.unpack_from("<I", raw, 64)[0]
                    except struct.error:
                        return
                    if resp_seq != expected_seq:
                        return

                if resp_q.empty():
                    resp_q.put(raw)

        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self._bpf,
            prn=_handler,
            store=False,
        )
        trace_bpf = (
            f"ether host {self.dst_mac} or host {self.dst_ip} or arp or icmp"
        )
        trace = AsyncSniffer(
            iface=self.iface,
            filter=trace_bpf,
            store=True,
        )
        sniffer.start()
        trace.start()
        # ── FIX 2: Give Npcap/WinPcap adequate time to arm the capture ───────
        # 50 ms was too short on Windows — Npcap can take 100–200 ms to attach
        # the BPF filter to the adapter driver.  If the device's response
        # arrives during that window the packet is permanently lost and the
        # call times out even though the wire exchange succeeded.
        time.sleep(0.20)

        frame = (Ether(dst=self.dst_mac, src=self.src_mac) /
                 IP(src=self.src_ip,   dst=self.dst_ip)   /
                 UDP(sport=self.sport, dport=self.dport)   /
                 Raw(load=payload))
        sendp(frame, iface=self.iface, verbose=False)
        # Also send through the OS UDP stack (same src/dst/port) to avoid
        # edge cases with raw crafted IP/UDP on specific NIC/driver combos.
        if self._dummy_sock is not None:
            self._dummy_sock.sendto(payload, (self.dst_ip, self.dport))
        log.debug(">>> %s  len=%d  payload[0:16]=%s",
                  label, len(payload), payload[:16].hex())

        try:
            resp = resp_q.get(timeout=timeout)
        except queue.Empty:
            resp = None
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
            try:
                trace.stop()
                trace_frames = trace.results or []
            except Exception:
                trace_frames = []

        if resp is None:
            log.error("TIMEOUT — no response to %s", label)
            log.error("  Check: (1) SCAPY_IFACE GUID is correct for the NIC with "
                      "IP %s", self.src_ip)
            log.error("  Check: (2) Npcap/WinPcap is installed (run as Administrator)")
            log.error("  Check: (3) TeSys Tera was power-cycled before this run")
            log.error("  Check: (4) 'ping %s' works from this PC", self.dst_ip)
            if seen_any:
                log.warning("  Capture saw %d frame(s) from target MAC during wait; "
                            "%d looked like DCE/RPC v4", seen_any, seen_dcerpc)
            if seen_udp_ports:
                ports = ", ".join(f"{sp}->{dp}" for sp, dp in sorted(seen_udp_ports))
                log.warning("  UDP flows seen from target during wait: %s", ports)
            if trace_frames:
                log.warning("  Per-attempt trace captured %d frame(s)", len(trace_frames))
                self._summarize_diag_frames(trace_frames, self.dst_mac, self.dst_ip)
            # ── Fallback diagnostic: listen for ANYTHING from the device ─────
            # If this catches packets, the device IS responding but on a port/
            # protocol not matched by the strict BPF above — helps narrow down
            # the problem without Wireshark.
            log.info("  Running 2 s fallback capture (both directions: target/IP/ARP/ICMP) …")
            wide_bpf = (
                f"ether host {self.dst_mac} or host {self.dst_ip} "
                f"or arp or icmp"
            )
            seen: list = []
            try:
                diag = AsyncSniffer(iface=self.iface, filter=wide_bpf,
                                    timeout=2.0, store=True)
                diag.start()
                diag.join()
                seen = diag.results or []
            except Exception as diag_exc:
                log.debug("  Fallback capture failed: %s", diag_exc)
            if seen:
                self._summarize_diag_frames(seen, self.dst_mac, self.dst_ip)
            else:
                log.error("  Fallback: no frames at all from %s — "
                          "check cable, VLAN, and SCAPY_IFACE GUID.", self.dst_mac)
            if not self._host_diag_done:
                self._host_diag_done = True
                self._run_host_network_diagnostics()
            return None

        ptype = resp[1]
        log.debug("<<< %s  ptype=0x%02x  len=%d", label, ptype, len(resp))

        if ptype == PKT_FAULT and len(resp) >= 84:
            code = struct.unpack_from("<I", resp, 80)[0]
            desc = FAULT_CODES.get(code, "unknown fault code")
            log.error("    DCE/RPC FAULT 0x%08x: %s", code, desc)
            if code == 0x1c00000e:
                log.error("    *** GHOST AR LOCK — power-cycle TeSys Tera, wait 10 s, retry ***")
            return None

        if ptype == 0x06:
            # DCE/RPC REJECT — return to step_ar_connect for proper handling
            log.debug("    DCE/RPC REJECT received — returning to caller")
            return resp

        return resp

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIX 3 — DCP Identify probe  (Layer-2, no IP required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# PROFINET DCP multicast MAC (IEC 61158-6-10 §6.3.13).
# DCP Identify Requests MUST be sent to this address; devices ignore unicast DCP.
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"


def list_interfaces() -> None:
    """
    Print all Scapy-visible network interfaces with their IPv4 addresses.
    Call from a Python shell:
      python -c "from tesys_pn_v9 import list_interfaces; list_interfaces()"
    """
    try:
        from scapy.all import get_if_list, get_if_addr
    except ImportError:
        print("scapy not installed")
        return
    print("\nAvailable network interfaces:")
    print(f"  {'GUID / Name':<60}  IPv4")
    print("  " + "-" * 75)
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "(error)"
        marker = " ◄ USE THIS" if ip == CONTROLLER_IP else ""
        print(f"  {iface:<60}  {ip}{marker}")
    print()


def dcp_identify(iface: str, src_mac: str, target_mac: str,
                 timeout: float = 3.0) -> bool:
    """
    FIX 3 (corrected): Send a PROFINET DCP Identify Request to the PROFINET
    multicast address 01:0e:cf:00:00:00 and wait for the device to respond.

    BUG IN v5: the request was sent unicast to the device MAC.  PROFINET
    devices only process DCP frames whose Ethernet destination is the DCP
    multicast MAC (IEC 61158-6-10 §6.3.13.3).  A unicast DCP frame is silently
    dropped by the device's PROFINET stack, producing a false "device not
    reachable" error even when the cable and NIC are fine.

    FIX: Ethernet dst = DCP_MULTICAST_MAC = 01:0e:cf:00:00:00
         The BPF sniffer still filters by *source* MAC (target_mac), so we
         only capture responses from the specific device we're talking to.

    Returns True if the device responds (is alive on the wire).
    """
    xid = 0x11223344

    # DCP Identify-All request (Option=0xFF/0xFF = All)
    dcp_req  = struct.pack(">H", 0xFEFF)          # FrameID (Identify-ReqPDU)
    dcp_req += struct.pack(">BB", 0x05, 0x00)     # ServiceID=Identify, Type=Request
    dcp_req += struct.pack(">I", xid)             # Xid
    dcp_req += struct.pack(">H", 1)               # ResponseDelay (1 × 10 ms)
    dcp_req += struct.pack(">H", 4)               # DCPDataLength = 4
    dcp_req += struct.pack(">BB", 0xFF, 0xFF)     # Option/SubOption = All
    dcp_req += struct.pack(">H", 0)               # DCPBlockLength = 0

    # ── KEY FIX: dst = PROFINET multicast, NOT the device unicast MAC ──────
    frame = (Ether(dst=DCP_MULTICAST_MAC, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    found: list = []

    def _handler(pkt):
        if not pkt.haslayer(Raw):
            return
        raw = bytes(pkt[Raw])
        if len(raw) < 10:
            return
        fid = struct.unpack_from(">H", raw, 0)[0]
        # DCP Identify Response FrameIDs: 0xFEFD (to multicast) or 0xFEFE (unicast)
        if fid in (0xFEFD, 0xFEFE):
            found.append(raw)

    # Capture any DCP response that originates from the target device's MAC
    bpf = f"ether src {target_mac} and ether proto 0x{PROFINET_ETYPE:04x}"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handler, store=False)
    sniffer.start()
    time.sleep(0.20)

    sendp(frame, iface=iface, verbose=False)
    log.debug("DCP Identify → %s (via multicast %s)", target_mac, DCP_MULTICAST_MAC)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)

    try:
        sniffer.stop()
    except Exception:
        pass

    if found:
        raw = found[0]
        log.info("DCP Identify OK — device %s is alive  (%d bytes)", target_mac, len(raw))
        # Try to extract station name from the DCP response for confirmation
        try:
            off = 10    # past FrameID(2)+SvcID(1)+SvcType(1)+Xid(4)+DCPDataLen(2)
            while off + 4 <= len(raw):
                opt, sub = raw[off], raw[off + 1]
                blen = struct.unpack_from(">H", raw, off + 2)[0]
                if opt == 0x02 and sub == 0x02 and blen > 0:  # NameOfStation
                    name = raw[off + 4: off + 4 + blen].decode("ascii", errors="replace").rstrip('\x00')
                    log.info("  Station name from DCP response: '%s'", name)
                off += 4 + blen + (blen % 2)   # align to 2 bytes
        except Exception:
            pass
        return True
    else:
        log.error("DCP Identify TIMEOUT — no response from %s within %.1f s",
                  target_mac, timeout)
        log.error("  The device did not respond to DCP Identify multicast.")
        return False


def arp_ping(iface: str, src_mac: str, src_ip: str, dst_ip: str,
             timeout: float = 2.0) -> bool:
    """
    ARP-ping the target IP as a supplementary Layer-2 reachability check.
    Returns True if an ARP reply is received.
    This works even when PROFINET DCP is blocked or unavailable.
    """
    try:
        from scapy.all import ARP
    except ImportError:
        return False

    found: list = []

    def _handler(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:   # ARP reply
            found.append(pkt)

    bpf = f"arp and src host {dst_ip}"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handler, store=False)
    sniffer.start()
    time.sleep(0.20)

    from scapy.all import ARP
    arp_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) /
               ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                   hwdst="00:00:00:00:00:00", pdst=dst_ip))
    sendp(arp_req, iface=iface, verbose=False)
    log.debug("ARP who-has %s tell %s", dst_ip, src_ip)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        sniffer.stop()
    except Exception:
        pass

    if found:
        reply_mac = found[0][ARP].hwsrc
        log.info("ARP reply from %s is-at %s — basic IP reachability confirmed",
                 dst_ip, reply_mac)
        if reply_mac.lower() != TARGET_MAC.lower():
            log.warning("  ARP MAC mismatch! Expected %s, got %s — check for IP conflict",
                        TARGET_MAC, reply_mac)
        return True
    else:
        log.warning("ARP ping to %s timed out — no IP reachability", dst_ip)
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# IO Controller
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class PNIOController:
    """
    PROFINET IO Controller for TeSys Tera.

    run() executes the full connection sequence then cyclic exchange:
      seq=0  AR Connect  (no BIND — DCE/RPC v4 CL does not need it)
      seq=1  PrmEnd
      seq=2  ApplicationReady
      seq≥3  Optional acyclic reads (I&M0, diagnostics, …)
      RT     Cyclic IO loop
    """

    def __init__(self):
        self.wire_profile = DEFAULT_WIRE_PROFILE
        self.ar_uuid   = uuid.uuid4()
        self.act_uuid  = self._new_activity_uuid(self.wire_profile)
        self.seq_num   = 0
        self.process_subslot = DEFAULT_PROCESS_SUBSLOT
        self.session_key = DEFAULT_SESSION_KEY
        self.obj_uuid = PNIO_CM_OBJ_UUID
        self.frame_id_in = self.wire_profile.frame_id_in
        self.frame_id_out = self.wire_profile.frame_id_out
        self.rt_frame_id_out = self.wire_profile.rt_output_frame_id or self.wire_profile.frame_id_out

        self._out_data = b'\x00' * OUTPUT_LEN
        self._out_lock = threading.Lock()

        self.xport: Optional[ScapyTransport] = None
        self._sport = None
        self._init_transport(self._select_sport(self.wire_profile))

        log.info("══════════════════════════════════════════")
        log.info("PROFINET Controller")
        log.info("  Target     : %s  %s", TARGET_IP, TARGET_MAC)
        log.info("  Controller : %s  %s", CONTROLLER_IP, CONTROLLER_MAC)
        log.info("  Object UUID: %s", self.obj_uuid)
        log.info("  AR UUID    : %s", self.ar_uuid)
        log.info("  Activity   : %s", self.act_uuid)
        log.info("  IFACE      : %s", SCAPY_IFACE)
        log.info("══════════════════════════════════════════")

    # ── internal ─────────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        s = self.seq_num
        self.seq_num += 1
        return s

    @staticmethod
    def _new_activity_uuid(profile: WireProfile) -> uuid.UUID:
        if profile.use_uuid1_activity:
            node = int(CONTROLLER_MAC.replace(":", ""), 16)
            return uuid.uuid1(node=node)
        return uuid.uuid4()

    @staticmethod
    def _select_sport(profile: WireProfile) -> int:
        if profile.use_ephemeral_sport:
            return random.randint(49152, 65535)
        return PNIO_UDP_PORT

    def _init_transport(self, sport: int) -> None:
        if self.xport is not None:
            self.xport.close()
        self.xport = ScapyTransport(
            iface=SCAPY_IFACE,
            src_mac=CONTROLLER_MAC, src_ip=CONTROLLER_IP,
            dst_mac=TARGET_MAC, dst_ip=TARGET_IP,
            sport=sport, dport=PNIO_UDP_PORT,
        )
        self._sport = sport

    def _send(self, opnum: int, stub: bytes, label: str,
              timeout: float = 3.0) -> Optional[bytes]:
        if self.xport is None:
            self._init_transport(PNIO_UDP_PORT)
        pkt = build_request(
            seq_num  = self._next_seq(),
            opnum    = opnum,
            obj_uuid = self.obj_uuid,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
            wire_profile=self.wire_profile,
        )
        resp = self.xport.send_recv(pkt, label, timeout)
        if resp is not None and resp[1] != PKT_RESPONSE:
            log.error("%s: unexpected pkt_type 0x%02x", label, resp[1])
            return None
        return resp

    # ── AR establishment ─────────────────────────────────────────────────────

    def step_ar_connect(self) -> bool:
        """
        IODConnectReq — opnum 0, seq_num MUST be 0.

        No BIND phase precedes this call.  DCE/RPC v4 CL does not use BIND.
        Any packet sent before Connect would consume seq=0, causing the device
        to treat Connect (arriving as seq=1) as a retransmit from a dead client
        and locking with nca_wrong_boot_time.  [FIX O]
        """
        log.info("── AR Connect (opnum=%d, seq=%d) ──", OP_CONNECT, self.seq_num)
        stub = build_connect_stub(
            self.ar_uuid, CONTROLLER_MAC, CONTROLLER_STATION_NAME, INPUT_LEN, OUTPUT_LEN,
            subslot=self.process_subslot, session_key=self.session_key,
            wire_profile=self.wire_profile)
        resp = self._send(OP_CONNECT, stub, "Connect")
        if resp is None:
            return False

        # ── Decode DCE/RPC packet type ─────────────────────────────────────
        rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
        if rpc_ptype == 0x06:
            # DCE/RPC REJECT — device actively refused the request.
            # After two consecutive AlarmCR errors the device switches from
            # returning a PNIO error response (ptype=0x02) to issuing a
            # DCE/RPC REJECT (ptype=0x06).  This means the ghost AR is very
            # firmly locked.  Only a hard power cycle will clear it.
            reject_status = struct.unpack_from(">I", resp, 8)[0] if len(resp) > 12 else 0
            log.error("    DCE/RPC REJECT (ptype=0x06) from device — status=0x%08x", reject_status)
            log.error("    ══════════════════════════════════════════════════")
            log.error("    GHOST AR LOCK — device has a locked Application Relationship")
            log.error("    from a previous session that is blocking all new connections.")
            log.error("    ")
            log.error("    ▶  REQUIRED ACTION: HARD POWER CYCLE the TeSys Tera")
            log.error("    ▶  Physically unplug the device's power cable for 15 seconds.")
            log.error("    ▶  A software restart is NOT sufficient.")
            log.error("    ▶  After power-on, wait 10 s then rerun this script.")
            log.error("    ══════════════════════════════════════════════════")
            return False

        if rpc_ptype != 0x02:
            log.error("    Unexpected RPC ptype=0x%02x (expected 0x02=Response)", rpc_ptype)
            return False

        # ── Decode PNIO error status from ConnectRes stub ──────────────────
        stub_body = resp[80:]
        log.debug("    stub[0:24]: %s", stub_body[:24].hex())

        if len(stub_body) >= 4:
            err_status = struct.unpack_from(">I", stub_body, 0)[0]
            if err_status != 0:
                ec  = (err_status >> 24) & 0xFF
                ed  = (err_status >> 16) & 0xFF
                ec1 = (err_status >> 8)  & 0xFF
                ec2 =  err_status        & 0xFF
                EC1_NAMES = {
                    0x81: "AlarmCR resource locked (ghost AR)",
                    0x82: "IOCR config rejected",
                    0x83: "AR properties rejected",
                    0x84: "Submodule mismatch",
                    0x85: "AR out of resources",
                    0xfe: "nca_wrong_boot_time (ghost AR lock)",
                }
                ec1_name = EC1_NAMES.get(ec1, "unknown")
                log.error("    ConnectRes PNIO error: 0x%02x%02x%02x%02x "
                          "(ErrorCode=0x%02x  Decode=0x%02x  Code1=0x%02x[%s]  Code2=0x%02x)",
                          ec, ed, ec1, ec2, ec, ed, ec1, ec1_name, ec2)
                if ec1 == 0x81:
                    log.error("    ══════════════════════════════════════════════════")
                    log.error("    GHOST AR LOCK — the device already has an AlarmCR")
                    log.error("    resource allocated from a previous session.")
                    log.error("    Our AlarmCR parameters are correct (verified against")
                    log.error("    reference pcap byte-for-byte). The device simply")
                    log.error("    cannot accept a new connection while it holds the")
                    log.error("    ghost AR.")
                    log.error("    ")
                    log.error("    ▶  REQUIRED ACTION: HARD POWER CYCLE the TeSys Tera")
                    log.error("    ▶  Physically unplug the device's power cable for 15 s.")
                    log.error("    ▶  A software restart is NOT sufficient to clear ghost ARs.")
                    log.error("    ▶  After power-on, wait 10 s then rerun immediately.")
                    log.error("    ══════════════════════════════════════════════════")
                elif ec1 == 0xfe or (err_status & 0xFFFF) == 0x000e:
                    log.error("    Ghost AR lock — POWER-CYCLE TeSys Tera (10s off)")
                return False

        iod_len = struct.unpack_from("<I", stub_body, 4)[0] if len(stub_body) >= 8 else 0
        if iod_len == 0 and len(stub_body) < 30:
            log.error("    ConnectRes: zero IOD data length — device silently rejected connect")
            log.debug("    Full stub: %s", stub_body.hex())
            return False

        log.info("    ConnectRes OK  (%d bytes, IOD_len=%d)", len(resp), iod_len)
        return True

    def step_prm_end(self) -> bool:
        """IODControlReq PrmEnd — opnum 2, ControlCommand=0x0008. [FIX G/H/I]"""
        log.info("── PrmEnd (opnum=%d, cmd=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_PRM_END, self.seq_num)
        resp = self._send(OP_CONTROL, build_control_stub(
            self.ar_uuid, CTRL_PRM_END, session_key=self.session_key),
                          "PrmEnd")
        if resp is None:
            return False
        log.info("    PrmEndRes OK")
        return True

    def step_application_ready(self) -> bool:
        """IODControlReq ApplicationReady — opnum 2, ControlCommand=0x0010. [FIX J/K/I]"""
        log.info("── ApplicationReady (opnum=%d, cmd=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_APP_READY, self.seq_num)
        resp = self._send(OP_CONTROL, build_control_stub(
            self.ar_uuid, CTRL_APP_READY, session_key=self.session_key),
                          "ApplicationReady")
        if resp is None:
            return False
        log.info("    ApplicationReadyRes OK — IO data exchange is now ACTIVE")
        return True

    # ── Acyclic services ─────────────────────────────────────────────────────

    def acyclic_read(self, slot: int = 1, subslot: Optional[int] = None,
                     index: int = 0xF830, max_len: int = 0x8000) -> Optional[bytes]:
        """
        IODReadReq (opnum 3).

        Useful record indices:
          0xF830  I&M 0 — manufacturer/order/serial/revision
          0xF831  I&M 1 — installation tag
          0x8028  PDPortDataReal — port status
          0xB081  Diagnosis
        """
        if subslot is None:
            subslot = self.process_subslot
        log.info("── Acyclic Read  slot=%d sub=0x%04x idx=0x%04x seq=%d ──",
                 slot, subslot, index, self.seq_num)
        stub = build_read_stub(self.ar_uuid, slot, subslot, index, max_len)
        resp = self._send(OP_READ, stub, "Read", timeout=5.0)
        if resp is None:
            return None
        # IODReadRes header: SeqNum(2)+Pad(2)+ARUUID(16)+API(4)+Slot(2)+Sub(2)
        #                    +Pad(2)+Index(2)+RecDataLen(4)+TargetARUUID(16)+Pad(20)
        hdr_len = 2 + 2 + 16 + 4 + 2 + 2 + 2 + 2 + 4 + 16 + 20   # = 76
        stub_off = 80 + hdr_len
        rec_len  = struct.unpack_from(">I", resp, 80 + 2 + 2 + 16 + 4 + 2 + 2 + 2 + 2)[0]
        record   = resp[stub_off: stub_off + rec_len] if len(resp) >= stub_off + rec_len else resp[stub_off:]
        log.info("    Read returned %d bytes", len(record))
        log.debug("    data[0:32]: %s", record[:32].hex())
        return record

    def acyclic_write(self, data: bytes,
                      slot: int = 1, subslot: Optional[int] = None,
                      index: int = 0x0000) -> bool:
        """IODWriteReq (opnum 4)."""
        if subslot is None:
            subslot = self.process_subslot
        log.info("── Acyclic Write  slot=%d sub=0x%04x idx=0x%04x  %d bytes  seq=%d ──",
                 slot, subslot, index, len(data), self.seq_num)
        stub = build_write_stub(self.ar_uuid, slot, subslot, index, data)
        resp = self._send(OP_WRITE, stub, "Write", timeout=5.0)
        if resp is None:
            return False
        log.info("    WriteRes OK")
        return True

    # ── Cyclic exchange ──────────────────────────────────────────────────────

    def set_output(self, data: bytes):
        """Thread-safe update of cyclic output data (controller → device)."""
        if len(data) != OUTPUT_LEN:
            raise ValueError(f"output must be {OUTPUT_LEN} bytes, got {len(data)}")
        with self._out_lock:
            self._out_data = bytes(data)

    def _tx_loop(self, stop: threading.Event):
        """Background: send cyclic output RT frames at 32 ms intervals."""
        cycle = 0
        log.debug("Cyclic TX thread started")
        while not stop.is_set():
            cycle = (cycle + 1) & 0xFFFF
            with self._out_lock:
                out = self._out_data
            try:
                if self.wire_profile.rt_send_tagged:
                    frame = build_output_rt_frame(
                        out, cycle, CONTROLLER_MAC, TARGET_MAC,
                        frame_id_out=self.rt_frame_id_out,
                        data_total_len=self.wire_profile.rt_output_total_len,
                        data_offset=self.wire_profile.rt_output_data_offset,
                        iops_positions=self.wire_profile.rt_output_iops_positions,
                        iops_value=self.wire_profile.rt_iops_value,
                        tagged=True,
                    )
                    sendp(frame, iface=SCAPY_IFACE, verbose=False)
                if self.wire_profile.rt_send_untagged:
                    frame = build_output_rt_frame(
                        out, cycle, CONTROLLER_MAC, TARGET_MAC,
                        frame_id_out=self.rt_frame_id_out,
                        data_total_len=self.wire_profile.rt_output_total_len,
                        data_offset=self.wire_profile.rt_output_data_offset,
                        iops_positions=self.wire_profile.rt_output_iops_positions,
                        iops_value=self.wire_profile.rt_iops_value,
                        tagged=False,
                    )
                    sendp(frame, iface=SCAPY_IFACE, verbose=False)
            except Exception as e:
                log.warning("TX error: %s", e)
            stop.wait(0.032)

    def read_cyclic_data(self, duration_s: float = CYCLIC_DURATION_S,
                         stop_tx: Optional[threading.Event] = None):
        """
        Sniff cyclic input RT frames for `duration_s` seconds.

        If `stop_tx` is provided the TX thread is already running (started
        immediately after ConnectRes to beat the device watchdog).  Otherwise
        this method starts its own TX thread — kept for backward compatibility.
        """
        log.info("══ Cyclic exchange  %.0f s ══", duration_s)

        _own_stop = None
        if stop_tx is None:
            # Fallback: caller didn't pre-start TX — start it now.
            # NOTE: this is the slow path that caused the watchdog issue in v7.
            _own_stop = threading.Event()
            stop_tx   = _own_stop
            tx_thr    = threading.Thread(target=self._tx_loop, args=(stop_tx,), daemon=True)
            tx_thr.start()
            log.debug("Cyclic TX thread started (fallback — prefer pre-start after ConnectRes)")
        else:
            log.debug("Cyclic RX: using pre-started TX thread")

        # ── FIX: BPF must filter by source MAC ────────────────────────────────
        # The previous BPF "ether proto 0x8892 or (vlan and ether proto 0x8892)"
        # matched ALL PROFINET frames on the wire — including our OWN sent frames
        # which Npcap echoes back through the loopback path.  All 2546 "captured"
        # frames in v7 were our own TX.  Adding "ether src TARGET_MAC" ensures we
        # only capture frames that originated from the device.
        bpf = (f"ether src {TARGET_MAC} and "
               f"(ether proto 0x{PROFINET_ETYPE:04x} or "
               f"(vlan and ether proto 0x{PROFINET_ETYPE:04x}))")
        log.info("Sniffing: iface='%s'  filter='%s'", SCAPY_IFACE, bpf)

        count = 0
        frame_ids_seen: dict = {}

        def _rx_handler(frm):
            nonlocal count
            if not frm.haslayer(Ether):
                return
            raw = bytes(frm)
            frame_ids_seen_local = frame_ids_seen  # closure

            frame_ids = self.wire_profile.rt_input_frame_ids or [self.frame_id_in]
            inp = parse_input_rt_frame(
                raw, INPUT_LEN,
                frame_id_in=frame_ids,
                data_total_len=self.wire_profile.rt_input_total_len,
                data_offset=self.wire_profile.rt_input_data_offset,
            )
            if inp is None:
                # Tally unexpected FrameIDs for diagnostics
                try:
                    off = 12
                    if raw[12:14] == b'\x81\x00':
                        off += 4
                    if len(raw) >= off + 4:
                        fid = struct.unpack_from(">H", raw, off + 2)[0]
                        frame_ids_seen_local[fid] = frame_ids_seen_local.get(fid, 0) + 1
                except Exception:
                    pass
                return
            count += 1
            d = decode_tesys_input(inp)
            log.info("  [%4d]  V=%6.1f V  I=%5.1f %%FLC  "
                     "state=0x%02x  trip=0x%02x  thermal=%d  P=%.3f kW",
                     count, d["voltage_V"], d["current_pct_flc"],
                     d["motor_state"], d["last_trip_cause"],
                     d["thermal_state"], d["power_kW"])

        try:
            sniffer = AsyncSniffer(
                iface=SCAPY_IFACE, filter=bpf,
                prn=_rx_handler, store=False,
                timeout=duration_s,
            )
            sniffer.start()
            sniffer.join()
        except Exception as e:
            log.error("Scapy sniff error: %s", e)
            log.error("Verify SCAPY_IFACE GUID and that Npcap is installed.")
        finally:
            if _own_stop is not None:
                _own_stop.set()

        log.info("Cyclic complete — %d valid input frames received", count)
        if count == 0:
            log.warning("Zero input frames.  Diagnostics:")
            log.warning("  Expected FrameID=0x%04x from %s",
                        self.frame_id_in, TARGET_MAC)
            if frame_ids_seen:
                top = ", ".join(f"0x{k:04x}({v})" for k, v in
                                sorted(frame_ids_seen.items(), key=lambda x: -x[1])[:6])
                log.warning("  FrameIDs seen from device: %s", top)
                log.warning("  → Device IS sending PROFINET but FrameID doesn't match")
                log.warning("    Update CMD_FRAME_ID_IN constant to match the device's FrameID")
            else:
                log.warning("  No PROFINET frames captured from %s at all", TARGET_MAC)
                log.warning("  Possible causes:")
                log.warning("    1. Device watchdog fired — TX started too late")
                log.warning("    2. AR not fully established (check PrmEnd/AppReady logs)")
                log.warning("    3. Wireshark confirm: does device send 0x8892 frames?")

    # ── Main run sequence ────────────────────────────────────────────────────

    def run(self):
        """Full AR establishment + cyclic exchange."""
        # Pre-flight: verify scapy is available
        if not SCAPY_OK:
            log.error("scapy is not installed.  Run:  pip install scapy")
            return

        # ── FIX 3: DCP Identify + ARP pre-flight ─────────────────────────────
        log.info("── DCP Identify pre-flight ──")
        list_interfaces()

        if SKIP_DCP_PREFLIGHT:
            log.warning("SKIP_DCP_PREFLIGHT=True — skipping DCP check, proceeding to AR Connect")
        else:
            dcp_ok = dcp_identify(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
            if not dcp_ok:
                # DCP failed — try ARP ping as a supplementary check
                log.info("── ARP ping fallback check ──")
                arp_ok = arp_ping(SCAPY_IFACE, CONTROLLER_MAC, CONTROLLER_IP,
                                  TARGET_IP, timeout=2.0)
                if arp_ok:
                    # ── KEY FIX ───────────────────────────────────────────────
                    # Device IS reachable at Layer 2 (ARP answered). DCP silence
                    # means it is holding a ghost AR from a previous session —
                    # the PROFINET stack is busy and ignores DCP requests.
                    # Do NOT abort: proceed to AR Connect.  Two outcomes:
                    #   (a) Device accepts the new Connect and clears the ghost AR.
                    #   (b) Device returns DCE/RPC fault 0x1c00000e
                    #       (nca_wrong_boot_time = AR still locked) → we will
                    #       print a "power-cycle required" message and stop.
                    # Aborting here would never make progress.
                    log.warning(
                        "DCP Identify failed but ARP ping succeeded — device IS alive.\n"
                        "  Likely cause: ghost AR lock from a previous session.\n"
                        "  Proceeding to AR Connect to attempt displacement.\n"
                        "  If Connect returns fault 0x1c00000e, POWER-CYCLE the\n"
                        "  TeSys Tera (10 s off) and rerun."
                    )
                    # fall through to AR Connect
                else:
                    log.error(
                        "Both DCP Identify and ARP ping failed.\n"
                        "  The device is NOT reachable at Layer 2.  Check:\n"
                        "  (1) Ethernet cable / switch port between PC NIC and TeSys Tera\n"
                        "  (2) TeSys Tera is powered on (LEDs should show RUN or FAULT)\n"
                        "  (3) SCAPY_IFACE GUID — correct one is marked ◄ USE THIS above\n"
                        "  (4) No VLAN or managed-switch port isolation\n"
                        "  Once connectivity is restored, rerun the script."
                    )
                    return   # genuinely unreachable — abort
            time.sleep(0.10)

        # seq=0  AR Connect  (no BIND — would steal seq=0)  [FIX O]
        # Try compatibility profiles for TeSys firmware variants.
        # Some devices expect legacy subslot/session-key combinations.
        mac_uuid = uuid.UUID(
            f"dea00000-6c97-11d1-8271-{TARGET_MAC.replace(':', '').lower()}")
        vendor_uuid = uuid.UUID("dea00000-6c97-11d1-8271-155915030001")
        epm_uuid = query_epm_object_uuid(TARGET_IP, timeout=4.0)
        if epm_uuid is not None:
            log.info("EPM resolved device Object UUID: %s", epm_uuid)
        else:
            log.warning("EPM object UUID lookup unavailable (TCP/135 not responding)")

        # v9: Only use COMMANDER_WIRE_PROFILE (flags1=0x20, len=466).
        # The log confirms the device responds ONLY to this wire format.
        # All DEFAULT_WIRE_PROFILE variants (flags1=0x83, len=336) are silently
        # ignored by this device — removed to avoid wasting 24 seconds.
        profiles = [
            ("cmd-capture",    PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE),
            ("cmd-capture-s1", PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE),
            ("cmd-standard",   PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE),
            ("cmd-standard-s1",PNIO_CM_OBJ_UUID,  0x0001, 0x0001, COMMANDER_WIRE_PROFILE),
        ]
        if epm_uuid is not None:
            profiles.insert(0, ("epm-cmd", epm_uuid, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE))
        for attempt, (pname, obj_uuid, subslot, sess_key, wprof) in enumerate(profiles, start=1):
            self.wire_profile = wprof
            self.obj_uuid = obj_uuid
            self.process_subslot = subslot
            self.session_key = sess_key
            self.seq_num = 0
            self.ar_uuid = uuid.uuid4()
            self.act_uuid = self._new_activity_uuid(self.wire_profile)
            self.frame_id_in = self.wire_profile.frame_id_in
            self.frame_id_out = self.wire_profile.frame_id_out
            self.rt_frame_id_out = self.wire_profile.rt_output_frame_id or self.wire_profile.frame_id_out
            self._init_transport(self._select_sport(self.wire_profile))
            log.info(
                "Connect profile %d/%d: %s (wire=%s, obj=%s, subslot=0x%04x, session=0x%04x, ar=%s, sport=%s)",
                attempt, len(profiles), pname, self.wire_profile.name, self.obj_uuid,
                self.process_subslot, self.session_key, self.ar_uuid, self._sport)
            if self.step_ar_connect():
                break
            if attempt < len(profiles):
                log.warning("Connect attempt %d/%d failed — retrying in 3 s …",
                            attempt, len(profiles))
                time.sleep(3.0)
        else:
            log.error("AR Connect failed after %d attempts — aborting", len(profiles))
            log.error("Power-cycle TeSys Tera, wait 10 s, then retry.")
            return

        # ── FIX: Start cyclic TX IMMEDIATELY after ConnectRes ─────────────────
        # Root cause of "0 valid input frames": the device watchdog is
        # WDF × SendClock × ReductionRatio = 3 × 128 × 31.25µs = 96 ms.
        # If no cyclic OUTPUT frame arrives within 96 ms the device enters
        # DATA_LOST mode and stops sending cyclic INPUT.
        # The reference pcap shows the real controller starts TX at pkt#312
        # (within ~10 ms of ConnectRes at pkt#310).  Our v7 waited until after
        # PrmEnd + AppReady + acyclic read — roughly 500 ms — so the watchdog
        # fired 5× before our first frame ever left the wire.
        stop_tx = threading.Event()
        tx_thr  = threading.Thread(target=self._tx_loop, args=(stop_tx,), daemon=True)
        tx_thr.start()
        log.info("Cyclic TX started immediately after ConnectRes (WDT=%d ms)",
                 self.wire_profile.watchdog_factor *
                 self.wire_profile.send_clock_factor *
                 self.wire_profile.reduction_ratio // 32)

        time.sleep(0.05)   # one TX cycle before the next DCE/RPC call

        # seq=1  PrmEnd
        if not self.step_prm_end():
            log.error("PrmEnd failed — aborting")
            stop_tx.set(); tx_thr.join(timeout=2.0)
            return
        time.sleep(0.05)

        # seq=2  ApplicationReady
        if not self.step_application_ready():
            log.error("ApplicationReady failed — aborting")
            stop_tx.set(); tx_thr.join(timeout=2.0)
            return
        time.sleep(0.05)

        # seq=3  Acyclic: read I&M0 identity
        log.info("Reading I&M0 identity record (slot=0, sub=1, idx=0xF830)…")
        im0 = self.acyclic_read(slot=0, subslot=1, index=0xF830)
        if im0 and len(im0) >= 54:
            vid       = struct.unpack_from(">H", im0, 0)[0]
            order_id  = im0[2:22].decode("ascii", errors="replace").strip()
            serial    = im0[22:42].decode("ascii", errors="replace").strip()
            hw_rev    = struct.unpack_from(">H", im0, 42)[0]
            sw_rev    = im0[44:54].decode("ascii", errors="replace")
            log.info("  VendorID=0x%04x  OrderID='%s'  Serial='%s'  HW=%d  SW='%s'",
                     vid, order_id, serial, hw_rev, sw_rev)

        # Cyclic RX exchange (TX is already running, pass the existing stop event)
        self.read_cyclic_data(stop_tx=stop_tx)
        stop_tx.set()
        tx_thr.join(timeout=2.0)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Self-tests (run without hardware)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_self_tests():
    """Validate all packet structures without sending anything to the network."""
    failures = []
    ar_uuid  = uuid.UUID("12345678-1234-5678-1234-567812345678")
    act_uuid = uuid.uuid4()

    def ok(name):
        log.info("PASS [%s]", name)

    def fail(name, msg):
        failures.append(f"[{name}] {msg}")
        log.error("FAIL [%s] %s", name, msg)

    def chk(name, got, expected, fmt="{}"):
        if got == expected:
            ok(name)
        else:
            fail(name, f"got {fmt.format(got)}, want {fmt.format(expected)}")

    # ── CL-PDU header ──────────────────────────────────────────────────────
    pkt = build_request(0, OP_CONNECT, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'',
                        wire_profile=DEFAULT_WIRE_PROFILE)
    chk("hdr.rpc_vers",    pkt[0],  4)
    chk("hdr.pkt_type",   pkt[1],  PKT_REQUEST, "0x{:02x}")
    chk("hdr.flags1",     pkt[2],  PFC_FIRST | PFC_LAST | PFC_OBJ_UUID, "0x{:02x}")
    chk("hdr.flags2",     pkt[3],  0)
    chk("hdr.drep0",      pkt[4],  0x10, "0x{:02x}")
    chk("hdr.obj_uuid",   _pu(pkt, 8),  PNIO_CM_OBJ_UUID)
    chk("hdr.if_uuid",    _pu(pkt, 24), PNIO_CM_IF_UUID)
    chk("hdr.if_version", struct.unpack_from("<I", pkt, 60)[0], 0x00010000, "0x{:08x}")
    chk("hdr.seq_num",    struct.unpack_from("<I", pkt, 64)[0], 0)
    chk("hdr.opnum",      struct.unpack_from("<H", pkt, 68)[0], OP_CONNECT)

    for op, name in [(OP_CONTROL,"control"),(OP_READ,"read"),(OP_WRITE,"write")]:
        p = build_request(1, op, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'',
                          wire_profile=DEFAULT_WIRE_PROFILE)
        chk(f"hdr.opnum_{name}", struct.unpack_from("<H",p,68)[0], op)

    # ── ARBlock ────────────────────────────────────────────────────────────
    ar = build_ar_block(ar_uuid, CONTROLLER_MAC, CONTROLLER_STATION_NAME)
    chk("ar.block_type",  struct.unpack_from(">H", ar, 0)[0], BT_AR_REQ, "0x{:04x}")
    # body starts at byte 6 (type2+len2+ver2)
    # ARType(2)+ARUUID(16)+SessionKey(2)+MAC(6) = 26 bytes before CMInitiatorObjectUUID
    cm_obj_off = 6 + 2 + 16 + 2 + 6
    chk("ar.cm_init_obj", _pu(ar, cm_obj_off), PNIO_CTRL_OBJ_UUID)         # FIX E
    props_off  = cm_obj_off + 16
    chk("ar.ar_props",    struct.unpack_from(">I", ar, props_off)[0], 0,    # FIX C
        "0x{:08x}")
    timeout_off = props_off + 4
    chk("ar.timeout_f",   struct.unpack_from(">H", ar, timeout_off)[0], 0x0064, "0x{:04x}")  # FIX D

    # ── IOCRBlock ──────────────────────────────────────────────────────────
    spec = IOCRSpec(IOCR_INPUT, 1, FRAME_ID_IN, INPUT_LEN + 1)
    iocr = build_iocr_block(spec)
    lt_off = 6 + 2 + 2         # block_env(6) + IOCRType(2) + IOCRRef(2)
    chk("iocr.lt_type",  struct.unpack_from(">H", iocr, lt_off)[0], PROFINET_ETYPE, "0x{:04x}")  # FIX F
    dl_off = lt_off + 2 + 4    # LT(2) + IOCRProperties(4)
    chk("iocr.data_len", struct.unpack_from(">H", iocr, dl_off)[0], INPUT_LEN + 1)

    # ── ExpectedSubmoduleBlock ────────────────────────────────────────────
    esm = build_expected_submodule_block(INPUT_LEN, OUTPUT_LEN)
    chk("esm.block_type", struct.unpack_from(">H", esm, 0)[0], BT_EXP_SUB, "0x{:04x}")
    # Find SubmoduleProperties: NumberOfAPIs(2)+API(4)+NumberOfMods(2)+Slot(2)+ModIdent(4)+ModProps(2)+NumSub(2)+Subslot(2)+SubIdent(4)
    subprops_off = 6 + 2 + 4 + 2 + 2 + 4 + 2 + 2 + 2 + 4
    chk("esm.sub_props",  struct.unpack_from(">H", esm, subprops_off)[0], 0x0003, "0x{:04x}")  # FIX NEW-1
    # DataDescription INPUT immediately follows SubmoduleProperties
    dd_in_off = subprops_off + 2
    chk("esm.dd_in_dir",  struct.unpack_from(">H", esm, dd_in_off)[0], 0x0001, "0x{:04x}")
    chk("esm.dd_in_len",  struct.unpack_from(">H", esm, dd_in_off + 2)[0], INPUT_LEN)
    dd_out_off = dd_in_off + 2 + 2 + 1 + 1    # dir(2)+len(2)+IOCS(1)+IOPS(1)
    chk("esm.dd_out_dir", struct.unpack_from(">H", esm, dd_out_off)[0], 0x0002, "0x{:04x}")  # FIX NEW-2
    chk("esm.dd_out_len", struct.unpack_from(">H", esm, dd_out_off + 2)[0], OUTPUT_LEN)

    # ── Control stubs ──────────────────────────────────────────────────────
    for cmd, cname in [(CTRL_PRM_END,"prm_end"),(CTRL_APP_READY,"app_ready")]:
        stub = build_control_stub(ar_uuid, cmd)
        chk(f"ctrl.{cname}.type", struct.unpack_from(">H",stub,0)[0], BT_IOCTRL_REQ, "0x{:04x}")
        # After type(2)+len(2)+ver(2)+pad(2) = 8 bytes → ARUUID
        chk(f"ctrl.{cname}.ar_uuid",  _pu(stub, 8), ar_uuid)   # FIX I: padding present
        cmd_off = 8 + 16 + 2 + 2      # header(8)+ARUUID(16)+SessionKey(2)+Padding(2)
        chk(f"ctrl.{cname}.cmd", struct.unpack_from(">H",stub,cmd_off)[0], cmd, "0x{:04x}")  # FIX H/K

    # Request uses opnum=2 for both control operations
    for cmd, cname in [(CTRL_PRM_END,"prm_end_opnum"),(CTRL_APP_READY,"app_ready_opnum")]:
        stub = build_control_stub(ar_uuid, cmd)
        req  = build_request(1, OP_CONTROL, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, stub,
                             wire_profile=DEFAULT_WIRE_PROFILE)
        chk(f"req.{cname}", struct.unpack_from("<H",req,68)[0], OP_CONTROL)  # FIX G/J

    # ── AlarmCR byte-exact test (verified against reference pcap) ─────────────
    alarm_body = build_alarm_cr_block()
    # Exact bytes from tesysprofinetdemo.pcapng AlarmCRBlockReq offset 356:
    # BlockType=0x0103 BlockLen=22(0x0016) BVH=1 BVL=0 + 20-byte body
    REF_ALARM = bytes.fromhex("010300160100" "000188920000000000010003000000c8c000a000")
    chk("alarm.full_block", alarm_body.hex(), REF_ALARM.hex())

    # ── Summary ────────────────────────────────────────────────────────────
    total = sum(1 for line in [
        "hdr.rpc_vers","hdr.pkt_type","hdr.flags1","hdr.flags2","hdr.drep0",
        "hdr.obj_uuid","hdr.if_uuid","hdr.if_version","hdr.seq_num","hdr.opnum",
        "hdr.opnum_control","hdr.opnum_read","hdr.opnum_write",
        "ar.block_type","ar.cm_init_obj","ar.ar_props","ar.timeout_f",
        "iocr.lt_type","iocr.data_len",
        "esm.block_type","esm.sub_props","esm.dd_in_dir","esm.dd_in_len",
        "esm.dd_out_dir","esm.dd_out_len",
        "ctrl.prm_end.type","ctrl.prm_end.ar_uuid","ctrl.prm_end.cmd",
        "ctrl.app_ready.type","ctrl.app_ready.ar_uuid","ctrl.app_ready.cmd",
        "req.prm_end_opnum","req.app_ready_opnum",
        "alarm.full_block",
    ])
    if failures:
        log.error("══ SELF-TEST: %d/%d FAILED ══", len(failures), total)
        for f in failures:
            log.error("  %s", f)
        sys.exit(1)
    log.info("All %d self-tests passed", total)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    log.info("PROFINET IO Controller — TeSys Tera")
    if not SCAPY_OK:
        log.error("scapy is required.  Install with:  pip install scapy")
        log.error("Also install Npcap from https://npcap.com (run as Administrator)")
        sys.exit(1)

    run_self_tests()

    ctrl = PNIOController()
    ctrl.run()


if __name__ == "__main__":
    main()
