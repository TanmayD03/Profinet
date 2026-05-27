#!/usr/bin/env python3
"""
PROFINET IO Controller ? TeSys Tera Motor Management Relay  [v10]
===========================================================
Transport: Scapy raw Ethernet for EVERYTHING (DCE/RPC + cyclic RT frames).
This bypasses the Windows networking stack, firewall, and routing table
completely ? which is why the UDP socket approach gets a timeout even
when the packet structure is perfectly correct.

Protocol sequence (all DCE/RPC v4, UDP port 34964, raw Ethernet):
  seq=0  IODConnectReq    (opnum 0) ? ConnectRes
  seq=1  IODControlReq    (opnum 2, ControlCommand=0x0008 PrmEnd) ? ControlRes
  seq=2  IODControlReq    (opnum 2, ControlCommand=0x0010 AppReady) ? ControlRes
  seq?3  IODReadReq/Res   (opnum 3) ? acyclic reads
  seq?3  IODWriteReq/Res  (opnum 4) ? acyclic writes
  RT     Cyclic output frames (Scapy raw, 32ms period)
  RT     Cyclic input  frames (Scapy sniff)

Hardware (from DCP discovery):
  Target     : 169.254.217.162  88:01:f9:35:d9:a2   tesys-tera-pn
  Controller : 169.254.0.100    18:3d:2d:61:f9:70
  Module 1   : 40 B input (device->ctrl), 4 B output (ctrl->device)

v5 ? Three root-cause fixes for the "TIMEOUT ? no response to Connect" error:

  FIX 1  ICMP Port Unreachable poisoning  ? most likely cause of the timeout
    When Scapy injects a raw UDP frame the device sends its DCE/RPC response
    back to CONTROLLER_IP:34964.  Because no OS process owns that UDP port,
    Windows immediately sends ICMP "Port Unreachable" back to the device.
    TeSys Tera interprets that as the controller going offline and silently
    aborts the AR ? which looks like a pure timeout on our end.
    Fix: ScapyTransport now binds a dummy UDP socket on port 34964 so that
    Windows never generates the ICMP.  (We still receive via raw sniffer.)

  FIX 2  Npcap sniffer startup race condition
    Npcap on Windows takes up to 150?200 ms to attach a BPF filter to the
    adapter driver.  The previous 50 ms delay meant the device's response
    could arrive before the sniffer was armed and be silently lost.
    Fix: startup delay raised to 200 ms.

  FIX 3  No Layer-2 connectivity check before DCE/RPC
    A DCP Identify probe (pure EtherType 0x8892, no IP) now runs before any
    DCE/RPC.  If the device doesn't answer DCP, the problem is the NIC /
    cable selection ? not the protocol ? and the script aborts early with a
    clear message.  list_interfaces() is also printed at startup to make it
    easy to identify the correct SCAPY_IFACE GUID.

Before running:
  1. Power-cycle TeSys Tera (10 s off) to clear any ghost AR lock
  2. Confirm ipconfig shows 169.254.0.100 on the correct NIC (same /16 subnet as device 169.254.217.162)
  3. Update SCAPY_IFACE below to match your NPF GUID:
       python -c "from scapy.all import get_if_list; print(get_if_list())"
     OR just run the script ? list_interfaces() now prints a table at startup.
  4. Run as Administrator (Npcap/WinPcap requires elevated privileges)
  5. Install scapy:  pip install scapy
"""

# ?? stdlib ???????????????????????????????????????????????????????????????????
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

# ?? scapy ????????????????????????????????????????????????????????????????????
try:
    from scapy.all import (
        AsyncSniffer, Ether, IP, UDP, ICMP, ARP, Dot1Q, Raw,
        sendp, get_if_hwaddr, conf as scapy_conf
    )
    scapy_conf.verb = 0          # suppress scapy noise
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ?? logging ??????????????????????????????????????????????????????????????????
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-5s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("PNIO")

# ??????????????????????????????????????????????????????????????????????????
# USER CONFIGURATION
# ??????????????????????????????????????????????????????????????????????????
TARGET_IP          = "169.254.220.165"
TARGET_MAC         = "82:01:fb:3b:dc:a5"
TARGET_SUBNET      = "255.255.0.0"      # link-local /16 after factory reset
CONTROLLER_IP      = "169.254.0.100"    # updated at runtime by _resolve_controller_ip()
CONTROLLER_MAC     = "18:3d:2d:61:f9:70"
# IMPORTANT: CMInitiatorStationName in ARBlock is the CONTROLLER name,
# not the device's NameOfStation.
CONTROLLER_STATION_NAME = "ctrl-pc"
INPUT_LEN          = 40        # process input bytes (device ? controller)
OUTPUT_LEN         = 4         # process output bytes (controller ? device)
CYCLIC_DURATION_S  = 60.0

# Set True to skip the DCP Identify pre-flight and go straight to AR Connect.
# Useful if the device is connected and responding but doesn't answer DCP
# (e.g. it already holds an AR with another controller).
SKIP_DCP_PREFLIGHT = False

# Windows NPF adapter GUID.  Find yours with:
#   python -c "from scapy.all import get_if_list; print(get_if_list())"
SCAPY_IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

# ??????????????????????????????????????????????????????????????????????????
# PROTOCOL CONSTANTS
# ??????????????????????????????????????????????????????????????????????????
PNIO_UDP_PORT   = 34964
PNIO_AR_SESSION_PORT = 49152   # Device's ephemeral AR session port (observed in demo pcap)
EPM_TCP_PORT    = 135
PROFINET_ETYPE  = 0x8892

# Ghost AR UUID from the Siemens PLC demo session (tesysprofinetdemo.pcapng [304]).
# The demo Release succeeded in RAM but the device NVM was not updated (firmware bug
# v000.000.005), so the AR resurfaces after every power cycle.
DEMO_GHOST_AR_UUID    = uuid.UUID("f9c6c366-7e9d-4aef-8f6a-3cd730f5afce")
DEMO_GHOST_AR_SESSKEY = 2

# Full session parameters from the Siemens PLC demo session (tesysprofinetdemo.pcapng).
# These are needed to spoof the original session context so the device accepts a Release.
# The device stores the CMInitiatorMACAddress and activity context from the original
# Connect; a Release coming from a different MAC/IP is rejected with Code1=0x81.
DEMO_SESSION_MAC      = "60:7d:09:5b:24:b6"   # Siemens PLC Ethernet MAC
DEMO_SESSION_IP       = "192.168.0.60"          # Siemens PLC IP address
DEMO_SESSION_SPORT    = 59981                   # PLC source UDP port (same for all ops)
DEMO_SESSION_ACT_UUID = uuid.UUID("e298926f-000e-1010-806c-607d095b24b6")  # DCE/RPC activity UUID
DEMO_SESSION_SEQ      = 3                       # seq_num used in the Release packet

# Object UUID of the device's Context Manager endpoint (Anybus/HMS stack)
PNIO_CM_OBJ_UUID  = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
# Interface UUID ? fixed by PROFINET standard
PNIO_CM_IF_UUID   = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
# Controller's own Object UUID ? placed in ARBlock.CMInitiatorObjectUUID
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
CMD_FRAME_ID_IN_ALT1   = 0xBC00   # alternative if ghost AR locked 0xBBF0
CMD_FRAME_ID_IN_ALT2   = 0xBC10   # second alternative
EPM_IF_UUID       = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")
NDR_SYNTAX_UUID   = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

# DCE/RPC v4 CL-PDU packet types  (byte 1 of 80-byte header)
PKT_REQUEST  = 0x00
PKT_RESPONSE = 0x02
PKT_FAULT    = 0x03
PKT_REJECT   = 0x06

# PFC flags  (byte 2)
PFC_FIRST    = 0x01
PFC_LAST     = 0x02
PFC_OBJ_UUID = 0x80   # Object UUID field is present and valid

# PROFINET CM opnums  (IEC 61158-6-10 ?6.3)
OP_CONNECT = 0
OP_RELEASE = 1
OP_READ    = 2   # IODReadReq
OP_WRITE   = 3   # IODWriteReq / IODWriteMultipleReq
OP_CONTROL = 4   # IODControlReq: PrmEnd + ApplicationReady

# IODControlReq ControlCommand bits  (IEC 61158-6-10 Table 566)
CTRL_PRM_END   = 0x0001   # bit 0 = end of parameterisation  (confirmed Tanmay pcap pkt 331)
CTRL_APP_READY = 0x0002   # bit 1 = controller is ready for data exchange
# Aliases used in spoof-connect code path
CTRL_CMD_PRM_END   = CTRL_PRM_END
CTRL_CMD_APP_READY = CTRL_APP_READY

# PROFINET block types
BT_AR_REQ      = 0x0101
BT_IOCR_REQ    = 0x0102
BT_ALARM_CR    = 0x0103
BT_EXP_SUB    = 0x0104
BT_IOCTRL_REQ  = 0x0110

IOCR_INPUT  = 0x0001
IOCR_OUTPUT = 0x0002
AR_IOCAR_SINGLE = 0x0001

FRAME_ID_IN  = 0x8000   # cyclic input frames  (device ? controller)
FRAME_ID_OUT = 0x8001   # cyclic output frames (controller ? device)
DEFAULT_SESSION_KEY = 0x0001
DEFAULT_PROCESS_SUBSLOT = 0x0001

FAULT_CODES = {
    0x1c010003: "nca_unk_if        ? wrong Object UUID (device endpoint not found)",
    0x1c010002: "nca_op_rng_error  ? opnum not registered on this interface",
    0x1c000009: "nca_s_fault_ill_inst ? malformed stub (block structure error)",
    0x1c000008: "nca_s_fault_cancel",
    0x1c010001: "nca_s_unsupported_type ? transfer syntax mismatch",
    0x1c00000e: "nca_wrong_boot_time ? ghost AR lock: POWER-CYCLE THE DEVICE",
}

# ??????????????????????????????????????????????????????????????????????????
# UUID helpers
# ??????????????????????????????????????????????????????????????????????????
def _u(u: uuid.UUID) -> bytes:
    """UUID ? 16-byte DCE/RPC little-endian wire encoding."""
    return u.bytes_le

def _pu(b: bytes, off: int = 0) -> uuid.UUID:
    """16 wire bytes ? UUID."""
    return uuid.UUID(bytes_le=b[off:off + 16])

# ??????????????????????????????????????????????????????????????????????????
# EPM lookup (DCE/RPC v5 over TCP/135) for dynamic Object UUID discovery
# ??????????????????????????????????????????????????????????????????????????
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

# ??????????????????????????????????????????????????????????????????????????
# DCE/RPC v4 CL-PDU builder
# ??????????????????????????????????????????????????????????????????????????
def build_request(seq_num: int,
                  opnum: int,
                  obj_uuid: uuid.UUID,
                  if_uuid: uuid.UUID,
                  act_uuid: uuid.UUID,
                  stub: bytes,
                  wire_profile: Optional["WireProfile"] = None) -> bytes:
    """
    Build a DCE/RPC v4 connectionless (CL) Request PDU.

    80-byte header layout ? all integers little-endian (drep[0]=0x10):
      [0]     rpc_vers   = 4
      [1]     pkt_type   = 0x00 (REQUEST)        ? byte 1, not byte 2
      [2]     flags1     = FIRST|LAST|OBJ_UUID   ? 0x83
      [3]     flags2     = 0
      [4-6]   drep[3]    = 0x10,0x00,0x00
      [7]     serial_hi  = 0
      [8-23]  object_uuid                        ? device checks this
      [24-39] if_uuid
      [40-55] act_uuid
      [56-59] server_boot = 0
      [60-63] if_version  = 0x00010000           ? v1.0 little-endian
      [64-67] seq_num                             ? 0 for Connect, +1 each call
      [68-69] opnum                               ? 0/2/3/4
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

# ??????????????????????????????????????????????????????????????????????????
# PROFINET block builder helpers
# ??????????????????????????????????????????????????????????????????????????
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

# Alternative IOCR blocks with different FrameIDs to bypass ghost AR frame-ID lock
CMD_IOCR_IN_BODY_HEX_ALT1 = (
    "00010001889200000002002dbc000080000800010000ffffffff00030003c000"
    "0000000000000001000000000004000000010000000080000001000080010002"
    "000100010003000100010001002c"
)
CMD_IOCR_IN_BODY_HEX_ALT2 = (
    "00010001889200000002002dbc100080000800010000ffffffff00030003c000"
    "0000000000000001000000000004000000010000000080000001000080010002"
    "000100010003000100010001002c"
)
CMD_IOCR_BLOCKS_ALT1 = [
    _block(BT_IOCR_REQ, bytes.fromhex(CMD_IOCR_IN_BODY_HEX_ALT1)),
    _block(BT_IOCR_REQ, bytes.fromhex(CMD_IOCR_OUT_BODY_HEX)),
]
CMD_IOCR_BLOCKS_ALT2 = [
    _block(BT_IOCR_REQ, bytes.fromhex(CMD_IOCR_IN_BODY_HEX_ALT2)),
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
    ARBlockReq  (0x0101) ? IEC 61158-6-10 ?6.3.5.1.1

    Bugs fixed vs previous versions:
      C:  ARProperties = 0x00000000  (was 0x00000001 = PullModule ? wrong mode)
      D:  CMInitiatorActivityTimeoutFactor = 0x0064  (was 0x8892 = ethertype!)
      E:  CMInitiatorObjectUUID = PNIO_CTRL_OBJ_UUID dea00002...
              (was PNIO_CM_IF_UUID dea00001... ? device's own UUID, not ours)
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

COMMANDER_WIRE_PROFILE_NO_ALARM = WireProfile(
    name="commander-no-alarm",
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

# Alternative-frame-ID profiles — use when ghost AR has locked CMD_FRAME_ID_IN (0xBBF0).
# The ghost AR occupies FrameID 0xBBF0; these profiles request 0xBC00/0xBC10 instead.
def _make_alt_fid_profile(name: str, frame_id: int, iocr_blocks_alt, include_alarm: bool):
    import dataclasses
    base = COMMANDER_WIRE_PROFILE if include_alarm else COMMANDER_WIRE_PROFILE_NO_ALARM
    return dataclasses.replace(
        base,
        name=name,
        frame_id_in=frame_id,
        iocr_blocks=iocr_blocks_alt,
        rt_input_frame_ids=[frame_id],
    )

COMMANDER_WIRE_PROFILE_ALT1 = _make_alt_fid_profile(
    "commander-alt1", CMD_FRAME_ID_IN_ALT1, CMD_IOCR_BLOCKS_ALT1, include_alarm=True)
COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM = _make_alt_fid_profile(
    "commander-alt1-no-alarm", CMD_FRAME_ID_IN_ALT1, CMD_IOCR_BLOCKS_ALT1, include_alarm=False)
COMMANDER_WIRE_PROFILE_ALT2 = _make_alt_fid_profile(
    "commander-alt2", CMD_FRAME_ID_IN_ALT2, CMD_IOCR_BLOCKS_ALT2, include_alarm=True)
COMMANDER_WIRE_PROFILE_ALT2_NO_ALARM = _make_alt_fid_profile(
    "commander-alt2-no-alarm", CMD_FRAME_ID_IN_ALT2, CMD_IOCR_BLOCKS_ALT2, include_alarm=False)

def build_iocr_block(spec: IOCRSpec) -> bytes:
    """
    IOCRBlockReq  (0x0102) ? IEC 61158-6-10 ?6.3.5.1.3

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
      NEW-1:  SubmoduleProperties was 0x0000 (NO_IO) ? now 0x0003 (INPUT_OUTPUT)
      NEW-2:  OUTPUT DataDescription block was missing entirely.
              Both INPUT and OUTPUT descriptions are required when a submodule
              has process data in both directions.
    """
    # SubmoduleDataDescription for INPUT (device ? controller)
    ddi  = struct.pack(">H", 0x0001)           # DataDirection = INPUT
    ddi += struct.pack(">H", in_len)           # SubmoduleDataLength
    ddi += struct.pack(">B", 1)               # LengthIOCS
    ddi += struct.pack(">B", 1)               # LengthIOPS

    # SubmoduleDataDescription for OUTPUT (controller ? device)
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
    AlarmCRBlockReq  (0x0103) ? alarm channel parameters.

    Values verified against reference pcap (tesysprofinetdemo.pcapng):
      REF body: 000188920000000000010003000000c8c000a000

    Previous v7 values vs corrected values:
      RTATimeoutFactor:    200  ? 1      (1 ? 1 ms = 1 ms, device requires minimum)
      LocalAlarmReference: 1   ? 0      (controller-assigned ref; device expects 0)
      AlarmCRTagHeaderHigh:0x0000 ? 0xc000  (VLAN priority bits for alarm frames)
      AlarmCRTagHeaderLow: 0x0000 ? 0xa000  (VLAN ID bits for alarm frames)
    These four mismatches caused the device to return PNIO error 0x010181db
    (ErrorCode1=0x81 = AlarmCR configuration error) in the ConnectRes stub,
    silently failing the connection while our code reported "ConnectRes OK".
    """
    body  = struct.pack(">H", 0x0001)         # AlarmCRType = Alarm CR
    body += struct.pack(">H", PROFINET_ETYPE) # LT          = 0x8892
    body += struct.pack(">I", 0x00000000)     # AlarmCRProperties
    body += struct.pack(">H", 1)              # RTATimeoutFactor  (1 ? 1 ms = 1 ms)
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
                       wire_profile: WireProfile = DEFAULT_WIRE_PROFILE,
                       include_alarm_cr: bool = True) -> bytes:
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
    stub = ar + b"".join(iocr_blocks) + esm
    if include_alarm_cr:
        stub += build_alarm_cr_block()
    if wire_profile.add_connect_prefix:
        blen = len(stub)
        prefix = struct.pack("<IIIII", blen + 0x2A, blen, blen + 0x2A, 0, blen)
        stub = prefix + stub
    return stub


def build_control_stub(ar_uuid: uuid.UUID, ctrl_cmd: int,
                       session_key: int = DEFAULT_SESSION_KEY) -> bytes:
    """
    IODControlReq stub (opnum 4) -- used for BOTH PrmEnd and ApplicationReady.

    Block structure (IEC 61158-6-10 ?6.3.10.1):
      BlockType    (2B): 0x0110
      BlockLength  (2B): 26  [= 2 + 24-byte body]
      Version      (2B): 1.0
      Padding      (2B): 0x0000  ? was MISSING in previous versions (bug I)
      ARUUID      (16B): LE
      SessionKey   (2B): 0x0001
      Padding      (2B): 0x0000
      ControlCommand (2B): 0x0001=PrmEnd  0x0002=AppReady  (confirmed Tanmay pcap pkt 331)
      ControlBlockProperties (2B): 0x0000

    opnum = 4 for both  (confirmed Tanmay pcap + ProfinetTools RPC.cs)
    """
    body  = struct.pack(">H", 0x0000)          # Padding  [FIX I]
    body += _u(ar_uuid)                         # ARUUID
    body += struct.pack(">H", session_key)      # SessionKey
    body += struct.pack(">H", 0x0000)          # Padding
    body += struct.pack(">H", ctrl_cmd)         # ControlCommand  [FIX H / FIX K]
    body += struct.pack(">H", 0x0000)          # ControlBlockProperties
    return _block(BT_IOCTRL_REQ, body)


def build_release_stub(ar_uuid: uuid.UUID, session_key: int = DEFAULT_SESSION_KEY) -> bytes:
    """
    Full stub (NDR prefix + IODControlReq block) for a PROFINET Release (opnum 1).

    Block type 0x0114 (IODControlReq Release) — verified from Tanmay pcap pkt 611/612.
    Layout matches pnio_spoof_release exactly.
    """
    body  = struct.pack(">H", 0x0000)
    body += _u(ar_uuid)
    body += struct.pack(">H", session_key)
    body += struct.pack(">H", 0x0000)
    body += struct.pack(">HH", 0x0004, 0x0000)
    block = _block(0x0114, body)
    blen  = len(block)
    return struct.pack("<IIIII", blen, blen, blen, 0, blen) + block


def build_read_stub(ar_uuid: uuid.UUID,
                    slot: int, subslot: int, index: int,
                    max_len: int = 0x8000) -> bytes:
    """IODReadReq stub (opnum 2)."""
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
    """IODWriteReq stub (opnum 3)."""
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

# ??????????????????????????????????????????????????????????????????????????
# Cyclic RT frame helpers
# ??????????????????????????????????????????????????????????????????????????

def build_output_rt_frame(out_data: bytes, cycle: int,
                           src_mac: str, dst_mac: str,
                           frame_id_out: int = FRAME_ID_OUT,
                           data_total_len: Optional[int] = None,
                           data_offset: int = 0,
                           iops_positions: Optional[list[int]] = None,
                           iops_value: int = 0x80,
                           tagged: bool = True):
    """
    Cyclic output frame (controller ? device).

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
             was 0x8001 (that's the output direction ? our own frames).
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

# ??????????????????????????????????????????????????????????????????????????
# Scapy transport layer ? replaces Python UDP socket entirely
# ??????????????????????????????????????????????????????????????????????????

class ScapyTransport:
    """
    Sends DCE/RPC payloads as Ether/IP/UDP frames via Scapy sendp,
    and receives responses via AsyncSniffer ? bypassing the Windows
    networking stack, firewall, and routing table completely.

    This is the fix for the silent TIMEOUT symptom.  The device WAS
    receiving the (correctly-formed) packet and sending a response back,
    but Windows Firewall / the UDP receive path was silently discarding
    the inbound response.  Raw Ethernet capture via Npcap ignores all of
    that ? we see every frame on the wire.
    """

    def __init__(self, iface: str,
                 src_mac: str, src_ip: str,
                 dst_mac: str, dst_ip: str,
                 sport: int, dport: int,
                 dummy_sock_ip: Optional[str] = None):
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

        # ?? FIX 1: Suppress ICMP "Port Unreachable" ??????????????????????????
        # When Scapy injects a raw UDP frame (src_ip:sport ? dst_ip:dport) the
        # device sends its DCE/RPC response back to src_ip:sport.  Because no
        # real process owns that UDP port, Windows immediately sends an ICMP
        # "Port Unreachable" back to the device.  TeSys Tera interprets that
        # as the controller going offline and silently aborts the AR without
        # ever completing the handshake ? which looks exactly like a timeout.
        # Binding a dummy UDP socket on sport claims the port so Windows never
        # generates the ICMP.  We never read from this socket; all receives are
        # done via the Scapy raw sniffer below.
        #
        # dummy_sock_ip overrides src_ip for binding — needed when src_ip is
        # a spoofed address we don't own (e.g. DEMO_SESSION_IP = 192.168.0.60).
        bind_ip = dummy_sock_ip if dummy_sock_ip is not None else src_ip
        self._dummy_sock: Optional[socket.socket] = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((bind_ip, sport))
            self._dummy_sock = s
            log.debug("Dummy UDP socket bound on %s:%d ? ICMP port-unreachable suppressed",
                      bind_ip, sport)
        except OSError as exc:
            log.warning(
                "Could not bind dummy UDP socket on %s:%d (%s). "
                "Windows may send ICMP port-unreachable to the device, "
                "which can cause silent AR abort.  "
                "Try running as Administrator.", bind_ip, sport, exc
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
                if raw[1] not in (PKT_RESPONSE, PKT_FAULT, PKT_REJECT):
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
        # ?? FIX 2: Give Npcap/WinPcap adequate time to arm the capture ???????
        # 50 ms was too short on Windows ? Npcap can take 100?200 ms to attach
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
            log.error("TIMEOUT ? no response to %s", label)
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
            # ?? Fallback diagnostic: listen for ANYTHING from the device ?????
            # If this catches packets, the device IS responding but on a port/
            # protocol not matched by the strict BPF above ? helps narrow down
            # the problem without Wireshark.
            log.info("  Running 2 s fallback capture (both directions: target/IP/ARP/ICMP) ...")
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
                log.error("  Fallback: no frames at all from %s ? "
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
                log.error("    *** GHOST AR LOCK ? power-cycle TeSys Tera, wait 10 s, retry ***")
            return None

        if ptype == 0x06:
            # DCE/RPC REJECT ? return to step_ar_connect for proper handling
            log.debug("    DCE/RPC REJECT received ? returning to caller")
            return resp

        return resp

# ??????????????????????????????????????????????????????????????????????????
# FIX 3 ? DCP Identify probe  (Layer-2, no IP required)
# ??????????????????????????????????????????????????????????????????????????

# PROFINET DCP multicast MAC (IEC 61158-6-10 ?6.3.13).
# DCP Identify Requests MUST be sent to this address; devices ignore unicast DCP.
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"


def _resolve_controller_ip() -> str:
    """
    Auto-detect the IPv4 address actually assigned to SCAPY_IFACE at runtime.
    Falls back to the hardcoded CONTROLLER_IP if Scapy is unavailable.
    This is critical after a device factory reset when the PC NIC may have
    fallen back to an APIPA address (169.254.x.x) instead of 169.254.0.100.
    """
    global CONTROLLER_IP
    try:
        from scapy.all import get_if_addr
        detected = get_if_addr(SCAPY_IFACE)
        if detected and detected != "0.0.0.0":
            if detected != CONTROLLER_IP:
                log.info("NIC IP auto-detected: %s (config says %s)", detected, CONTROLLER_IP)
                if not detected.startswith("169.254."):
                    log.warning(
                        "NIC IP %s is NOT in the 169.254.x.x subnet!  "
                        "PROFINET communication will FAIL.  "
                        "Set the NIC to static 169.254.0.100 / 255.255.0.0 first.", detected)
            CONTROLLER_IP = detected
            return detected
    except Exception:
        pass
    return CONTROLLER_IP


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
        marker = " ? USE THIS" if ip == CONTROLLER_IP else ""
        print(f"  {iface:<60}  {ip}{marker}")
    print()


def dcp_identify(iface: str, src_mac: str, target_mac: str,
                 timeout: float = 3.0) -> bool:
    """
    FIX 3 (corrected): Send a PROFINET DCP Identify Request to the PROFINET
    multicast address 01:0e:cf:00:00:00 and wait for the device to respond.

    BUG IN v5: the request was sent unicast to the device MAC.  PROFINET
    devices only process DCP frames whose Ethernet destination is the DCP
    multicast MAC (IEC 61158-6-10 ?6.3.13.3).  A unicast DCP frame is silently
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
    dcp_req += struct.pack(">H", 1)               # ResponseDelay (1 ? 10 ms)
    dcp_req += struct.pack(">H", 4)               # DCPDataLength = 4
    dcp_req += struct.pack(">BB", 0xFF, 0xFF)     # Option/SubOption = All
    dcp_req += struct.pack(">H", 0)               # DCPBlockLength = 0

    # ?? KEY FIX: dst = PROFINET multicast, NOT the device unicast MAC ??????
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
    log.debug("DCP Identify ? %s (via multicast %s)", target_mac, DCP_MULTICAST_MAC)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)

    try:
        sniffer.stop()
    except Exception:
        pass

    if found:
        raw = found[0]
        log.info("DCP Identify OK ? device %s is alive  (%d bytes)", target_mac, len(raw))
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
        log.error("DCP Identify TIMEOUT -- no response from %s within %.1f s",
                  target_mac, timeout)
        log.error("  The device did not respond to DCP Identify multicast.")
        return False


def dcp_identify_unicast(iface: str, src_mac: str, target_mac: str,
                         timeout: float = 3.0) -> dict:
    """
    Send a DCP Identify Request UNICAST directly to the device MAC and parse
    the full response.  Devices in DATA_EXCHANGE ignore multicast DCP Identify
    but DO respond to unicast DCP Identify (FrameID=0xFEFD, SvcID=0x05).

    Returns a dict with keys: 'alive', 'ip', 'name', 'vendor_id', 'device_id',
    'status', 'raw_blocks'. Returns {'alive': False} if no response.
    """
    xid = 0xDEAD0099

    dcp_req  = struct.pack(">H", 0xFEFD)          # FrameID (unicast)
    dcp_req += struct.pack(">BB", 0x05, 0x00)     # ServiceID=Identify, Type=Request
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)               # ResponseDelay
    dcp_req += struct.pack(">H", 4)               # DCPDataLength = 4
    dcp_req += struct.pack(">BB", 0xFF, 0xFF)     # Option/SubOption = All
    dcp_req += struct.pack(">H", 0)               # DCPBlockLength = 0

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    found: list = []

    def _handler(pkt):
        if not pkt.haslayer(Raw):
            return
        raw = bytes(pkt[Raw])
        if len(raw) < 10:
            return
        fid = struct.unpack_from(">H", raw, 0)[0]
        svc_id, svc_type = raw[2], raw[3]
        if fid == 0xFEFD and svc_id == 0x05 and svc_type == 0x01:
            found.append(raw)

    bpf = f"ether src {target_mac} and ether proto 0x{PROFINET_ETYPE:04x}"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handler, store=False)
    sniffer.start()
    time.sleep(0.20)
    sendp(frame, iface=iface, verbose=False)
    log.debug("DCP Identify (unicast) -> %s", target_mac)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        sniffer.stop()
    except Exception:
        pass

    if not found:
        return {"alive": False}

    raw = found[0]
    result = {"alive": True, "raw_blocks": []}
    import socket as _socket
    try:
        off = 10  # past FrameID(2)+SvcID(1)+SvcType(1)+Xid(4)+DCPDataLen(2)
        while off + 4 <= len(raw):
            opt  = raw[off]
            sub  = raw[off + 1]
            blen = struct.unpack_from(">H", raw, off + 2)[0]
            data = raw[off + 4: off + 4 + blen]
            result["raw_blocks"].append((opt, sub, data))
            if opt == 0x01 and sub == 0x02 and blen >= 14:  # IP block
                qual = struct.unpack_from(">H", data, 0)[0]
                ip   = _socket.inet_ntoa(data[2:6])
                mask = _socket.inet_ntoa(data[6:10])
                gw   = _socket.inet_ntoa(data[10:14])
                result["ip"] = ip
                result["mask"] = mask
                result["gw"] = gw
                result["ip_qualifier"] = qual
            elif opt == 0x02 and sub == 0x01 and blen >= 4:   # Device ID
                result["vendor_id"] = struct.unpack_from(">H", data, 0)[0]
                result["device_id"] = struct.unpack_from(">H", data, 2)[0]
            elif opt == 0x02 and sub == 0x02 and blen > 0:    # NameOfStation
                result["name"] = data.decode("ascii", errors="replace").rstrip('\x00')
            elif opt == 0x02 and sub == 0x07 and blen >= 1:   # DeviceStatus
                result["status"] = data[0]
            off += 4 + blen + (blen % 2)
    except Exception:
        pass
    return result


def _dcp_set_wait_ack(iface: str, target_mac: str, frame,
                      svc_id_expect: int, timeout: float) -> tuple:
    """
    Send a DCP Set frame and wait for the Set-Response ACK.
    Returns (acked: bool, block_result: int or -1 if no response).
    block_result=0x00 means the operation was accepted by the device.
    """
    found: list = []

    def _handler(pkt):
        if not pkt.haslayer(Raw):
            return
        raw = bytes(pkt[Raw])
        if len(raw) < 14:
            return
        fid      = struct.unpack_from(">H", raw, 0)[0]
        svc_id   = raw[2]
        svc_type = raw[3]
        if fid == 0xFEFD and svc_id == svc_id_expect and svc_type == 0x01:
            found.append(raw)

    bpf = f"ether src {target_mac} and ether proto 0x{PROFINET_ETYPE:04x}"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handler, store=False)
    sniffer.start()
    time.sleep(0.20)
    sendp(frame, iface=iface, verbose=False)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        sniffer.stop()
    except Exception:
        pass

    if not found:
        return False, -1

    raw = found[0]
    # Parse the first block in the response to find the block result
    pos = 12
    block_result = -1
    while pos + 4 <= len(raw):
        opt  = raw[pos]
        sub  = raw[pos + 1]
        blen = struct.unpack_from(">H", raw, pos + 2)[0]
        # Control/Response block carries [orig_opt, orig_sub, result]
        if opt == 0x05 and sub == 0x04 and blen >= 3:
            block_result = raw[pos + 6] if pos + 6 < len(raw) else -1
            break
        pos += 4 + blen + (blen % 2)
    return True, block_result


def dcp_set_ip(iface: str, src_mac: str, target_mac: str,
               ip: str, subnet: str = "255.255.255.0", gateway: str = "0.0.0.0",
               permanent: bool = False, timeout: float = 3.0) -> tuple:
    """
    Send PROFINET DCP Set IP Parameter to the device.

    Per IEC 61158-6-10, the device SHALL process this request and abort all
    active ARs even when in DATA_EXCHANGE state. This makes it the preferred
    software method to clear a ghost AR lock without a power cycle.

    Returns (acked: bool, block_result: int).
    block_result=0x00 means the IP was applied; non-zero means rejected.
    """
    import socket
    xid = 0xDEAD0003

    qualifier = 0x0001 if permanent else 0x0000
    ip_bytes  = socket.inet_aton(ip)
    sn_bytes  = socket.inet_aton(subnet)
    gw_bytes  = socket.inet_aton(gateway)

    dcp_blk  = struct.pack(">BB", 0x01, 0x02)   # Option=IP, Sub=IP-Parameter
    dcp_blk += struct.pack(">H", 14)             # BlockLength = 14
    dcp_blk += struct.pack(">H", qualifier)      # qualifier
    dcp_blk += ip_bytes + sn_bytes + gw_bytes    # IP, mask, GW

    dcp_req  = struct.pack(">H", 0xFEFD)         # FrameID
    dcp_req += struct.pack(">BB", 0x04, 0x00)    # ServiceID=Set, Type=Request
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)              # ResponseDelay
    dcp_req += struct.pack(">H", len(dcp_blk))
    dcp_req += dcp_blk

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    log.info("DCP Set IP -> %s  ip=%s/%s (qualifier=0x%04x)", target_mac, ip, subnet, qualifier)
    acked, result = _dcp_set_wait_ack(iface, target_mac, frame, svc_id_expect=0x04, timeout=timeout)
    if acked:
        log.info("  DCP Set IP ACK  block_result=0x%02x %s",
                 result if result >= 0 else 0xFF,
                 "(accepted)" if result == 0 else "(device returned non-zero result)")
    else:
        log.warning("  DCP Set IP: no ACK from %s (timeout)", target_mac)
    return acked, result


def dcp_reset_to_factory(iface: str, src_mac: str, target_mac: str,
                          timeout: float = 3.0) -> bool:
    """
    Send PROFINET DCP ResetToFactory unicast to the device.

    Qualifier=0x0002 resets communication parameters.  Note: if the device
    is in DATA_EXCHANGE state it may acknowledge but NOT execute the reset
    (returning block_result=0x06).  Use dcp_set_ip() as a more reliable
    ghost-AR killer that the spec mandates MUST be processed in any state.

    Returns True if DCP Ack received with block_result=0x00 (executed).
    """
    xid = 0xDEAD0001

    qualifier = 0x0002
    dcp_blk  = struct.pack(">BB", 0x05, 0x05)
    dcp_blk += struct.pack(">H", 2)
    dcp_blk += struct.pack(">H", qualifier)

    dcp_req  = struct.pack(">H", 0xFEFD)
    dcp_req += struct.pack(">BB", 0x04, 0x00)
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)
    dcp_req += struct.pack(">H", len(dcp_blk))
    dcp_req += dcp_blk

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    log.info("DCP ResetToFactory -> %s (qualifier=0x%04x)", target_mac, qualifier)
    acked, result = _dcp_set_wait_ack(iface, target_mac, frame, svc_id_expect=0x04, timeout=timeout)
    if acked:
        if result == 0x00:
            log.info("  DCP ResetToFactory accepted (block_result=0x00)")
            time.sleep(2.0)
            return True
        else:
            log.warning("  DCP ResetToFactory ACK but NOT executed "
                        "(block_result=0x%02x - device likely in DATA_EXCHANGE state). "
                        "Falling back to DCP Set IP.", result if result >= 0 else 0xFF)
            return False
    else:
        log.warning("  DCP ResetToFactory: no ACK (timeout)")
        return False


def dcp_reset_all(iface: str, src_mac: str, target_mac: str,
                  timeout: float = 4.0) -> bool:
    """
    Send DCP ResetToFactory with qualifier=0x0001 (reset ALL parameters to factory default).

    This is more aggressive than qualifier=0x0002 (communication params only) and
    resets application data as well.  The device may still return block_result=0x06
    if in DATA_EXCHANGE state, but some firmware versions treat qualifier=0x0001
    differently and will execute it.

    Returns True if DCP Ack received with block_result=0x00 (executed).
    """
    xid = 0xDEAD0005

    qualifier = 0x0001   # reset ALL to factory default
    dcp_blk  = struct.pack(">BB", 0x05, 0x05)
    dcp_blk += struct.pack(">H", 2)
    dcp_blk += struct.pack(">H", qualifier)

    dcp_req  = struct.pack(">H", 0xFEFD)
    dcp_req += struct.pack(">BB", 0x04, 0x00)
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)
    dcp_req += struct.pack(">H", len(dcp_blk))
    dcp_req += dcp_blk

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    log.info("DCP ResetToFactory (ALL) -> %s (qualifier=0x%04x)", target_mac, qualifier)
    acked, result = _dcp_set_wait_ack(iface, target_mac, frame, svc_id_expect=0x04, timeout=timeout)
    if acked:
        if result == 0x00:
            log.info("  DCP ResetToFactory (ALL) accepted (block_result=0x00) -- waiting 5s for reboot ...")
            time.sleep(5.0)
            return True
        else:
            log.warning("  DCP ResetToFactory (ALL) ACK but NOT executed "
                        "(block_result=0x%02x -- firmware refused while in DATA_EXCHANGE).",
                        result if result >= 0 else 0xFF)
            return False
    else:
        log.warning("  DCP ResetToFactory (ALL): no ACK (timeout)")
        return False


def dcp_reset_communication(iface: str, src_mac: str, target_mac: str,
                             timeout: float = 4.0) -> bool:
    """
    Send DCP Control ResetToFactory with SubOption=6 (ResetToFactory with bitmask).

    SubOption=6 is distinct from SubOption=5 (FactoryReset):
      - SubOption=5: full factory reset (often blocked with result=0x06 in DATA_EXCHANGE)
      - SubOption=6: partial reset using a bitmask qualifier:
          bit 0 (0x0001): ResetApplicationData
          bit 1 (0x0002): ResetCommunicationParameter  <-- what we want
          bit 2 (0x0004): ResetEngineering
          bit 3 (0x0008): ResetAll

    qualifier=0x0002 resets only communication state (including ghost ARs in NVM)
    without touching application parameters.  The device firmware may allow this
    even when SubOption=5 is blocked by the IN_OPERATION guard.

    Returns True if DCP Ack received with block_result=0x00 (executed).
    """
    xid = 0xDEAD0006

    qualifier = 0x0002   # ResetCommunicationParameter
    dcp_blk  = struct.pack(">BB", 0x05, 0x06)   # Option=5, SubOption=6
    dcp_blk += struct.pack(">H", 2)
    dcp_blk += struct.pack(">H", qualifier)

    dcp_req  = struct.pack(">H", 0xFEFD)         # FrameID: DCP_SET_REQUEST
    dcp_req += struct.pack(">BB", 0x04, 0x00)    # ServiceID=4 (Set), ServiceType=0 (Request)
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)              # ResponseDelay
    dcp_req += struct.pack(">H", len(dcp_blk))
    dcp_req += dcp_blk

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    log.info("DCP ResetToFactory SubOpt=6 (ResetCommunication) -> %s (qualifier=0x%04x)",
             target_mac, qualifier)
    acked, result = _dcp_set_wait_ack(iface, target_mac, frame, svc_id_expect=0x04, timeout=timeout)
    if acked:
        if result == 0x00:
            log.info("  DCP ResetCommunication accepted (block_result=0x00) -- waiting 3s ...")
            time.sleep(3.0)
            return True
        else:
            log.warning("  DCP ResetCommunication ACK but NOT executed "
                        "(block_result=0x%02x -- firmware refused in DATA_EXCHANGE).",
                        result if result >= 0 else 0xFF)
            return False
    else:
        log.warning("  DCP ResetCommunication SubOpt=6: no ACK (timeout)")
        return False


def dcp_set_station_name(iface: str, src_mac: str, target_mac: str,
                          name: str = "", timeout: float = 3.0) -> tuple:
    """
    Send DCP Set NameOfStation.

    Per IEC 61158-6-10 Sect. 4.3.1.4.1: when a device receives a Set NameOfStation
    request it SHALL abort all active ARs before applying the new name.  This makes
    it an alternative ghost-AR killer even when Set IP is refused.

    Setting name="" clears the station name and forces AR abort.
    Returns (acked: bool, block_result: int).
    """
    xid = 0xDEAD0006

    name_bytes = name.encode("ascii") if name else b""
    blen = len(name_bytes)
    padding = b"\x00" if blen % 2 else b""

    dcp_blk  = struct.pack(">BB", 0x02, 0x02)   # Option=DeviceProperties, Sub=NameOfStation
    dcp_blk += struct.pack(">H", blen)
    dcp_blk += name_bytes + padding

    dcp_req  = struct.pack(">H", 0xFEFD)
    dcp_req += struct.pack(">BB", 0x04, 0x00)
    dcp_req += struct.pack(">I", xid)
    dcp_req += struct.pack(">H", 0)
    dcp_req += struct.pack(">H", blen + 4)       # DataLength = block header (4) + name bytes
    dcp_req += dcp_blk

    frame = (Ether(dst=target_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    log.info("DCP Set NameOfStation -> %s  name=%r", target_mac, name)
    acked, result = _dcp_set_wait_ack(iface, target_mac, frame, svc_id_expect=0x04, timeout=timeout)
    if acked:
        log.info("  DCP Set NameOfStation ACK  block_result=0x%02x %s",
                 result if result >= 0 else 0xFF,
                 "(accepted -- AR abort triggered)" if result == 0 else "(refused)")
    else:
        log.warning("  DCP Set NameOfStation: no ACK (timeout)")
    return acked, result


def _extract_uuids_from_buf(buf: bytes) -> list:
    """
    Scan a buffer for 16-byte UUID-like values at every 4-byte aligned offset.
    Returns a deduplicated list of non-trivial uuid.UUID objects found.
    Used to extract the ghost AR's ARUUID from a ConnectRes rejection stub.
    """
    seen = set()
    result = []
    for i in range(0, len(buf) - 15, 4):
        try:
            u = uuid.UUID(bytes_le=buf[i:i+16])
            if u.int == 0:
                continue
            if u.int == (1 << 128) - 1:
                continue
            # Skip obvious filler patterns
            b = buf[i:i+16]
            if len(set(b)) <= 2:
                continue
            if u not in seen:
                seen.add(u)
                result.append(u)
        except Exception:
            pass
    # Also try big-endian interpretation
    for i in range(0, len(buf) - 15, 4):
        try:
            u = uuid.UUID(bytes=buf[i:i+16])
            if u.int == 0:
                continue
            if u.int == (1 << 128) - 1:
                continue
            b = buf[i:i+16]
            if len(set(b)) <= 2:
                continue
            if u not in seen:
                seen.add(u)
                result.append(u)
        except Exception:
            pass
    return result


def pnio_targeted_release(ar_uuid_val: uuid.UUID, sess_key: int = 2,
                          timeout: float = 5.0) -> bool:
    """
    Send a targeted PROFINET AR Release for a specific ARUUID.

    Tries both PNIO_UDP_PORT (34964) and PNIO_AR_SESSION_PORT (49152).
    The demo pcap shows the device uses port 49152 as its AR session port,
    so Release must be sent there as well as to the standard RPC port.
    Returns True on the first accepted response.
    """
    act_uuid = uuid.uuid4()
    sport = random.randint(49153, 65535)

    body  = struct.pack(">H", 0x0000)
    body += _u(ar_uuid_val)
    body += struct.pack(">H", sess_key)
    body += struct.pack(">H", 0x0000)
    body += struct.pack(">HH", 0x0004, 0x0000)
    block = _block(0x0114, body)
    blen  = len(block)
    ndr_prefix = struct.pack("<IIIII", blen, blen, blen, 0, blen)
    stub = ndr_prefix + block

    pkt = build_request(
        seq_num=0, opnum=OP_RELEASE,
        obj_uuid=PNIO_CMD_OBJ_UUID,
        if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid,
        stub=stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )

    def _try_port(dport: int) -> bool:
        xport = ScapyTransport(
            iface=SCAPY_IFACE,
            src_mac=CONTROLLER_MAC, src_ip=CONTROLLER_IP,
            dst_mac=TARGET_MAC, dst_ip=TARGET_IP,
            sport=sport, dport=dport,
        )
        log.info("  Targeted Release  ARUUID=%s  sess=%d  dport=%d", ar_uuid_val, sess_key, dport)
        resp = xport.send_recv(pkt, f"TargetedRelease-{dport}", timeout)
        xport.close()

        if resp is None:
            log.warning("    No response (timeout) on port %d", dport)
            return False

        rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
        if rpc_ptype == 0x02:
            stub_body = resp[80:]
            if len(stub_body) >= 4:
                err = struct.unpack_from(">I", stub_body, 0)[0]
                if err == 0:
                    log.info("    Targeted Release ACCEPTED (error=0) on port %d -- ghost AR cleared!", dport)
                    return True
                ec1 = (err >> 8) & 0xFF
                log.info("    Targeted Release port %d: PNIO error 0x%08x (Code1=0x%02x)", dport, err, ec1)
            return False
        elif rpc_ptype == 0x06:
            log.warning("    Targeted Release port %d: DCE/RPC REJECT", dport)
            return False
        else:
            log.warning("    Targeted Release port %d: unexpected ptype=0x%02x", dport, rpc_ptype)
            return False

    # Try the standard PROFINET RPC port first, then the device's AR session port
    for dport in (PNIO_UDP_PORT, PNIO_AR_SESSION_PORT):
        if _try_port(dport):
            return True
    return False


def pnio_spoof_release(timeout: float = 5.0) -> bool:
    """
    Send a PROFINET Release spoofing the original Siemens PLC Ethernet MAC and
    DCE/RPC session parameters (activity UUID, seq, AR UUID).

    IMPORTANT: We do NOT spoof the IP address.  The device is currently on
    169.254.x.x (APIPA) while the original PLC was on 192.168.0.60.  If we
    send a packet with src_ip=192.168.0.60, the device cannot route its
    response back (different subnet, no gateway) and silently drops it.
    Using our real CONTROLLER_IP (169.254.0.100) ensures the response can
    be delivered.

    PROFINET session ownership is validated by the firmware using the stored
    CMInitiatorMACAddress from the original ARBlock, NOT by IP address.
    By spoofing the MAC to 60:7d:09:5b:24:b6 (the original Siemens PLC) and
    using the exact DCE/RPC activity UUID from that session, the device
    should accept the Release.

    Parameters spoofed from tesysprofinetdemo.pcapng:
      - Ethernet src MAC: 60:7d:09:5b:24:b6  (Siemens PLC)
      - UDP sport:        59981
      - DCE/RPC act_uuid: e298926f-000e-1010-806c-607d095b24b6
      - seq_num:          3
      - AR UUID:          f9c6c366-7e9d-4aef-8f6a-3cd730f5afce
      - SessionKey:       2
    IP src stays as CONTROLLER_IP so the device can route its reply back.
    """
    if not SCAPY_OK:
        log.error("Scapy is required for --spoof-release")
        return False

    log.info("== Spoofed Session Release (--spoof-release) ==")
    log.info("  Spoofing original PLC MAC=%s  sport=%d  (IP stays %s for routability)",
             DEMO_SESSION_MAC, DEMO_SESSION_SPORT, CONTROLLER_IP)
    log.info("  act_uuid=%s  seq=%d", DEMO_SESSION_ACT_UUID, DEMO_SESSION_SEQ)
    log.info("  AR UUID=%s  sess_key=%d", DEMO_GHOST_AR_UUID, DEMO_GHOST_AR_SESSKEY)

    body  = struct.pack(">H", 0x0000)
    body += _u(DEMO_GHOST_AR_UUID)
    body += struct.pack(">H", DEMO_GHOST_AR_SESSKEY)
    body += struct.pack(">H", 0x0000)
    body += struct.pack(">HH", 0x0004, 0x0000)
    block = _block(0x0114, body)
    blen  = len(block)
    ndr_prefix = struct.pack("<IIIII", blen, blen, blen, 0, blen)
    stub = ndr_prefix + block

    pkt = build_request(
        seq_num=DEMO_SESSION_SEQ, opnum=OP_RELEASE,
        obj_uuid=PNIO_CMD_OBJ_UUID,
        if_uuid=PNIO_CM_IF_UUID,
        act_uuid=DEMO_SESSION_ACT_UUID,
        stub=stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )

    act_bytes = pkt[40:56]
    # Bind a dummy socket to suppress ICMP port-unreachable from Windows.
    # The device sends its response to CONTROLLER_IP:DEMO_SESSION_SPORT; without
    # a bound socket on that port Windows would immediately send ICMP back.
    _dummy: Optional[socket.socket] = None
    try:
        _dummy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _dummy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _dummy.bind((CONTROLLER_IP, DEMO_SESSION_SPORT))
        log.debug("Dummy UDP socket bound on %s:%d for spoof-release", CONTROLLER_IP, DEMO_SESSION_SPORT)
    except OSError as exc:
        log.warning("Could not bind dummy socket on %s:%d: %s", CONTROLLER_IP, DEMO_SESSION_SPORT, exc)

    success = False

    for dport in (PNIO_AR_SESSION_PORT, PNIO_UDP_PORT):
        log.info("  Sending spoofed Release to %s:%d ...", TARGET_IP, dport)
        resp_q: queue.Queue = queue.Queue()

        def _handler(frame, _seq=DEMO_SESSION_SEQ, _act=act_bytes):
            if not frame.haslayer(Raw):
                return
            raw = bytes(frame[Raw])
            if len(raw) < 80 or raw[0] != 4 or raw[4] != 0x10:
                return
            if raw[1] not in (PKT_RESPONSE, PKT_FAULT, PKT_REJECT):
                return
            if raw[40:56] != _act:
                return
            try:
                if struct.unpack_from("<I", raw, 64)[0] != _seq:
                    return
            except struct.error:
                return
            if resp_q.empty():
                resp_q.put(raw)

        bpf = f"ether src {TARGET_MAC}"
        sniffer = AsyncSniffer(iface=SCAPY_IFACE, filter=bpf, prn=_handler, store=False)
        sniffer.start()
        time.sleep(0.20)

        frame = (Ether(dst=TARGET_MAC, src=DEMO_SESSION_MAC) /
                 IP(src=CONTROLLER_IP, dst=TARGET_IP) /
                 UDP(sport=DEMO_SESSION_SPORT, dport=dport) /
                 Raw(load=pkt))
        sendp(frame, iface=SCAPY_IFACE, verbose=False)
        log.debug(">>> SpoofRelease-%d  len=%d  stub[0:16]=%s", dport, len(pkt), pkt[:16].hex())

        try:
            resp = resp_q.get(timeout=timeout)
        except queue.Empty:
            resp = None
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass

        if resp is None:
            log.warning("    No response on port %d (timeout)", dport)
            continue

        rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
        stub_body = resp[80:]
        if rpc_ptype == 0x02 and len(stub_body) >= 4:
            err = struct.unpack_from(">I", stub_body, 0)[0]
            if err == 0:
                log.info("    Spoofed Release ACCEPTED (error=0) on port %d -- ghost AR cleared!", dport)
                success = True
                break
            ec1 = (err >> 8) & 0xFF
            log.info("    Spoofed Release port %d: PNIO error 0x%08x (Code1=0x%02x)  stub=%s",
                     dport, err, ec1, stub_body[:20].hex())
        elif rpc_ptype == 0x06:
            log.warning("    Spoofed Release port %d: DCE/RPC REJECT", dport)
        else:
            log.warning("    Spoofed Release port %d: ptype=0x%02x  stub=%s",
                        dport, rpc_ptype, stub_body[:20].hex())

    if _dummy is not None:
        try:
            _dummy.close()
        except Exception:
            pass

    return success


def _parse_iodread_response(sb: bytes, req_index: int = 0xF820) -> dict:
    """
    Parse an IODReadRes stub returned by the device.

    The response layout from this device (TeSys Tera firmware v000.000.005):
      Bytes  0-19 : NDR prefix (5 × LE uint32: ArgsMax, ArgsLen, MaxCount, Offset, ActualCount).
                    NDR[0] carries a device-level RPC return code (non-zero means the CL-RPC
                    layer flagged an issue, but the block itself may still be valid).
      Bytes 20+   : IODReadResHeader block (BlockType=0x8009)

    IODReadResHeader block layout:
      +0,+1  BlockType         (2, BE) = 0x8009
      +2,+3  BlockLength       (2, BE)
      +4     VersionHigh       = 1
      +5     VersionLow        = 0
      +6,+7  SeqNum            (2, BE)
      +8,+9  Padding
      +10..+25  ARUUID         (16 bytes)
      +26..+29  API            (4, BE)
      +30,+31   Slot           (2, BE)
      +32,+33   SubSlot        (2, BE)
      +34,+35   Padding
      +36,+37   Index          (2, BE)   ← echoed back
      +38..+41  RecordDataLen  (4, BE)   ← length of record payload
      +42..+45  PNIO_STATUS    (4, BE)   ← 0 = success
      +46,+47   AV1            (2, BE)
      +48,+49   AV2            (2, BE)
      +50+      RecordData     (RecordDataLen bytes)

    Returns a dict with keys:
      ok, block_type, seq, index, rdl, pnio_status, av1, av2,
      record_data, ndr_code
    """
    result = {"ok": False, "block_type": 0, "seq": 0, "index": 0,
              "rdl": 0, "pnio_status": 0, "av1": 0, "av2": 0,
              "record_data": b"", "ndr_code": 0}

    BLOCK_OFF = 20  # NDR prefix is 20 bytes (5 × LE uint32: ArgsMax, ArgsLen, MaxCount, Offset, ActualCount)

    # Decode the 5-DWORD NDR prefix
    if len(sb) >= 20:
        ndr = struct.unpack_from("<IIIII", sb, 0)
        result["ndr_code"] = ndr[0]  # device-level RPC return code

    if len(sb) < BLOCK_OFF + 6:
        return result

    btype, blen = struct.unpack_from(">HH", sb, BLOCK_OFF)
    result["block_type"] = btype
    if btype != 0x8009:
        return result

    # Body starts at block offset +6 (after type+len+version)
    body_off = BLOCK_OFF + 6
    MIN_BODY = 2 + 2 + 16 + 4 + 2 + 2 + 2 + 2 + 4 + 4 + 2 + 2  # 44 bytes
    if len(sb) < body_off + MIN_BODY:
        return result

    off = body_off
    seq  = struct.unpack_from(">H", sb, off)[0]; off += 4    # SeqNum + Padding
    off += 16                                                  # skip ARUUID
    off += 4                                                   # skip API
    off += 6                                                   # skip Slot+Sub+Padding
    idx  = struct.unpack_from(">H", sb, off)[0]; off += 2     # Index echoed
    rdl  = struct.unpack_from(">I", sb, off)[0]; off += 4     # RecordDataLength
    pst  = struct.unpack_from(">I", sb, off)[0]; off += 4     # PNIO_STATUS
    av1  = struct.unpack_from(">H", sb, off)[0]; off += 2
    av2  = struct.unpack_from(">H", sb, off)[0]; off += 2

    result.update({
        "ok": True, "seq": seq, "index": idx,
        "rdl": rdl, "pnio_status": pst, "av1": av1, "av2": av2,
        "record_data": sb[off:off + rdl] if rdl > 0 else b"",
    })
    return result


def pnio_read_ardata(timeout: float = 5.0) -> Optional[bytes]:
    """
    Send PROFINET IODReadImplicit (opnum=5) for index 0xF820 (ARData).
    ARData lists all active Application Relationships including their UUIDs.
    ReadImplicit does NOT require an established AR.

    Observations from hardware testing:
    - Port 34964 (PNIO_UDP_PORT):     no response — device ignores it
    - Port 49152 (PNIO_AR_SESSION_PORT): responds with IODReadResHeader
    - The device returns an empty record (RecordDataLength=0, PNIO_STATUS=0)
      meaning the ghost AR is NOT exposed via the ARData record index.

    Returns the raw response stub on success, or None on failure.
    """
    if not SCAPY_OK:
        log.error("Scapy is required for --read-ardata")
        return None

    log.info("== PROFINET ARData Read (index 0xF820) ==")

    seq_num = 1
    body  = struct.pack(">H", seq_num)
    body += struct.pack(">H", 0)
    body += bytes(16)                         # ARUUID = zeros (ReadImplicit)
    body += struct.pack(">I", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0)
    body += struct.pack(">H", 0xF820)         # Index = ARData
    body += struct.pack(">I", 0x4000)
    body += struct.pack(">HH", 0, 0)
    body += bytes(20)
    block = _block(0x0009, body)
    blen  = len(block)
    ndr   = struct.pack("<IIIII", blen, blen, blen, 0, blen)
    stub  = ndr + block

    act_uuid = uuid.uuid4()
    sport    = random.randint(49153, 65535)
    known    = {PNIO_CMD_OBJ_UUID, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, PNIO_CTRL_OBJ_UUID}

    any_response: Optional[bytes] = None

    for opnum, opname in [(5, "ReadImplicit"), (3, "Read")]:
        pkt = build_request(
            seq_num=seq_num, opnum=opnum,
            obj_uuid=PNIO_CMD_OBJ_UUID,
            if_uuid=PNIO_CM_IF_UUID,
            act_uuid=act_uuid,
            stub=stub,
            wire_profile=COMMANDER_WIRE_PROFILE,
        )

        for dport in (PNIO_AR_SESSION_PORT, PNIO_UDP_PORT):
            log.info("  Trying %s (opnum=%d) -> port %d ...", opname, opnum, dport)
            xport = ScapyTransport(
                iface=SCAPY_IFACE,
                src_mac=CONTROLLER_MAC, src_ip=CONTROLLER_IP,
                dst_mac=TARGET_MAC,     dst_ip=TARGET_IP,
                sport=sport, dport=dport,
            )
            resp = xport.send_recv(pkt, f"ARDataRead-{opnum}-{dport}", timeout)
            xport.close()

            if resp is None:
                log.warning("    No response (timeout)")
                continue

            rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
            sb = resp[80:]
            log.debug("    ptype=0x%02x  stub[0:40]=%s", rpc_ptype, sb[:40].hex())

            if rpc_ptype == 0x02:  # RESPONSE
                any_response = sb
                log.info("    Got RESPONSE  stub_len=%d", len(sb))
                log.debug("    stub=%s", sb.hex())

                parsed = _parse_iodread_response(sb, req_index=0xF820)

                if not parsed["ok"]:
                    log.warning("    Could not parse IODReadResHeader (block_type=0x%04x)",
                                parsed["block_type"])
                    continue

                ndr_c = parsed["ndr_code"]
                if ndr_c != 0:
                    log.debug("    NDR[0]=0x%08x (device RPC-level code, not a block error)",
                              ndr_c)

                pst = parsed["pnio_status"]
                if pst != 0:
                    ec  = (pst >> 24) & 0xFF
                    ed  = (pst >> 16) & 0xFF
                    ec1 = (pst >>  8) & 0xFF
                    ec2 =  pst        & 0xFF
                    log.warning("    PNIO_STATUS=0x%08x  Code=0x%02x Decode=0x%02x"
                                " Code1=0x%02x Code2=0x%02x",
                                pst, ec, ed, ec1, ec2)
                else:
                    log.info("    PNIO_STATUS=0 (success)")

                idx_echo = parsed["index"]
                rdl      = parsed["rdl"]
                log.info("    IODReadResHeader: Index_echoed=0x%04x (req=0xF820)"
                         "  RecordDataLen=%d  PNIO_STATUS=0x%08x",
                         idx_echo, rdl, pst)

                if idx_echo != 0xF820:
                    log.warning("    Device echoed Index=0x%04x (not 0xF820) —"
                                " firmware may not support ARData at this index", idx_echo)

                if rdl == 0:
                    log.warning("    ARData record is EMPTY (RecordDataLength=0)")
                    log.warning("    The ghost AR is NOT tracked in the ARData record.")
                    log.warning("    This firmware (v000.000.005) stores the ghost AR in NVM only.")
                    log.warning("    Software approaches exhausted — options remaining:")
                    log.warning("      1. --spoof-connect : reconnect as original PLC (spec §4.4.1.6)")
                    log.warning("      2. Power-cycle device for 60+ seconds")
                    log.warning("      3. SoMove USB service cable -> 'Reset Communication'")
                else:
                    rec = parsed["record_data"]
                    log.info("    ARData record: %d bytes", rdl)
                    log.debug("    record_data=%s", rec.hex())
                    candidates = [u for u in _extract_uuids_from_buf(rec) if u not in known]
                    if candidates:
                        log.info("    Found %d AR UUID(s) in ARData record:", len(candidates))
                        for u in candidates:
                            log.info("      AR UUID: %s", u)
                        log.info("    Run: python tesys_pn_v10.py --force-release")
                    else:
                        log.info("    ARData record contained no UUID-like values")
                return sb

            elif rpc_ptype == 0x06:
                log.warning("    DCE/RPC REJECT  stub=%s", sb[:20].hex())
            elif rpc_ptype == 0x03:
                log.warning("    DCE/RPC FAULT   stub=%s", sb[:20].hex())
            else:
                log.warning("    Unexpected ptype=0x%02x  stub=%s", rpc_ptype, sb[:20].hex())

    if any_response is None:
        log.error("  ARData read: no response on any opnum/port combination.")
        log.error("  Device may not support ReadImplicit, or it dropped the request.")
    return any_response


def pnio_spoof_connect(timeout: float = 8.0) -> bool:
    """
    Send a PROFINET ConnectReq spoofing the original ghost PLC's MAC address.

    IEC 61158-6-10 §4.4.1.6 (Station Restart):
      If a CMInitiatorMACAddress that already owns an AR sends a NEW ConnectReq
      with a DIFFERENT ARUUID, the device MUST abort the existing AR from that
      MAC and accept the new connection.  This is exactly the "station restart"
      scenario — the original PLC has rebooted and is reconnecting.

    Strategy:
      1. Spoof src_mac = DEMO_SESSION_MAC (60:7d:09:5b:24:b6)
      2. Use a fresh ARUUID (uuid4) — different from ghost → triggers §4.4.1.6
      3. If ConnectRes PNIO_STATUS=0: ghost AR aborted, new AR active
         → send PrmEnd + AppReady from spoofed MAC, then Release to clean up
         → re-run script normally to establish our own AR
      4. If rejected: log the error for diagnostics; ghost AR may be in NVM

    Returns True if the device accepted the spoofed Connect and the ghost
    AR appears to have been cleared.
    """
    if not SCAPY_OK:
        log.error("Scapy is required for --spoof-connect")
        return False

    log.info("== Spoofed Connect (--spoof-connect) ==")
    log.info("  Spoofing ghost PLC MAC=%s  (PROFINET §4.4.1.6 station-restart)", DEMO_SESSION_MAC)
    log.info("  NOTE: src_ip is CONTROLLER_IP (%s), NOT DEMO_SESSION_IP (%s).",
             CONTROLLER_IP, DEMO_SESSION_IP)
    log.info("  Device is on 169.254.x.x subnet; sending from 192.168.0.60 causes the")
    log.info("  response to be unroutable.  Station-restart is checked by CMInitiatorMAC")
    log.info("  in the ARBlock (spoofed), not by IP.  IP stays reachable so we receive ACK.")

    fresh_ar_uuid  = uuid.uuid4()
    fresh_sess_key = 1
    log.info("  Fresh AR UUID:   %s", fresh_ar_uuid)

    stub = build_connect_stub(
        fresh_ar_uuid,
        ctrl_mac=DEMO_SESSION_MAC,
        controller_station_name="plc-station",
        in_len=INPUT_LEN,
        out_len=OUTPUT_LEN,
        subslot=DEFAULT_PROCESS_SUBSLOT,
        session_key=fresh_sess_key,
        wire_profile=COMMANDER_WIRE_PROFILE,
        include_alarm_cr=True,
    )

    # Activity UUID: standard PROFINET act_uuid has PLC MAC embedded in last 6 bytes
    mac_b = bytes(int(x, 16) for x in DEMO_SESSION_MAC.split(":"))
    act_bytes = bytes([0xe2, 0x98, 0x92, 0x6f, 0x00, 0x0e, 0x10, 0x10,
                       0x80, 0x6c]) + mac_b
    act_uuid = uuid.UUID(bytes=act_bytes)

    pkt = build_request(
        seq_num=0,
        opnum=OP_CONNECT,
        obj_uuid=PNIO_CMD_OBJ_UUID,
        if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid,
        stub=stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )

    log.info("  Sending ConnectReq to port %d (spoofed MAC=%s, IP=%s)...",
             PNIO_AR_SESSION_PORT, DEMO_SESSION_MAC, CONTROLLER_IP)
    xport = ScapyTransport(
        iface=SCAPY_IFACE,
        src_mac=DEMO_SESSION_MAC, src_ip=CONTROLLER_IP,
        dst_mac=TARGET_MAC,       dst_ip=TARGET_IP,
        sport=DEMO_SESSION_SPORT, dport=PNIO_AR_SESSION_PORT,
        dummy_sock_ip=CONTROLLER_IP,
    )
    resp = xport.send_recv(pkt, "SpoofConnect", timeout)
    xport.close()

    if resp is None:
        log.error("  Spoofed Connect: no response (timeout)")
        log.error("  The device may only respond to its current AR owner's MAC.")
        return False

    rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
    sb = resp[80:] if len(resp) > 80 else b""
    log.debug("  SpoofConnect response: ptype=0x%02x  stub=%s", rpc_ptype, sb[:32].hex())

    if rpc_ptype == 0x06:
        reject_st = struct.unpack_from(">I", resp, 8)[0] if len(resp) > 12 else 0
        log.error("  DCE/RPC REJECT (ptype=0x06)  status=0x%08x", reject_st)
        log.error("  Ghost AR is very firmly locked — only power-cycle will clear it.")
        return False

    if rpc_ptype != 0x02:
        log.error("  Unexpected ptype=0x%02x", rpc_ptype)
        return False

    if len(sb) < 4:
        log.error("  Response stub too short (%d bytes)", len(sb))
        return False

    err_status = struct.unpack_from(">I", sb, 0)[0]
    if err_status != 0:
        ec  = (err_status >> 24) & 0xFF
        ed  = (err_status >> 16) & 0xFF
        ec1 = (err_status >>  8) & 0xFF
        ec2 =  err_status        & 0xFF
        log.error("  Spoofed ConnectRes error: 0x%08x  Code1=0x%02x Code2=0x%02x",
                  err_status, ec1, ec2)
        if ec1 == 0x81:
            log.error("  AR still locked — device does not honor §4.4.1.6 for NVM-stored ghost AR.")
            log.error("  The ghost AR UUID was saved in NVM and reloaded after reboot;")
            log.error("  the station-restart rule requires a live AR, not a NVM phantom.")
        elif ec1 == 0x85:
            log.error("  AR resources exhausted — may indicate a different AR is still alive.")
        log.error("  Physical options:  power-cycle 60+ s  |  SoMove USB reset-communication")
        return False

    log.info("  Spoofed ConnectRes ACCEPTED (PNIO_STATUS=0)!")
    log.info("  Ghost AR from %s has been cleared via station-restart.", DEMO_SESSION_MAC)
    log.info("  Sending PrmEnd to complete spoofed AR establishment...")

    prm_block = build_control_stub(fresh_ar_uuid, CTRL_CMD_PRM_END, session_key=fresh_sess_key)
    _blen = len(prm_block)
    prm_stub = struct.pack("<IIIII", _blen, _blen, _blen, 0, _blen) + prm_block
    prm_pkt  = build_request(
        seq_num=1, opnum=OP_CONTROL,
        obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid, stub=prm_stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )
    xport2 = ScapyTransport(
        iface=SCAPY_IFACE,
        src_mac=DEMO_SESSION_MAC, src_ip=CONTROLLER_IP,
        dst_mac=TARGET_MAC,       dst_ip=TARGET_IP,
        sport=DEMO_SESSION_SPORT, dport=PNIO_AR_SESSION_PORT,
        dummy_sock_ip=CONTROLLER_IP,
    )
    prm_resp = xport2.send_recv(prm_pkt, "SpoofPrmEnd", timeout)

    if prm_resp is not None:
        log.info("  PrmEnd accepted — sending AppReady...")
        app_block = build_control_stub(fresh_ar_uuid, CTRL_CMD_APP_READY, session_key=fresh_sess_key)
        _blen2 = len(app_block)
        app_stub = struct.pack("<IIIII", _blen2, _blen2, _blen2, 0, _blen2) + app_block
        app_pkt  = build_request(
            seq_num=2, opnum=OP_CONTROL,
            obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
            act_uuid=act_uuid, stub=app_stub,
            wire_profile=COMMANDER_WIRE_PROFILE,
        )
        app_resp = xport2.send_recv(app_pkt, "SpoofAppReady", timeout)
        if app_resp is not None:
            log.info("  AppReady accepted — spoofed AR is now fully established.")

    # Clean up the spoofed AR with a Release so device is ready for our real Connect
    log.info("  Sending Release to clean up spoofed AR...")
    rel_stub = build_release_stub(fresh_ar_uuid, session_key=fresh_sess_key)
    rel_pkt  = build_request(
        seq_num=3, opnum=OP_RELEASE,
        obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid, stub=rel_stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )
    rel_resp = xport2.send_recv(rel_pkt, "SpoofRelease", 3.0)
    xport2.close()

    if rel_resp is not None:
        log.info("  Release sent — spoofed AR cleaned up successfully.")
    else:
        log.warning("  Release timed out — spoofed AR may persist briefly, but device should be free.")

    log.info("  Ghost AR cleared!  Re-run without --spoof-connect to establish a normal AR.")
    return True


def pnio_spoof_same_uuid(timeout: float = 8.0) -> bool:
    """
    Send a PROFINET ConnectReq spoofing the original PLC MAC AND using the exact
    same ghost AR UUID.  This targets a different firmware code path than
    --spoof-connect (station-restart §4.4.1.6):

    When the device sees:  same MAC + same UUID + same act_uuid
      → it may treat the request as the original PLC reconnecting to its
        existing AR (a reconnect/resume rather than a station-restart).
        If accepted, the ghost AR transitions from NVM-phantom state to an
        active/open state that we can then cleanly Release.

    Sequence:
      1. ConnectReq  (ghost UUID, ghost MAC, ghost session params)
      2. PrmEnd      (if Connect accepted)
      3. AppReady    (if PrmEnd accepted)
      4. Release     (always attempted if Connect accepted)

    Returns True if the ghost AR was released successfully.
    """
    if not SCAPY_OK:
        log.error("Scapy is required for --spoof-same-uuid")
        return False

    log.info("== Spoofed Connect -- SAME UUID strategy (--spoof-same-uuid) ==")
    log.info("  Ghost AR UUID:    %s", DEMO_GHOST_AR_UUID)
    log.info("  Spoofing MAC:     %s  sport=%d", DEMO_SESSION_MAC, DEMO_SESSION_SPORT)
    log.info("  SessionKey:       %d", DEMO_GHOST_AR_SESSKEY)
    log.info("  act_uuid:         %s", DEMO_SESSION_ACT_UUID)
    log.info("  Strategy: same UUID+MAC+act_uuid = reconnect (not station-restart)")

    stub = build_connect_stub(
        DEMO_GHOST_AR_UUID,
        ctrl_mac=DEMO_SESSION_MAC,
        controller_station_name="plc-station",
        in_len=INPUT_LEN,
        out_len=OUTPUT_LEN,
        subslot=DEFAULT_PROCESS_SUBSLOT,
        session_key=DEMO_GHOST_AR_SESSKEY,
        wire_profile=COMMANDER_WIRE_PROFILE,
        include_alarm_cr=True,
    )

    act_uuid = DEMO_SESSION_ACT_UUID

    pkt = build_request(
        seq_num=0,
        opnum=OP_CONNECT,
        obj_uuid=PNIO_CMD_OBJ_UUID,
        if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid,
        stub=stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )

    log.info("  Sending ConnectReq to port %d (ghost UUID, ghost MAC=%s, IP=%s)...",
             PNIO_AR_SESSION_PORT, DEMO_SESSION_MAC, CONTROLLER_IP)
    xport = ScapyTransport(
        iface=SCAPY_IFACE,
        src_mac=DEMO_SESSION_MAC, src_ip=CONTROLLER_IP,
        dst_mac=TARGET_MAC,       dst_ip=TARGET_IP,
        sport=DEMO_SESSION_SPORT, dport=PNIO_AR_SESSION_PORT,
        dummy_sock_ip=CONTROLLER_IP,
    )
    resp = xport.send_recv(pkt, "SpoofSameUUID-Connect", timeout)
    xport.close()

    if resp is None:
        log.error("  SameUUID Connect: no response (timeout)")
        return False

    rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
    sb = resp[80:] if len(resp) > 80 else b""
    log.debug("  SameUUID ConnectRes: ptype=0x%02x  stub=%s", rpc_ptype, sb[:32].hex())

    if rpc_ptype == 0x06:
        reject_st = struct.unpack_from(">I", resp, 8)[0] if len(resp) > 12 else 0
        log.error("  DCE/RPC REJECT  status=0x%08x", reject_st)
        return False

    if rpc_ptype != 0x02:
        log.error("  Unexpected ptype=0x%02x", rpc_ptype)
        return False

    if len(sb) < 4:
        log.error("  Response stub too short (%d bytes)", len(sb))
        return False

    err_status = struct.unpack_from(">I", sb, 0)[0]
    if err_status != 0:
        ec1 = (err_status >> 8) & 0xFF
        ec2 =  err_status       & 0xFF
        log.error("  SameUUID ConnectRes error: 0x%08x  Code1=0x%02x Code2=0x%02x",
                  err_status, ec1, ec2)
        if ec1 == 0x81:
            log.error("  Ghost AR still locked (NVM phantom, firmware won't resume).")
            log.error("  Only remaining software option: power-cycle 60+ s.")
        elif ec1 == 0x83:
            log.error("  AR already in use by different session.")
        else:
            log.error("  Unexpected error — ghost AR state unknown.")
        return False

    log.info("  SameUUID ConnectRes ACCEPTED (PNIO_STATUS=0)!")
    log.info("  Ghost AR resumed — sending PrmEnd...")

    xport2 = ScapyTransport(
        iface=SCAPY_IFACE,
        src_mac=DEMO_SESSION_MAC, src_ip=CONTROLLER_IP,
        dst_mac=TARGET_MAC,       dst_ip=TARGET_IP,
        sport=DEMO_SESSION_SPORT, dport=PNIO_AR_SESSION_PORT,
        dummy_sock_ip=CONTROLLER_IP,
    )

    prm_block = build_control_stub(DEMO_GHOST_AR_UUID, CTRL_CMD_PRM_END,
                                   session_key=DEMO_GHOST_AR_SESSKEY)
    _blen = len(prm_block)
    prm_stub = struct.pack("<IIIII", _blen, _blen, _blen, 0, _blen) + prm_block
    prm_pkt  = build_request(
        seq_num=1, opnum=OP_CONTROL,
        obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid, stub=prm_stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )
    prm_resp = xport2.send_recv(prm_pkt, "SameUUID-PrmEnd", timeout)

    if prm_resp is not None:
        log.info("  PrmEnd accepted — sending AppReady...")
        app_block = build_control_stub(DEMO_GHOST_AR_UUID, CTRL_CMD_APP_READY,
                                       session_key=DEMO_GHOST_AR_SESSKEY)
        _blen2 = len(app_block)
        app_stub = struct.pack("<IIIII", _blen2, _blen2, _blen2, 0, _blen2) + app_block
        app_pkt  = build_request(
            seq_num=2, opnum=OP_CONTROL,
            obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
            act_uuid=act_uuid, stub=app_stub,
            wire_profile=COMMANDER_WIRE_PROFILE,
        )
        xport2.send_recv(app_pkt, "SameUUID-AppReady", timeout)
    else:
        log.warning("  PrmEnd timed out — sending Release anyway...")

    log.info("  Sending Release to cleanly close the ghost AR...")
    rel_stub = build_release_stub(DEMO_GHOST_AR_UUID, session_key=DEMO_GHOST_AR_SESSKEY)
    rel_pkt  = build_request(
        seq_num=DEMO_SESSION_SEQ, opnum=OP_RELEASE,
        obj_uuid=PNIO_CMD_OBJ_UUID, if_uuid=PNIO_CM_IF_UUID,
        act_uuid=act_uuid, stub=rel_stub,
        wire_profile=COMMANDER_WIRE_PROFILE,
    )
    rel_resp = xport2.send_recv(rel_pkt, "SameUUID-Release", 3.0)
    xport2.close()

    if rel_resp is not None and len(rel_resp) > 80:
        rel_sb  = rel_resp[80:]
        rel_err = struct.unpack_from(">I", rel_sb, 0)[0] if len(rel_sb) >= 4 else 0xFFFFFFFF
        if rel_err == 0:
            log.info("  Release ACCEPTED (PNIO_STATUS=0) — ghost AR cleared!")
            log.info("  Re-run without --spoof-same-uuid to establish a normal AR.")
            return True
        else:
            log.warning("  Release returned PNIO error 0x%08x — AR may still linger.", rel_err)
    else:
        log.warning("  Release timed out — AR may still linger briefly.")

    log.info("  SameUUID strategy complete.  Try normal connect now.")
    return True



    """
    Send a Connect that will be rejected, then parse the full ConnectRes stub
    body to extract any UUID-like patterns (the ghost AR's ARUUID).
    Returns a list of candidate uuid.UUID objects.
    """
    log.info("== Extract Ghost AR UUID from ConnectRes rejection ==")
    ctrl = PNIOController()
    # step_ar_connect will populate ctrl._ghost_ar_uuids if error 0x81 occurs
    ctrl.step_ar_connect()
    found = ctrl._ghost_ar_uuids
    if found:
        log.info("  Extracted %d candidate UUID(s) from ConnectRes:", len(found))
        for u in found:
            log.info("    %s", u)
    else:
        log.info("  No candidate UUIDs extracted from ConnectRes stub.")
    if ctrl.xport:
        ctrl.xport.close()
    return found


def modbus_full_register_scan(ip: str = TARGET_IP, timeout: float = 2.0):
    """
    FC03 scan of Modbus holding registers 0x0001 to 0x03FF (4 registers at a time).
    Logs all addresses that return non-zero data and checks for UUID-like patterns.
    UUID = 8 consecutive non-zero 16-bit registers.
    """
    import socket as _sock
    log.info("== Modbus Full Register Scan FC03 0x0001-0x03FF ==")
    nonzero_blocks = {}

    def _mb_read(addr: int, count: int = 4) -> list:
        tid = addr & 0xFFFF
        req = struct.pack(">HHHBBHH", tid, 0, 6, 0xFF, 3, addr, count)
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, 502))
            s.sendall(req)
            resp = s.recv(256)
            s.close()
            if len(resp) >= 9 and resp[7] == 3:
                n = resp[8] // 2
                return list(struct.unpack_from(">" + "H" * n, resp, 9))
        except Exception:
            pass
        return []

    for addr in range(0x0001, 0x0400, 4):
        vals = _mb_read(addr, 4)
        if vals and any(v != 0 for v in vals):
            hex_vals = " ".join(f"{v:04x}" for v in vals)
            log.info("  FC03 0x%04x: %s", addr, hex_vals)
            nonzero_blocks[addr] = vals

    # Check for UUID-like pattern: 8 consecutive non-zero registers
    log.info("  Scanning for 8-register UUID patterns ...")
    all_addrs = sorted(nonzero_blocks.keys())
    for i in range(len(all_addrs) - 1):
        a1, a2 = all_addrs[i], all_addrs[i+1]
        if a2 == a1 + 4:
            combined = nonzero_blocks[a1] + nonzero_blocks[a2]
            raw = struct.pack(">" + "H" * 8, *combined)
            try:
                u_le = uuid.UUID(bytes_le=raw)
                u_be = uuid.UUID(bytes=raw)
                if u_le.int != 0:
                    log.info("  Possible UUID at 0x%04x (LE): %s", a1, u_le)
                if u_be.int != 0:
                    log.info("  Possible UUID at 0x%04x (BE): %s", a1, u_be)
            except Exception:
                pass

    log.info("  Scan complete.  %d non-zero blocks found.", len(nonzero_blocks))
    return nonzero_blocks


def wait_for_device_hello(timeout: float = 120.0,
                          post_hello_delay: float = 3.0) -> bool:
    """
    Listen on the WS-Discovery multicast (UDP 3702) for a Hello or Bye+Hello
    sequence from TARGET_MAC.  Returns True once Hello is received and
    post_hello_delay seconds have elapsed (giving PROFINET stack time to init).

    TeSys Tera boot timing (measured from pcap):
      ~159 s : IPv6/IPv4 stack comes up
      ~198 s : WS-Discovery Hello sent  ← PROFINET init starts
      ~213 s : Ready for DCE/RPC Connect (15 s after Hello)

    This is needed when the device just rebooted — the Connect must not be sent
    until the PROFINET RPC listener is ready (~15 s after the Hello).
    """
    import socket as _sk
    log.info("== Waiting for WS-Discovery Hello from %s (timeout=%.0f s) ==", TARGET_MAC, timeout)
    log.info("  Listening on UDP 3702 multicast 239.255.255.250 ...")
    log.info("  TeSys Tera boot time is ~3.5 min — do NOT expect Hello before ~200 s.")
    log.info("  (Power-cycle the device now if needed.  Press Ctrl-C to cancel.)")

    MCAST_GRP = "239.255.255.250"
    target_mac_norm = TARGET_MAC.lower().replace("-", ":").replace(".", ":")

    # Try Scapy sniff first; fall back to raw socket if Scapy unavailable
    if SCAPY_OK:
        hello_received: list = []

        def _handle(pkt):
            if not (Ether in pkt and UDP in pkt):
                return
            src_mac = pkt[Ether].src.lower()
            if src_mac != target_mac_norm:
                return
            if pkt[UDP].sport != 3702:
                return
            try:
                payload = bytes(pkt[UDP].payload).decode("utf-8", errors="replace")
                if "Hello" in payload and "discovery" in payload.lower():
                    log.info("  [HELLO] WS-Discovery Hello received from %s", src_mac)
                    hello_received.append(True)
                    return True  # stop sniff
                if "Bye" in payload:
                    log.info("  [BYE] WS-Discovery Bye received — device is shutting down, "
                             "waiting for Hello ...")
            except Exception:
                pass

        from scapy.all import sniff as _sniff
        _sniff(iface=SCAPY_IFACE,
               filter="udp and port 3702",
               prn=_handle,
               stop_filter=lambda p: bool(hello_received),
               timeout=timeout,
               store=False)
        if hello_received:
            log.info("  Waiting %.1f s for PROFINET RPC stack to initialise ...", post_hello_delay)
            time.sleep(post_hello_delay)
            return True
        log.warning("  Timeout — no WS-Discovery Hello received from %s in %.0f s",
                    TARGET_MAC, timeout)
        return False

    # Fallback: plain multicast socket (no Scapy)
    import struct as _struct
    sock = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM, _sk.IPPROTO_UDP)
    sock.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
    sock.bind(("", 3702))
    mreq = _struct.pack("4sL", _sk.inet_aton(MCAST_GRP), _sk.INADDR_ANY)
    sock.setsockopt(_sk.IPPROTO_IP, _sk.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(5.0)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                xml = data.decode("utf-8", errors="replace")
                if "Hello" in xml and addr[0] == TARGET_IP:
                    log.info("  [HELLO] WS-Discovery Hello received from %s", addr[0])
                    sock.close()
                    log.info("  Waiting %.1f s for PROFINET RPC stack ...", post_hello_delay)
                    time.sleep(post_hello_delay)
                    return True
                if "Bye" in xml and addr[0] == TARGET_IP:
                    log.info("  [BYE] WS-Discovery Bye from %s — waiting for Hello ...", addr[0])
            except _sk.timeout:
                pass
    finally:
        sock.close()
    log.warning("  Timeout — no WS-Discovery Hello received in %.0f s", timeout)
    return False


def pnio_force_release(timeout: float = 5.0) -> bool:
    """
    Attempt a 'blind' PROFINET AR Release (opnum=1) without a prior Connect.

    Uses the CMD Object UUID (dea00000-...-000107010129) which the device recognises
    and processes at PNIO level (returns RSP, not REJECT).  Sends two attempts:
      - ARUUID = all-zeros   (some devices treat this as 'release any AR')
      - ARUUID = random UUID  (compliant fallback)

    If the device releases its ghost AR, subsequent AR Connect will succeed.
    Returns True if at least one attempt received a success response (error=0).
    """
    import socket as _socket

    sport = random.randint(49152, 65535)
    act_uuid = uuid.uuid4()

    def _try_release(ar_uuid_val: uuid.UUID, sess_key: int, label: str) -> bool:
        body  = struct.pack(">H", 0x0000)
        body += _u(ar_uuid_val)
        body += struct.pack(">H", sess_key)
        body += struct.pack(">H", 0x0000)
        body += struct.pack(">HH", 0x0004, 0x0000)   # ControlCommand=Release
        block = _block(0x0114, body)
        blen  = len(block)
        ndr_prefix = struct.pack("<IIIII", blen, blen, blen, 0, blen)
        stub = ndr_prefix + block

        pkt = build_request(
            seq_num=0, opnum=OP_RELEASE,
            obj_uuid=PNIO_CMD_OBJ_UUID,
            if_uuid=PNIO_CM_IF_UUID,
            act_uuid=act_uuid,
            stub=stub,
            wire_profile=COMMANDER_WIRE_PROFILE,   # must match Connect flags1=0x20
        )

        for dport in (PNIO_UDP_PORT, PNIO_AR_SESSION_PORT):
            xport = ScapyTransport(
                iface=SCAPY_IFACE,
                src_mac=CONTROLLER_MAC, src_ip=CONTROLLER_IP,
                dst_mac=TARGET_MAC, dst_ip=TARGET_IP,
                sport=sport, dport=dport,
            )
            log.info("  Blind Release %s  ARUUID=%s  sess=%d  dport=%d",
                     label, ar_uuid_val, sess_key, dport)
            resp = xport.send_recv(pkt, f"BlindRelease-{label}-{dport}", timeout)
            xport.close()

            if resp is None:
                log.warning("    No response (timeout) on port %d", dport)
                continue

            rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
            if rpc_ptype == 0x02:
                stub_body = resp[80:]
                if len(stub_body) >= 4:
                    err = struct.unpack_from(">I", stub_body, 0)[0]
                    if err == 0:
                        log.info("    Blind Release ACCEPTED (error=0) on port %d -- ghost AR cleared!",
                                 dport)
                        return True
                    ec1 = (err >> 8) & 0xFF
                    log.info("    Blind Release port %d: PNIO error 0x%08x (Code1=0x%02x)",
                             dport, err, ec1)
            elif rpc_ptype == 0x06:
                log.warning("    Blind Release port %d: DCE/RPC REJECT", dport)
            else:
                log.warning("    Blind Release port %d: unexpected ptype=0x%02x", dport, rpc_ptype)
        return False

    log.info("Attempting blind PROFINET AR Release to clear ghost AR ...")
    ok = _try_release(uuid.UUID(int=0), 1, "zeros/sess1")
    if not ok:
        ok = _try_release(uuid.UUID(int=0), 2, "zeros/sess2")
    if not ok:
        # Try the known ghost AR UUID from the Siemens PLC demo session
        log.info("  Trying known ghost AR UUID from demo pcap ...")
        ok = _try_release(DEMO_GHOST_AR_UUID, DEMO_GHOST_AR_SESSKEY, "demo-uuid/sess2")
    if not ok:
        ok = _try_release(DEMO_GHOST_AR_UUID, 1, "demo-uuid/sess1")
    if not ok:
        log.warning("  Blind Release did not succeed -- ghost AR is firmly locked")
    return ok


def tcp_port_probe(ip: str, ports: list, timeout: float = 2.0) -> dict:
    """
    Probe a list of TCP ports.  Returns dict of {port: bool}.
    Used to discover non-PROFINET channels (HTTP/80, Modbus/502, HTTPS/443).
    """
    import socket as _sock
    results = {}
    for port in ports:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            results[port] = True
            s.close()
        except Exception:
            results[port] = False
    return results


def tcp_port_scan(ip: str, ports: list, timeout: float = 1.5) -> list:
    """Quick TCP connect scan on a list of ports. Returns list of open port numbers."""
    import socket as _sock
    open_ports = []
    for port in ports:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def snmp_probe(ip: str, community: str = "public", timeout: float = 3.0) -> dict:
    """
    Send SNMP v1 GetRequest for sysDescr (OID 1.3.6.1.2.1.1.1.0) and
    sysName (OID 1.3.6.1.2.1.1.5.0) via raw UDP.
    Returns {'alive': bool, 'sysDescr': str, 'sysName': str}.
    """
    import socket as _sock

    def _build_snmp_get(community: str, oid: bytes) -> bytes:
        """Build minimal SNMPv1 GetRequest PDU for a single OID."""
        # VarBind: OID + NULL value
        var_bind = b"\x30" + bytes([2 + len(oid)]) + b"\x06" + bytes([len(oid)]) + oid + b"\x05\x00"
        # VarBindList
        vbl = b"\x30" + bytes([len(var_bind)]) + var_bind
        # PDU (type=0xA0 GetRequest, request-id=1, error=0, error-index=0)
        pdu_inner = b"\x02\x01\x01\x02\x01\x00\x02\x01\x00" + vbl
        pdu = b"\xa0" + bytes([len(pdu_inner)]) + pdu_inner
        # Community string
        comm_bytes = community.encode()
        comm_asn = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
        # Version = 0 (v1)
        ver = b"\x02\x01\x00"
        # Sequence
        seq_inner = ver + comm_asn + pdu
        return b"\x30" + bytes([len(seq_inner)]) + seq_inner

    # OIDs: sysDescr=1.3.6.1.2.1.1.1.0, sysName=1.3.6.1.2.1.1.5.0
    OID_SYSDESCR = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    OID_SYSNAME  = bytes([0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00])

    result = {'alive': False, 'sysDescr': '', 'sysName': ''}

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        s.settimeout(timeout)
        s.bind(("", 0))
    except Exception as e:
        log.debug("SNMP socket error: %s", e)
        return result

    try:
        for label, oid in [("sysDescr", OID_SYSDESCR), ("sysName", OID_SYSNAME)]:
            pkt = _build_snmp_get(community, oid)
            try:
                s.sendto(pkt, (ip, 161))
                resp, _ = s.recvfrom(65535)
                result['alive'] = True
                # Extract OctetString value from response (very naive parse)
                idx = resp.find(b"\x04")
                if idx >= 0 and idx + 1 < len(resp):
                    slen = resp[idx + 1]
                    val = resp[idx + 2:idx + 2 + slen].decode("latin-1", errors="replace")
                    result[label] = val
            except _sock.timeout:
                pass
    except Exception as e:
        log.debug("SNMP probe error: %s", e)
    finally:
        s.close()

    return result


def ethernetip_probe(ip: str, timeout: float = 3.0) -> dict:
    """
    Probe EtherNet/IP (CIP) port 44818 with a ListIdentity request.
    Returns {'alive': bool, 'product_name': str, 'vendor_id': int, 'device_type': int}.
    """
    import socket as _sock
    import struct as _st

    # EtherNet/IP ListIdentity command (0x0063), no data
    LI_CMD = _st.pack("<HHIIQH", 0x0063, 0, 0, 0, 0, 0)  # Encap header only

    result = {'alive': False, 'product_name': '', 'vendor_id': 0, 'device_type': 0}
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 44818))
        s.sendall(LI_CMD)
        resp = s.recv(1024)
        s.close()
        if len(resp) > 24:
            result['alive'] = True
            # Parse Identity object from CIP response (vendor ID at offset 28+2)
            try:
                vendor_id = _st.unpack_from("<H", resp, 30)[0]
                dev_type  = _st.unpack_from("<H", resp, 32)[0]
                result['vendor_id'] = vendor_id
                result['device_type'] = dev_type
                # product name: length-prefixed string after device info
                name_start = 44
                if name_start < len(resp):
                    name_len = resp[name_start]
                    result['product_name'] = resp[name_start+1:name_start+1+name_len].decode("latin-1", errors="replace")
            except Exception:
                pass
    except Exception as e:
        log.debug("EtherNet/IP probe error: %s", e)
    return result


def modbus_extended_probe(ip: str, timeout: float = 4.0) -> dict:
    """
    Extended Modbus TCP probe with multiple unit IDs and register addresses.
    Tries unit IDs: 0x01, 0xFF, 0x00, 0x02.
    Tries FC03 at multiple starting addresses.
    Returns {'alive': bool, 'unit_id': int, 'regs': list}.
    """
    import socket as _sock
    import struct as _st

    result = {'alive': False, 'unit_id': None, 'regs': []}

    # Addresses to try for FC03 read (holding registers)
    READ_ADDRS = [
        (0x0000, 4),   # common start
        (0x0001, 4),   # 1-based Modbus addr
        (0x0064, 4),   # decimal 100 - common TeSys status
        (0x0100, 4),   # PNU block start
        (0x0200, 4),
    ]

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 502))
        log.info("  Modbus Extended: connected to %s:502", ip)
    except Exception as e:
        log.info("  Modbus Extended: port 502 not reachable (%s)", e)
        return result

    tid = 1
    try:
        for unit_id in [0x01, 0xFF, 0x00, 0x02]:
            for addr, count in READ_ADDRS:
                pdu = bytes([0x03]) + _st.pack(">HH", addr, count)
                mbap = _st.pack(">HHH", tid, 0, len(pdu) + 1) + bytes([unit_id])
                tid += 1
                try:
                    s.sendall(mbap + pdu)
                    s.settimeout(2.0)
                    resp = b""
                    while len(resp) < 9:
                        chunk = s.recv(256)
                        if not chunk:
                            break
                        resp += chunk
                        if len(resp) >= 9:
                            break
                    if resp and len(resp) >= 9:
                        fc = resp[7]
                        if fc == 0x03:
                            nb = resp[8]
                            regs = [_st.unpack_from(">H", resp, 9+i*2)[0]
                                    for i in range(nb//2)]
                            log.info("  Modbus FC03 unit=%d addr=0x%04X: regs=%s", unit_id, addr, regs)
                            result['alive'] = True
                            result['unit_id'] = unit_id
                            result['regs'] = regs
                        elif fc & 0x80:
                            ec = resp[8] if len(resp) > 8 else 0
                            log.info("  Modbus FC03 unit=%d addr=0x%04X: exception 0x%02X", unit_id, addr, ec)
                            result['alive'] = True
                        else:
                            log.debug("  Modbus unexpected FC=0x%02X", fc)
                    if result['alive']:
                        # Also try FC06 write for PROFINET reset on confirmed-alive unit ID
                        for write_addr, write_val, note in [
                            (0x0128, 0x0001, "comm-fault-reset PNU296"),
                            (0x012A, 0x0001, "PROFINET-reset PNU298"),
                            (0x012C, 0x0001, "factory-reset PNU300"),
                            (0x0001, 0x0001, "control-word bit0"),
                        ]:
                            pdu6 = bytes([0x06]) + _st.pack(">HH", write_addr, write_val)
                            mbap6 = _st.pack(">HHH", tid, 0, len(pdu6)+1) + bytes([unit_id])
                            tid += 1
                            s.sendall(mbap6 + pdu6)
                            s.settimeout(2.0)
                            r6 = b""
                            try:
                                r6 = s.recv(256)
                            except _sock.timeout:
                                pass
                            if r6 and len(r6) >= 8:
                                fc6 = r6[7]
                                if fc6 == 0x06:
                                    log.info("  Modbus FC06 write addr=0x%04X val=0x%04X ACK! (%s)", write_addr, write_val, note)
                                elif fc6 & 0x80:
                                    ec6 = r6[8] if len(r6) > 8 else 0
                                    log.info("  Modbus FC06 write addr=0x%04X: exception 0x%02X (%s)", write_addr, ec6, note)
                        break
                except _sock.timeout:
                    pass
            if result['alive']:
                break
    finally:
        try:
            s.close()
        except Exception:
            pass

    if not result['alive']:
        log.info("  Modbus Extended: no Modbus response from any unit ID or address")
    return result


def probe_port_8080(ip: str, timeout: float = 5.0) -> None:
    """
    Deep probe of HTTP port 8080 on TeSys Tera.

    Port 8080: TCP accepts connections but echoes back the HTTP request line - NOT plain HTTP.
    Possibilities: HTTPS on 8080, HTTP/1.0 only, or a proprietary binary protocol.
    This function tries: raw TCP (see what device says first), HTTP/1.0, HTTPS, binary probes.
    """
    import socket as _sock
    import ssl as _ssl
    import uuid as _uuid
    import requests as _req
    import warnings as _w

    # --- 1. Raw TCP: connect, send nothing, see if device sends a banner ---
    log.info("  8080 raw TCP banner probe ...")
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 8080))
        s.settimeout(3.0)
        try:
            banner = s.recv(1024)
            log.info("  8080 raw banner: %s", banner[:200])
        except _sock.timeout:
            log.info("  8080 raw banner: (server sent nothing - not a banner protocol)")
        s.close()
    except Exception as e:
        log.info("  8080 raw TCP: ERROR %s", e)

    # --- 2. HTTPS on port 8080 ---
    log.info("  8080 HTTPS probe ...")
    try:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        ss = ctx.wrap_socket(s, server_hostname=ip)
        ss.connect((ip, 8080))
        req = b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
        ss.sendall(req)
        ss.settimeout(3.0)
        resp = b""
        try:
            while True:
                c = ss.recv(1024)
                if not c:
                    break
                resp += c
                if len(resp) > 4096:
                    break
        except _sock.timeout:
            pass
        ss.close()
        if resp:
            log.info("  8080 HTTPS response (%d bytes): %s", len(resp), resp[:800])
        else:
            log.info("  8080 HTTPS: connected but no response")
    except Exception as e:
        log.info("  8080 HTTPS: ERROR %s", e)

    # --- 3. HTTP/1.0 raw request (bypass requests library) ---
    log.info("  8080 HTTP/1.0 raw probe ...")
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 8080))
        req = b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n"
        s.sendall(req)
        s.settimeout(3.0)
        resp = b""
        try:
            while True:
                c = s.recv(1024)
                if not c:
                    break
                resp += c
        except _sock.timeout:
            pass
        s.close()
        if resp:
            log.info("  8080 HTTP/1.0 raw response (%d bytes): %s", len(resp), resp[:800])
        else:
            log.info("  8080 HTTP/1.0: connected but no response")
    except Exception as e:
        log.info("  8080 HTTP/1.0 raw: ERROR %s", e)

    # --- 4. WS-Management (WS-Man) POST with SOAP (port 8080 is the WS-Man default) ---
    log.info("  8080 WS-Management probe ...")
    wsman_identify = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        '  xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">'
        '<soap:Header/>'
        '<soap:Body><wsmid:Identify/></soap:Body>'
        '</soap:Envelope>'
    )
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 8080))
        body_b = wsman_identify.encode()
        hdr = (f"POST /wsman HTTP/1.1\r\n"
               f"Host: {ip}:8080\r\n"
               f"Content-Type: application/soap+xml; charset=UTF-8\r\n"
               f"Content-Length: {len(body_b)}\r\n"
               f"Connection: close\r\n\r\n")
        s.sendall(hdr.encode() + body_b)
        s.settimeout(3.0)
        resp = b""
        try:
            while True:
                c = s.recv(2048)
                if not c:
                    break
                resp += c
        except _sock.timeout:
            pass
        s.close()
        if resp:
            log.info("  8080 WS-Man response (%d bytes): %s", len(resp), resp[:800])
        else:
            log.info("  8080 WS-Man: connected but no response")
    except Exception as e:
        log.info("  8080 WS-Man raw: ERROR %s", e)

    # --- 5. Proprietary Schneider EcoReach / EcoStruxure binary probe ---
    #  Some SE devices use a length-prefixed binary framing on port 8080.
    #  Send a minimal frame and observe response.
    log.info("  8080 Schneider EcoReach binary probe ...")
    for probe_bytes in [
        b"\x00\x00\x00\x04\x00\x00\x00\x00",             # 4-byte length + payload
        b"\x00\x01\x00\x00",                              # minimal header
        b"SE\x00\x01",                                    # magic "SE" prefix
        b"\x1a\x00\x00\x00\x00\x00\x00\x01",             # common SE device header
    ]:
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, 8080))
            s.sendall(probe_bytes)
            s.settimeout(2.0)
            resp = b""
            try:
                resp = s.recv(512)
            except _sock.timeout:
                pass
            s.close()
            if resp:
                log.info("  8080 binary probe 0x%-20s => 0x%s", probe_bytes.hex(), resp.hex()[:80])
            else:
                log.info("  8080 binary probe 0x%-20s => (no response)", probe_bytes.hex())
        except Exception as e:
            log.info("  8080 binary probe error: %s", e)

    import requests as _req
    import warnings as _w
    import uuid as _uuid

    BASE = f"http://{ip}:8080"

    def _get(path: str) -> None:
        try:
            with _w.catch_warnings():
                _w.simplefilter("ignore")
                r = _req.get(BASE + path, timeout=timeout, allow_redirects=False)
            log.info("  8080 GET %-25s  %s  (%d bytes)", path, r.status_code, len(r.content))
            body = r.text[:2000]
            if body.strip():
                log.info("  8080 body: %s", body[:600])
        except Exception as e:
            log.info("  8080 GET %-25s  ERROR: %s", path, e)

    def _soap_post(path: str, soap_body: str, action: str, label: str) -> None:
        hdrs = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": f'"{action}"',
        }
        try:
            with _w.catch_warnings():
                _w.simplefilter("ignore")
                r = _req.post(BASE + path, data=soap_body.encode(), headers=hdrs,
                              timeout=timeout, allow_redirects=False)
            log.info("  8080 SOAP %-20s  %s  (%d bytes)", label, r.status_code, len(r.content))
            if r.text.strip():
                log.info("  8080 SOAP body: %s", r.text[:800])
        except Exception as e:
            log.info("  8080 SOAP %-20s  ERROR: %s", label, e)

    # HTTP GET probes
    for path in ["/", "/index.html", "/profinet", "/management", "/api",
                 "/reset", "/services", "/wsdl", "/config", "/status"]:
        _get(path)

    # SOAP WS-Transfer Get (same as port 80, but maybe different response here)
    ws_get = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        '  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        '<soap:Header>'
        '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>'
        f'<wsa:MessageID>uuid:{_uuid.uuid4()}</wsa:MessageID>'
        '<wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>'
        '</soap:Header><soap:Body/></soap:Envelope>'
    )
    _soap_post("/", ws_get, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get", "WS-Transfer-Get")

    # WS-Discovery Probe via HTTP (some DPWS devices accept UDP probe over HTTP too)
    ws_probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        '  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        '  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<soap:Header>'
        '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
        f'<wsa:MessageID>uuid:{_uuid.uuid4()}</wsa:MessageID>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        '</soap:Header>'
        '<soap:Body><wsd:Probe><wsd:Types/></wsd:Probe></soap:Body>'
        '</soap:Envelope>'
    )
    _soap_post("/", ws_probe, "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe", "WSD-Probe")

    # Schneider Electric proprietary SOAP (from known SE device service schemas)
    for action_ns, action_name, path in [
        ("http://schneider-electric.com/profinet/management", "Reset",             "/profinet"),
        ("http://schneider-electric.com/profinet/management", "DisconnectAR",      "/profinet"),
        ("http://www.schneider-electric.com/management",      "FactoryReset",      "/management"),
        ("http://www.schneider-electric.com/management",      "ProfinetReset",     "/management"),
        ("urn:schneider-electric:tesys:profinet",             "DisconnectDevice",  "/"),
    ]:
        action = f"{action_ns}/{action_name}"
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            '  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            '<soap:Header>'
            f'<wsa:Action>{action}</wsa:Action>'
            f'<wsa:MessageID>uuid:{_uuid.uuid4()}</wsa:MessageID>'
            '</soap:Header>'
            f'<soap:Body><{action_name}/></soap:Body>'
            '</soap:Envelope>'
        )
        _soap_post(path, body, action, action_name[:20])


def modbus_fc04_and_targeted_writes(ip: str, timeout: float = 8.0) -> None:
    """
    Modbus unit 0xFF is confirmed alive.

    1. FC04 Read Input Registers - TeSys Tera uses FC04 for status/data (not FC03)
    2. FC03 Read Holding Registers at addresses 0x0064-0x0200 (beyond the failed 0x0000)
    3. FC06 Write Single Register with multiple values at the known addresses
       (0x0128, 0x012A, 0x012C got exception 0x03 = wrong value, not missing address)
    4. FC16 Write Multiple Registers as alternative write method
    """
    import socket as _sock
    import struct as _st

    UNIT = 0xFF

    def _mbap(tid: int, pdu: bytes) -> bytes:
        return _st.pack(">HHH", tid, 0, len(pdu) + 1) + bytes([UNIT]) + pdu

    def _xact(s, tid: list, pdu: bytes, label: str) -> bytes | None:
        tid[0] += 1
        try:
            s.sendall(_mbap(tid[0], pdu))
            s.settimeout(2.5)
            buf = b""
            while len(buf) < 9:
                c = s.recv(512)
                if not c:
                    break
                buf += c
                if len(buf) >= 9:
                    break
            if buf:
                fc = buf[7] if len(buf) > 7 else 0
                if fc & 0x80:
                    ec = buf[8] if len(buf) > 8 else 0
                    log.info("  MB %-35s  exception 0x%02X", label, ec)
                else:
                    log.info("  MB %-35s  FC=0x%02X  raw=%s", label, fc, buf[7:].hex())
                return buf
            else:
                log.info("  MB %-35s  no response", label)
                return None
        except _sock.timeout:
            log.info("  MB %-35s  timeout", label)
            return None

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 502))
        log.info("  Modbus FC04/FC06 probe: connected to %s:502 unit=0xFF", ip)
    except Exception as e:
        log.info("  Modbus FC04/FC06: cannot connect: %s", e)
        return

    tid = [0]
    try:
        # --- FC04 Read Input Registers (TeSys Tera status registers) ---
        for addr, cnt in [(0x0000, 8), (0x0001, 8), (0x0064, 8), (0x0100, 8),
                          (0x0200, 8), (0x0050, 8), (0x0080, 8)]:
            pdu = bytes([0x04]) + _st.pack(">HH", addr, cnt)
            _xact(s, tid, pdu, f"FC04 Read Input addr=0x{addr:04X} cnt={cnt}")

        # --- FC03 Read Holding Registers at broader addresses ---
        for addr, cnt in [(0x0010, 4), (0x0064, 4), (0x00C8, 4), (0x0100, 4), (0x01F4, 4)]:
            pdu = bytes([0x03]) + _st.pack(">HH", addr, cnt)
            _xact(s, tid, pdu, f"FC03 Read Hold addr=0x{addr:04X} cnt={cnt}")

        # --- FC06 Write Single Register: try multiple values at known addresses ---
        # We know 0x0001 caused exception 0x03 - try 0x0000, 0x0002, 0x0003, 0x00FF, 0x0100
        for addr, val, note in [
            # Try value 0x0000 (disable/reset) at all known register addresses
            (0x0128, 0x0000, "PNU296 comm-reset val=0"),
            (0x012A, 0x0000, "PNU298 PN-reset val=0"),
            (0x012C, 0x0000, "PNU300 fac-reset val=0"),
            # Try value 2 (often used as "execute" command in SE devices)
            (0x0128, 0x0002, "PNU296 comm-reset val=2"),
            (0x012A, 0x0002, "PNU298 PN-reset val=2"),
            # Try value 0x00FF (full reset mask)
            (0x0128, 0x00FF, "PNU296 comm-reset val=0xFF"),
            (0x012A, 0x00FF, "PNU298 PN-reset val=0xFF"),
            # Write to low holding register (control word)
            (0x0003, 0x0001, "ctrl-word addr=3 val=1"),
            (0x0004, 0x0001, "ctrl-word addr=4 val=1"),
        ]:
            pdu = bytes([0x06]) + _st.pack(">HH", addr, val)
            _xact(s, tid, pdu, f"FC06 Write 0x{addr:04X}=0x{val:04X} ({note})")

        # --- FC16 Write Multiple Registers (alternative to FC06) ---
        for addr, values, note in [
            (0x0128, [0x0001], "PNU296 FC16"),
            (0x012A, [0x0001], "PNU298 FC16"),
        ]:
            data = b"".join(_st.pack(">H", v) for v in values)
            pdu = bytes([0x10]) + _st.pack(">HH", addr, len(values)) + bytes([len(data)]) + data
            _xact(s, tid, pdu, f"FC16 Write 0x{addr:04X} ({note})")

        # --- FC05 Write Single Coil (some SE devices use coils for reset commands) ---
        for addr, val, note in [
            (0x0000, 0xFF00, "coil 0 ON"),
            (0x0001, 0xFF00, "coil 1 ON"),
            (0x0100, 0xFF00, "coil 256 ON"),
        ]:
            pdu = bytes([0x05]) + _st.pack(">HH", addr, val)
            _xact(s, tid, pdu, f"FC05 Coil 0x{addr:04X}={'ON' if val==0xFF00 else 'OFF'} ({note})")

    finally:
        try:
            s.close()
        except Exception:
            pass


def full_device_scan(ip: str) -> None:
    """
    Full scan of TeSys Tera device on all known industrial ports.
    Runs TCP port scan, SNMP, EtherNet/IP, extended Modbus.
    """
    SCAN_PORTS = [
        # Web / management
        80, 443, 8080, 8443, 8888, 8889,
        # PROFINET
        34964, 49153, 49154,
        # Modbus TCP
        502,
        # EtherNet/IP (CIP)
        44818, 2222,
        # OPC-UA
        4840,
        # SNMP (TCP)
        161, 10161,
        # SFTP/SSH/Telnet
        21, 22, 23,
        # Other industrial
        1025, 1026, 5000, 5001, 9999, 10000, 10001,
        # DPWS / WS-Discovery
        3702, 5357, 5358,
    ]

    log.info("-- TCP port scan on %s --", ip)
    open_ports = tcp_port_scan(ip, SCAN_PORTS, timeout=1.5)
    log.info("  Open TCP ports: %s", open_ports if open_ports else "(none found in scan list)")

    # --- Port 8080 probe (newly discovered open port) ---
    if 8080 in open_ports:
        log.info("-- Port 8080 deep probe (HTTP management?) --")
        probe_port_8080(ip)

    log.info("-- SNMP (UDP 161) probe --")
    snmp_r = snmp_probe(ip, community="public", timeout=3.0)
    if snmp_r['alive']:
        log.info("  SNMP alive! sysDescr=%r  sysName=%r", snmp_r['sysDescr'], snmp_r['sysName'])
    else:
        snmp_r2 = snmp_probe(ip, community="private", timeout=3.0)
        if snmp_r2['alive']:
            log.info("  SNMP alive (community=private)! sysDescr=%r  sysName=%r",
                     snmp_r2['sysDescr'], snmp_r2['sysName'])
        else:
            log.info("  SNMP: no response (port 161 UDP not open or community mismatch)")

    log.info("-- EtherNet/IP CIP (TCP 44818) probe --")
    eip_r = ethernetip_probe(ip, timeout=3.0)
    if eip_r['alive']:
        log.info("  EtherNet/IP alive! vendor_id=0x%04X device_type=0x%04X product=%r",
                 eip_r['vendor_id'], eip_r['device_type'], eip_r['product_name'])
    else:
        log.info("  EtherNet/IP: port 44818 not reachable")

    log.info("-- Extended Modbus TCP (port 502) probe --")
    mb_r = modbus_extended_probe(ip, timeout=4.0)
    log.info("  Modbus Extended result: alive=%s unit_id=%s regs=%s",
             mb_r['alive'], mb_r['unit_id'], mb_r['regs'])

    # --- Modbus FC04 + FC06 targeted probe (unit 0xFF confirmed alive) ---
    log.info("-- Modbus FC04 (Input Registers) + FC06 targeted write probe --")
    modbus_fc04_and_targeted_writes(ip, timeout=8.0)


def modbus_tcp_force_ar_release(ip: str, timeout: float = 4.0) -> bool:
    """
    Attempt to release the ghost PROFINET AR via Modbus TCP (port 502).

    TeSys Tera supports Modbus TCP.  Schneider Electric TeSys devices expose
    communication fault reset and factory reset via holding registers.
    Returns True if any Modbus response (ACK or exception) was received.
    """
    import socket as _sock
    import struct as _struct

    def _send_recv(s, pdu: bytes, tid: int, recv_timeout: float = 3.0) -> bytes | None:
        """Build MBAP+PDU, send, recv. Returns full response or None."""
        # Standard MBAP: TransID(2)+ProtoID(2)+Length(2)+UnitID(1) = 7 bytes
        mbap = _struct.pack(">HHH", tid, 0, len(pdu) + 1) + b"\x01"
        try:
            s.sendall(mbap + pdu)
            s.settimeout(recv_timeout)
            resp = b""
            while len(resp) < 256:
                try:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) >= 9:   # minimum valid Modbus TCP response
                        break
                except _sock.timeout:
                    break
            return resp if resp else None
        except Exception:
            return None

    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, 502))
        log.info("  Modbus TCP: connected to %s:502", ip)
    except Exception as e:
        log.info("  Modbus TCP: port 502 not reachable (%s)", e)
        return False

    alive = False
    try:
        # FC03 Read Holding Registers (addr=0x0000, count=4) - device info
        pdu_read = b"\x03\x00\x00\x00\x04"
        resp = _send_recv(s, pdu_read, tid=1)
        if resp:
            fc = resp[7] & 0x7F if len(resp) > 7 else 0
            if fc == 0x03:
                nregs = resp[8] // 2 if len(resp) > 8 else 0
                regs = [_struct.unpack_from(">H", resp, 9 + i*2)[0]
                        for i in range(min(nregs, 4))]
                log.info("  Modbus TC FC03 read regs[0:4] = %s - device is Modbus-accessible!", regs)
                alive = True
            elif resp[7] & 0x80:
                ec = resp[8] if len(resp) > 8 else 0
                log.info("  Modbus FC03 exception code=0x%02x - Modbus alive but read rejected", ec)
                alive = True
            else:
                log.info("  Modbus response raw[7:12]=%s", resp[7:12].hex())
                alive = True
        else:
            log.info("  Modbus FC03 read: no response (device may not support FC03 at addr 0)")

        # FC06 Write Single Register: address 0x0128 (PNU 296 - 'Communication Fault Reset')
        # Value 0x0001 = trigger reset
        pdu_rst = b"\x06\x01\x28\x00\x01"
        resp2 = _send_recv(s, pdu_rst, tid=2)
        if resp2 and len(resp2) > 7:
            fc2 = resp2[7] & 0x7F
            if fc2 == 0x06:
                log.info("  Modbus FC06 write addr=0x0128 (comm-fault-reset) ACK - may clear PROFINET AR!")
                alive = True
            elif resp2[7] & 0x80:
                ec2 = resp2[8] if len(resp2) > 8 else 0
                log.info("  Modbus FC06 addr=0x0128: exception code=0x%02x", ec2)
                alive = True

        # FC06 Write to address 0x012A (PNU 298 - 'PROFINET Reset' on some TeSys FW)
        pdu_pn_rst = b"\x06\x01\x2a\x00\x01"
        resp3 = _send_recv(s, pdu_pn_rst, tid=3)
        if resp3 and len(resp3) > 7:
            fc3 = resp3[7] & 0x7F
            if fc3 == 0x06:
                log.info("  Modbus FC06 write addr=0x012A (PROFINET reset) ACK!")
                alive = True
            elif resp3[7] & 0x80:
                ec3 = resp3[8] if len(resp3) > 8 else 0
                log.info("  Modbus FC06 addr=0x012A: exception code=0x%02x", ec3)

        # FC06 Write to address 0x012C (PNU 300 - factory defaults on some FW)
        pdu_fac = b"\x06\x01\x2c\x00\x01"
        resp4 = _send_recv(s, pdu_fac, tid=4)
        if resp4 and len(resp4) > 7:
            fc4 = resp4[7] & 0x7F
            if fc4 == 0x06:
                log.info("  Modbus FC06 write addr=0x012C (factory-reset) ACK!")
                alive = True
            elif resp4[7] & 0x80:
                ec4 = resp4[8] if len(resp4) > 8 else 0
                log.info("  Modbus FC06 addr=0x012C: exception code=0x%02x", ec4)

    except Exception as e:
        log.warning("  Modbus TCP: error during exchange: %s", e)
    finally:
        s.close()

    return alive


def dpws_discover_and_probe(ip: str, timeout: float = 5.0) -> dict:
    """
    DPWS (Devices Profile for Web Services) discovery and metadata probe.

    Step 1: WS-Discovery UDP probe (multicast 239.255.255.250:3702 + unicast ip:3702)
            - get device EPR address (urn:uuid:...) and XAddrs (service endpoints)
    Step 2: WS-Transfer Get to XAddrs with proper wsa:To = device EPR
            - full metadata INCLUDING Relationship section (lists hosted service URIs)
    Step 3: Try any functional service endpoints found

    Returns dict: {'epr': str, 'xaddrs': list, 'services': list, 'raw_meta': str}
    """
    import socket as _sock
    import uuid as _uuid

    msg_id = str(_uuid.uuid4())

    PROBE_SOAP = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        '  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        '  xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        '<soap:Header>'
        '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
        f'<wsa:MessageID>uuid:{msg_id}</wsa:MessageID>'
        '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
        '</soap:Header>'
        '<soap:Body><wsd:Probe><wsd:Types/></wsd:Probe></soap:Body>'
        '</soap:Envelope>'
    )

    result: dict = {'epr': None, 'xaddrs': [], 'services': [], 'raw_meta': ''}

    def _udp_probe(dest_ip: str, dest_port: int) -> str:
        """Send WS-Discovery probe via UDP; return raw response or ''."""
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM, _sock.IPPROTO_UDP)
            s.settimeout(timeout)
            s.bind(("", 0))
            if dest_ip == "239.255.255.250":
                s.setsockopt(_sock.IPPROTO_IP, _sock.IP_MULTICAST_TTL, 2)
            s.sendto(PROBE_SOAP.encode(), (dest_ip, dest_port))
            try:
                data, _ = s.recvfrom(65535)
                return data.decode("utf-8", errors="replace")
            except _sock.timeout:
                return ""
        except Exception as e:
            log.debug("  DPWS UDP probe error: %s", e)
            return ""
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _extract_tag(xml: str, tag: str) -> str:
        """Naive single-tag extractor; handles namespace prefixes."""
        import re
        pattern = rf'<[^>]*:{re.escape(tag)}[^>]*>(.*?)<\/[^>]*:{re.escape(tag)}>'
        m = re.search(pattern, xml, re.DOTALL)
        if not m:
            pattern2 = rf'<{re.escape(tag)}[^>]*>(.*?)<\/{re.escape(tag)}>'
            m = re.search(pattern2, xml, re.DOTALL)
        return m.group(1).strip() if m else ""

    def _extract_all_tags(xml: str, tag: str) -> list:
        import re
        pattern = rf'<[^>]*:{re.escape(tag)}[^>]*>(.*?)<\/[^>]*:{re.escape(tag)}>'
        return re.findall(pattern, xml, re.DOTALL)

    # --- Step 1: WS-Discovery probe ---
    log.info("  DPWS: WS-Discovery UDP probe -> multicast 239.255.255.250:3702 ...")
    resp_mc = _udp_probe("239.255.255.250", 3702)
    if resp_mc:
        log.info("  DPWS: multicast ProbeMatches response received (%d bytes)", len(resp_mc))
        log.info("  DPWS: %s", resp_mc[:800])
    else:
        log.info("  DPWS: no multicast response; trying unicast %s:3702 ...", ip)
        resp_mc = _udp_probe(ip, 3702)
        if resp_mc:
            log.info("  DPWS: unicast response received (%d bytes)", len(resp_mc))
            log.info("  DPWS: %s", resp_mc[:800])
        else:
            log.info("  DPWS: no UDP WS-Discovery response (port 3702 may not be open)")

    # Parse EPR and XAddrs from WS-Discovery response
    if resp_mc:
        epr_raw = _extract_tag(resp_mc, "Address")
        if epr_raw:
            result['epr'] = epr_raw.strip()
            log.info("  DPWS: device EPR = %s", result['epr'])
        xaddrs_raw = _extract_tag(resp_mc, "XAddrs")
        if xaddrs_raw:
            result['xaddrs'] = xaddrs_raw.strip().split()
            log.info("  DPWS: XAddrs = %s", result['xaddrs'])

    # --- Step 2: WS-Transfer Get with device EPR ---
    # If we got the EPR from WS-Discovery, use it; otherwise try common patterns
    epr_candidates = []
    if result['epr']:
        epr_candidates.append(result['epr'])
    # TeSys Tera commonly uses urn:uuid based on MAC or serial
    # Try with FriendlyName as guessed UUID base
    epr_candidates += [
        f"urn:uuid:MMR0000001",
        f"urn:uuid:88-01-f9-35-d9-a2",
        f"urn:uuid:{TARGET_MAC.replace(':', '-')}",
        f"urn:uuid:00000000-0000-0000-0000-{TARGET_MAC.replace(':', '')}",
    ]

    def _ws_transfer_get(xaddr: str, epr: str) -> str:
        """WS-Transfer Get to xaddr with wsa:To=epr; return response body."""
        import requests as _req
        import warnings as _w

        get_soap = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            '  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
            '<soap:Header>'
            '<wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>'
            f'<wsa:MessageID>uuid:{_uuid.uuid4()}</wsa:MessageID>'
            f'<wsa:To>{epr}</wsa:To>'
            '</soap:Header>'
            '<soap:Body/>'
            '</soap:Envelope>'
        )

        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "SOAPAction": '"http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"',
        }
        try:
            with _w.catch_warnings():
                _w.simplefilter("ignore")
                r = _req.post(xaddr, data=get_soap.encode(), headers=headers,
                              timeout=timeout, verify=False)
            return r.text
        except Exception as e:
            log.debug("  DPWS WS-Transfer error to %s: %s", xaddr, e)
            return ""

    # Build list of endpoints to try (from XAddrs + fallback to IP)
    xaddr_candidates = result['xaddrs'] if result['xaddrs'] else [f"http://{ip}/"]

    log.info("  DPWS: WS-Transfer Get with EPR candidates ...")
    for epr in epr_candidates:
        for xaddr in xaddr_candidates:
            log.info("  DPWS: WS-Transfer Get  xaddr=%s  wsa:To=%s", xaddr, epr)
            meta = _ws_transfer_get(xaddr, epr)
            if meta and len(meta) > 100:
                log.info("  DPWS: response (%d bytes):\n%s", len(meta), meta[:3000])
                result['raw_meta'] = meta
                # Parse hosted services
                rel_sections = _extract_all_tags(meta, "MetadataSection")
                for sec in rel_sections:
                    if "Relationship" in sec:
                        log.info("  DPWS: found Relationship section!")
                        endpoints = _extract_all_tags(sec, "ServiceId")
                        addrs     = _extract_all_tags(sec, "Address")
                        log.info("  DPWS: hosted service IDs: %s", endpoints)
                        log.info("  DPWS: hosted service addrs: %s", addrs)
                        result['services'] = addrs
                if result['services']:
                    break
        if result['services']:
            break

    # --- Step 3: probe discovered service endpoints ---
    if result['services']:
        log.info("  DPWS: Probing %d discovered service endpoints ...", len(result['services']))
        for svc_addr in result['services']:
            log.info("  DPWS: -> %s", svc_addr)
            # Try a generic SOAP invoke on each endpoint
            try:
                raw_svc = _ws_transfer_get(svc_addr, svc_addr)
                if raw_svc:
                    log.info("  DPWS: service response: %s", raw_svc[:800])
            except Exception as e:
                log.debug("  DPWS service probe error: %s", e)
    else:
        log.info("  DPWS: no Relationship section found - device only exposes ThisModel/ThisDevice metadata")
        log.info("  DPWS: (this means no programmatic PROFINET reset API is available via DPWS)")

    return result


def http_probe_ar_release(ip: str, timeout: float = 8.0) -> bool:
    """
    Probe the TeSys Tera HTTP/HTTPS web interface for a PROFINET reset API.

    The device was observed to redirect HTTP/80 -> HTTPS/443 and to respond to
    POST /reset_profinet with 200 OK and Content-Type: application/soap+xml.
    This function:
      1. Reads the full SOAP body from that POST response
      2. Tries various SOAP payloads to request a PROFINET AR reset
      3. Probes HTTPS/443 with the same requests
      4. Probes port 8889 (WS-Management, used by some Schneider products)

    Returns True if any HTTP/HTTPS response was received (200 or otherwise).
    """
    import socket as _sock
    import ssl as _ssl

    def _raw_http(host: str, port: int, method: str, path: str,
                  body: str = "", use_ssl: bool = False,
                  extra_headers: str = "") -> bytes:
        """Low-level HTTP/HTTPS request; returns full raw bytes."""
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if use_ssl:
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            body_b = body.encode("utf-8") if body else b""
            ct = "application/soap+xml; charset=utf-8" if body else "text/plain"
            hdr  = f"{method} {path} HTTP/1.1\r\n"
            hdr += f"Host: {host}\r\n"
            hdr += f"Content-Type: {ct}\r\n"
            hdr += f"Content-Length: {len(body_b)}\r\n"
            hdr += extra_headers
            hdr += "Connection: close\r\n\r\n"
            s.sendall(hdr.encode() + body_b)
            buf = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return buf
        except Exception as e:
            return b""
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _parse_http(raw: bytes):
        """Split raw HTTP bytes -> (status_line, headers_str, body_bytes)."""
        sep = raw.find(b"\r\n\r\n")
        if sep < 0:
            return "", raw.decode("latin-1", errors="replace"), b""
        head = raw[:sep].decode("latin-1", errors="replace")
        body = raw[sep + 4:]
        lines = head.split("\r\n")
        status = lines[0] if lines else ""
        return status, head, body

    def _log_response(label: str, raw: bytes):
        status, head, body = _parse_http(raw)
        log.info("  [%s] %s", label, status)
        if body:
            text = body.decode("latin-1", errors="replace")
            log.info("  [%s] body (%d bytes):\n%s", label, len(body),
                     text[:3000] if len(text) <= 3000 else text[:3000] + "\n...(truncated)")

    # --- SOAP payloads to try ---
    # Empty body (already confirmed returns 200 OK SOAP response)
    SOAP_EMPTY = ""

    # Generic SOAP envelope with "ResetProfinet" action
    SOAP_RESET_GENERIC = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
        '<soap:Body><ResetProfinet xmlns="urn:schneider-electric:tesys:profinet"/>'
        '</soap:Body></soap:Envelope>'
    )

    # Schneider EcoStruxure / TeSys-style reset
    SOAP_RESET_SE = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:tns="urn:SchneiderElectric:TeSys:Management">'
        '<soap:Header>'
        '<tns:Action>ResetProfinet</tns:Action>'
        '</soap:Header>'
        '<soap:Body>'
        '<tns:ResetProfinetRequest>'
        '<tns:Mode>ClearAR</tns:Mode>'
        '</tns:ResetProfinetRequest>'
        '</soap:Body></soap:Envelope>'
    )

    # WS-Transfer Delete (generic management reset)
    SOAP_WS_TRANSFER = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
        ' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
        ' xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        '<s:Header>'
        f'<wsa:To>http://{ip}/reset_profinet</wsa:To>'
        '<wsa:Action>http://schemas.dmtf.org/wbem/wsman/1/wsman/ResetAR</wsa:Action>'
        '<wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>'
        '<wsa:MessageID>uuid:1</wsa:MessageID>'
        '</s:Header>'
        '<s:Body/></s:Envelope>'
    )

    found_soap = False

    # 1. Read full body from HTTP/80 POST /reset_profinet (empty body - already confirmed 200 OK)
    log.info("  HTTP/80 POST /reset_profinet (reading full SOAP response) ...")
    raw = _raw_http(ip, 80, "POST", "/reset_profinet", body=SOAP_EMPTY)
    if raw:
        found_soap = True
        _log_response("HTTP/80 POST /reset_profinet empty", raw)

    # 2. Try with SOAP reset payloads on HTTP/80
    for label, payload in [("SOAP-reset-generic", SOAP_RESET_GENERIC),
                            ("SOAP-reset-SE",      SOAP_RESET_SE),
                            ("SOAP-ws-transfer",   SOAP_WS_TRANSFER)]:
        log.info("  HTTP/80 POST /reset_profinet [%s] ...", label)
        raw2 = _raw_http(ip, 80, "POST", "/reset_profinet", body=payload)
        if raw2:
            _log_response(f"HTTP/80 {label}", raw2)

    # 3. Probe HTTPS/443 - same endpoints
    log.info("  HTTPS/443 GET / (check if HTTPS is active) ...")
    raw3 = _raw_http(ip, 443, "GET", "/", use_ssl=True)
    if raw3:
        found_soap = True
        _log_response("HTTPS/443 GET /", raw3)

        raw4 = _raw_http(ip, 443, "POST", "/reset_profinet", body=SOAP_EMPTY, use_ssl=True)
        if raw4:
            _log_response("HTTPS/443 POST /reset_profinet empty", raw4)

        raw5 = _raw_http(ip, 443, "POST", "/reset_profinet", body=SOAP_RESET_SE, use_ssl=True)
        if raw5:
            _log_response("HTTPS/443 SOAP-reset-SE", raw5)

    # 4. Probe port 8889 (WS-Management)
    log.info("  HTTP/8889 GET / (WS-Management probe) ...")
    raw6 = _raw_http(ip, 8889, "GET", "/")
    if raw6:
        found_soap = True
        _log_response("HTTP/8889 WS-Mgmt", raw6)

    # 5. GET /wsdl and /services to discover the API
    for path in ["/wsdl", "/services", "/profinet", "/management", "/api"]:
        raw_x = _raw_http(ip, 80, "GET", path)
        if raw_x and raw_x[:5] != b"":
            status, _, body_x = _parse_http(raw_x)
            if "200" in status or "301" in status or "302" in status:
                log.info("  HTTP/80 GET %s -> %s (%d bytes)", path, status, len(body_x))
                if body_x:
                    log.info("    body: %s",
                             body_x[:500].decode("latin-1", errors="replace"))

    return found_soap


def arp_ping(iface: str, src_mac: str, src_ip: str, dst_ip: str,
             timeout: float = 2.0) -> bool:
    """
    ARP-ping the target IP as a supplementary Layer-2 reachability check.
    Returns True if an ARP reply is received.
    This works even when PROFINET DCP is blocked or unavailable.
    Side effect: if the ARP-replied MAC differs from TARGET_MAC, the global
    TARGET_MAC is updated in-place so all subsequent Scapy filters and DCP
    operations use the correct MAC without requiring a restart.
    """
    global TARGET_MAC
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
        log.info("ARP reply from %s is-at %s ? basic IP reachability confirmed",
                 dst_ip, reply_mac)
        if reply_mac.lower() != TARGET_MAC.lower():
            log.warning("  ARP MAC mismatch! Expected %s, got %s -- auto-updating TARGET_MAC",
                        TARGET_MAC, reply_mac)
            TARGET_MAC = reply_mac.lower()
            log.info("  TARGET_MAC updated to %s (from ARP reply)", TARGET_MAC)
        return True
    else:
        log.warning("ARP ping to %s timed out ? no IP reachability", dst_ip)
        return False


# ??????????????????????????????????????????????????????????????????????????
# IO Controller
# ??????????????????????????????????????????????????????????????????????????

class PNIOController:
    """
    PROFINET IO Controller for TeSys Tera.

    run() executes the full connection sequence then cyclic exchange:
      seq=0  AR Connect  (no BIND ? DCE/RPC v4 CL does not need it)
      seq=1  PrmEnd
      seq=2  ApplicationReady
      seq?3  Optional acyclic reads (I&M0, diagnostics, ...)
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
        self._ghost_ar_detected = False  # set when device returns 0x81 or REJECT
        self._ghost_ar_uuids: list = []  # UUIDs extracted from ConnectRes rejection

        self.xport: Optional[ScapyTransport] = None
        self._sport = None
        self._init_transport(self._select_sport(self.wire_profile))

        log.info("??????????????????????????????????????????")
        log.info("PROFINET Controller")
        log.info("  Target     : %s  %s", TARGET_IP, TARGET_MAC)
        log.info("  Controller : %s  %s", CONTROLLER_IP, CONTROLLER_MAC)
        log.info("  Object UUID: %s", self.obj_uuid)
        log.info("  AR UUID    : %s", self.ar_uuid)
        log.info("  Activity   : %s", self.act_uuid)
        log.info("  IFACE      : %s", SCAPY_IFACE)
        log.info("??????????????????????????????????????????")

    # ?? internal ?????????????????????????????????????????????????????????????

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
        if resp is not None and resp[1] not in (PKT_RESPONSE, PKT_REJECT):
            log.error("%s: unexpected pkt_type 0x%02x", label, resp[1])
            return None
        return resp

    # ?? AR establishment ?????????????????????????????????????????????????????

    def step_ar_connect(self, include_alarm_cr: bool = True) -> bool:
        """
        IODConnectReq ? opnum 0, seq_num MUST be 0.

        No BIND phase precedes this call.  DCE/RPC v4 CL does not use BIND.
        Any packet sent before Connect would consume seq=0, causing the device
        to treat Connect (arriving as seq=1) as a retransmit from a dead client
        and locking with nca_wrong_boot_time.  [FIX O]
        """
        log.info("-- AR Connect (opnum=%d, seq=%d, alarm_cr=%s) --",
                 OP_CONNECT, self.seq_num, include_alarm_cr)
        stub = build_connect_stub(
            self.ar_uuid, CONTROLLER_MAC, CONTROLLER_STATION_NAME, INPUT_LEN, OUTPUT_LEN,
            subslot=self.process_subslot, session_key=self.session_key,
            wire_profile=self.wire_profile, include_alarm_cr=include_alarm_cr)
        resp = self._send(OP_CONNECT, stub, "Connect")
        if resp is None:
            return False

        # ?? Decode DCE/RPC packet type ?????????????????????????????????????
        rpc_ptype = resp[1] if len(resp) > 1 else 0xFF
        if rpc_ptype == 0x06:
            # DCE/RPC REJECT ? device actively refused the request.
            # After two consecutive AlarmCR errors the device switches from
            # returning a PNIO error response (ptype=0x02) to issuing a
            # DCE/RPC REJECT (ptype=0x06).  This means the ghost AR is very
            # firmly locked.  Only a hard power cycle will clear it.
            reject_status = struct.unpack_from(">I", resp, 8)[0] if len(resp) > 12 else 0
            log.error("    DCE/RPC REJECT (ptype=0x06) from device ? status=0x%08x", reject_status)
            log.error("    GHOST AR LOCK ? device has a locked Application Relationship")
            log.error("    from a previous session that is blocking all new connections.")
            self._ghost_ar_detected = True
            return False

        if rpc_ptype != 0x02:
            log.error("    Unexpected RPC ptype=0x%02x (expected 0x02=Response)", rpc_ptype)
            return False

        # ?? Decode PNIO error status from ConnectRes stub ??????????????????
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
                    log.error("    GHOST AR LOCK ? the device already has an AlarmCR")
                    log.error("    resource allocated from a previous session.")
                    self._ghost_ar_detected = True
                    # Dump the full stub and extract potential ghost AR UUIDs.
                    # PROFINET spec allows the ConnectRes body to include the
                    # conflicting AR's UUID so a controller can send a targeted Release.
                    log.error("    Full ConnectRes stub (%d bytes): %s",
                              len(stub_body), stub_body.hex())
                    found = _extract_uuids_from_buf(stub_body)
                    if found:
                        log.error("    Potential ghost AR UUIDs found in stub: %s",
                                  [str(u) for u in found])
                        self._ghost_ar_uuids = found
                    else:
                        log.error("    No UUID-like patterns found in ConnectRes stub.")
                elif ec1 == 0xfe or (err_status & 0xFFFF) == 0x000e:
                    log.error("    Ghost AR lock ? POWER-CYCLE TeSys Tera (10s off)")
                return False

        iod_len = struct.unpack_from("<I", stub_body, 4)[0] if len(stub_body) >= 8 else 0
        if iod_len == 0 and len(stub_body) < 30:
            log.error("    ConnectRes: zero IOD data length ? device silently rejected connect")
            log.debug("    Full stub: %s", stub_body.hex())
            return False

        log.info("    ConnectRes OK  (%d bytes, IOD_len=%d)", len(resp), iod_len)
        return True

    def step_prm_end(self) -> bool:
        """IODControlReq PrmEnd -- opnum 4, ControlCommand=0x0001."""
        log.info("?? PrmEnd (opnum=%d, cmd=0x%04x, seq=%d) ??",
                 OP_CONTROL, CTRL_PRM_END, self.seq_num)
        block = build_control_stub(
            self.ar_uuid, CTRL_PRM_END, session_key=self.session_key)
        blen = len(block)
        stub = struct.pack("<IIIII", blen, blen, blen, 0, blen) + block
        resp = self._send(OP_CONTROL, stub, "PrmEnd")
        if resp is None:
            return False
        log.info("    PrmEndRes OK")
        return True

    def step_application_ready(self) -> bool:
        """IODControlReq ApplicationReady -- opnum 4, ControlCommand=0x0002."""
        log.info("-- ApplicationReady (opnum=%d, cmd=0x%04x, seq=%d) --",
                 OP_CONTROL, CTRL_APP_READY, self.seq_num)
        block = build_control_stub(
            self.ar_uuid, CTRL_APP_READY, session_key=self.session_key)
        blen = len(block)
        stub = struct.pack("<IIIII", blen, blen, blen, 0, blen) + block
        resp = self._send(OP_CONTROL, stub, "ApplicationReady")
        if resp is None:
            return False
        log.info("    ApplicationReadyRes OK -- IO data exchange is now ACTIVE")
        return True

    def step_ar_release(self) -> bool:
        """
        IODReleaseReq (opnum 1) -- cleanly terminates the AR on the device.

        MUST be called on exit to free the device's AR resources.
        If skipped, the device holds a ghost AR and the next connect attempt
        gets error 0x81 (AlarmCR resource locked).

        Block type 0x0114 verified from reference pcap (tesysprofinetdemo.pcapng pkt 612).
        NDR prefix uses {blen, blen, blen, 0, blen} format (not the Connect prefix format).
        Block body: Padding(2) + ARUUID(16) + SessionKey(2) + Padding(2) + cmd(4)
        """
        log.info("-- AR Release (opnum=%d, seq=%d) --", OP_RELEASE, self.seq_num)
        body  = struct.pack(">H", 0x0000)    # Padding
        body += _u(self.ar_uuid)             # ARUUID
        body += struct.pack(">H", self.session_key)
        body += struct.pack(">H", 0x0000)    # Padding
        body += struct.pack(">HH", 0x0004, 0x0000)  # ControlCommand + reserved
        block = _block(0x0114, body)
        blen = len(block)
        ndr_prefix = struct.pack("<IIIII", blen, blen, blen, 0, blen)
        stub = ndr_prefix + block
        resp = self._send(OP_RELEASE, stub, "Release", timeout=5.0)
        if resp is None:
            log.warning("    AR Release timed out (device may have already cleared AR)")
            return False
        log.info("    AR Release OK -- AR freed on device")
        return True

    # ?? Acyclic services ?????????????????????????????????????????????????????

    def acyclic_read(self, slot: int = 1, subslot: Optional[int] = None,
                     index: int = 0xF830, max_len: int = 0x8000) -> Optional[bytes]:
        """
        IODReadReq (opnum 2).

        Useful record indices:
          0xF830  I&M 0 ? manufacturer/order/serial/revision
          0xF831  I&M 1 ? installation tag
          0x8028  PDPortDataReal ? port status
          0xB081  Diagnosis
        """
        if subslot is None:
            subslot = self.process_subslot
        log.info("?? Acyclic Read  slot=%d sub=0x%04x idx=0x%04x seq=%d ??",
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
        """IODWriteReq (opnum 3)."""
        if subslot is None:
            subslot = self.process_subslot
        log.info("?? Acyclic Write  slot=%d sub=0x%04x idx=0x%04x  %d bytes  seq=%d ??",
                 slot, subslot, index, len(data), self.seq_num)
        stub = build_write_stub(self.ar_uuid, slot, subslot, index, data)
        resp = self._send(OP_WRITE, stub, "Write", timeout=5.0)
        if resp is None:
            return False
        log.info("    WriteRes OK")
        return True

    # ?? Cyclic exchange ??????????????????????????????????????????????????????

    def set_output(self, data: bytes):
        """Thread-safe update of cyclic output data (controller ? device)."""
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
        this method starts its own TX thread ? kept for backward compatibility.
        """
        log.info("?? Cyclic exchange  %.0f s ??", duration_s)

        _own_stop = None
        if stop_tx is None:
            # Fallback: caller didn't pre-start TX ? start it now.
            # NOTE: this is the slow path that caused the watchdog issue in v7.
            _own_stop = threading.Event()
            stop_tx   = _own_stop
            tx_thr    = threading.Thread(target=self._tx_loop, args=(stop_tx,), daemon=True)
            tx_thr.start()
            log.debug("Cyclic TX thread started (fallback ? prefer pre-start after ConnectRes)")
        else:
            log.debug("Cyclic RX: using pre-started TX thread")

        # ?? FIX: BPF must filter by source MAC ????????????????????????????????
        # The previous BPF "ether proto 0x8892 or (vlan and ether proto 0x8892)"
        # matched ALL PROFINET frames on the wire ? including our OWN sent frames
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

        log.info("Cyclic complete ? %d valid input frames received", count)
        if count == 0:
            log.warning("Zero input frames.  Diagnostics:")
            log.warning("  Expected FrameID=0x%04x from %s",
                        self.frame_id_in, TARGET_MAC)
            if frame_ids_seen:
                top = ", ".join(f"0x{k:04x}({v})" for k, v in
                                sorted(frame_ids_seen.items(), key=lambda x: -x[1])[:6])
                log.warning("  FrameIDs seen from device: %s", top)
                log.warning("  ? Device IS sending PROFINET but FrameID doesn't match")
                log.warning("    Update CMD_FRAME_ID_IN constant to match the device's FrameID")
            else:
                log.warning("  No PROFINET frames captured from %s at all", TARGET_MAC)
                log.warning("  Possible causes:")
                log.warning("    1. Device watchdog fired ? TX started too late")
                log.warning("    2. AR not fully established (check PrmEnd/AppReady logs)")
                log.warning("    3. Wireshark confirm: does device send 0x8892 frames?")

    # ?? Main run sequence ????????????????????????????????????????????????????

    def run(self):
        """Full AR establishment + cyclic exchange."""
        # Pre-flight: verify scapy is available
        if not SCAPY_OK:
            log.error("scapy is not installed.  Run:  pip install scapy")
            return

        # ?? FIX 3: DCP Identify + ARP pre-flight ?????????????????????????????
        log.info("?? DCP Identify pre-flight ??")
        list_interfaces()

        if SKIP_DCP_PREFLIGHT:
            log.warning("SKIP_DCP_PREFLIGHT=True ? skipping DCP check, proceeding to AR Connect")
        else:
            dcp_ok = dcp_identify(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
            if not dcp_ok:
                # DCP failed ? try ARP ping as a supplementary check
                log.info("?? ARP ping fallback check ??")
                arp_ok = arp_ping(SCAPY_IFACE, CONTROLLER_MAC, CONTROLLER_IP,
                                  TARGET_IP, timeout=2.0)
                if arp_ok:
                    # Device IS reachable at Layer 2 (ARP answered). DCP silence
                    # means it is holding a ghost AR - the PROFINET stack is busy
                    # and ignores DCP Identify.
                    #
                    # Strategy (in order of spec compliance):
                    #  1. DCP Set IP (same IP) - spec mandates device MUST process
                    #     IP change and abort ALL ARs even in DATA_EXCHANGE state.
                    #  2. DCP ResetToFactory - only works if device is NOT in
                    #     DATA_EXCHANGE (returns block_result=0x06 otherwise).
                    #  3. Fall through to AR Connect anyway.
                    log.warning(
                        "DCP Identify failed but ARP ping succeeded -> device IS alive.\n"
                        "  Likely cause: ghost AR lock from a previous session.\n"
                        "  Trying DCP Set IP to force AR abort (PROFINET spec-mandated) ..."
                    )
                    acked, ip_result = dcp_set_ip(
                        SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
                        ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
                        permanent=False, timeout=3.0)
                    if acked and ip_result == 0x00:
                        log.info("DCP Set IP accepted -> device MUST have aborted ghost AR. "
                                 "Waiting 3 s ...")
                        time.sleep(3.0)
                    else:
                        if acked:
                            log.warning("  DCP Set IP ACK but block_result=0x%02x - "
                                        "device may not have aborted ARs. "
                                        "Trying DCP ResetToFactory as fallback ...",
                                        ip_result if ip_result >= 0 else 0xFF)
                        else:
                            log.warning("  DCP Set IP: no ACK. "
                                        "Trying DCP ResetToFactory as fallback ...")
                        reset_ok = dcp_reset_to_factory(
                            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                        if reset_ok:
                            log.info("DCP ResetToFactory accepted -> waiting 8 s ...")
                            time.sleep(8.0)
                        else:
                            log.warning(
                                "  Both DCP Set IP and DCP ResetToFactory failed or were "
                                "rejected.\n"
                                "  Proceeding to AR Connect. If all profiles fail:\n"
                                "    Option 1 (software): python tesys_pn_v10.py --reset\n"
                                "    Option 2 (hardware): Unplug TeSys Tera power cable 15 s,\n"
                                "                         wait 10 s after power-on, then rerun."
                            )
                    # fall through to AR Connect
                else:
                    log.error(
                        "Both DCP Identify and ARP ping failed.\n"
                        "  The device is NOT reachable at Layer 2.  Check:\n"
                        "  (1) Ethernet cable / switch port between PC NIC and TeSys Tera\n"
                        "  (2) TeSys Tera is powered on (LEDs should show RUN or FAULT)\n"
                        "  (3) SCAPY_IFACE GUID ? correct one is marked ? USE THIS above\n"
                        "  (4) No VLAN or managed-switch port isolation\n"
                        "  Once connectivity is restored, rerun the script."
                    )
                    return   # genuinely unreachable ? abort
            time.sleep(0.10)

        # seq=0  AR Connect  (no BIND ? would steal seq=0)  [FIX O]
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

        # v10: Try COMMANDER profiles with AND without AlarmCR.
        # Alt-frame-ID profiles bypass ghost AR frame-ID lock (error 0x81=IOCRBlock/FrameID).
        # Ghost AR holds FrameID 0xBBF0; alt profiles use 0xBC00/0xBC10 which are free.
        profiles = [
            ("cmd-with-alarm",         PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE,               True),
            ("cmd-no-alarm",           PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
            ("cmd-alt1-no-alarm",      PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
            ("cmd-alt1-with-alarm",    PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1,           True),
            ("cmd-alt2-no-alarm",      PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT2_NO_ALARM,  False),
            ("cmd-alt2-with-alarm",    PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT2,           True),
            ("cmd-with-alarm-s1",      PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE,               True),
            ("cmd-no-alarm-s1",        PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
            ("cmd-alt1-no-alarm-s1",   PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
            ("std-with-alarm",         PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE,               True),
            ("std-no-alarm",           PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
            ("std-alt1-no-alarm",      PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
        ]
        if epm_uuid is not None:
            profiles.insert(0, ("epm-cmd", epm_uuid, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE, True))
        for attempt, (pname, obj_uuid, subslot, sess_key, wprof, alarm_cr) in enumerate(profiles, start=1):
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
                "Connect profile %d/%d: %s (wire=%s, obj=%s, subslot=0x%04x, session=0x%04x, alarm_cr=%s)",
                attempt, len(profiles), pname, self.wire_profile.name, self.obj_uuid,
                self.process_subslot, self.session_key, alarm_cr)
            if self.step_ar_connect(include_alarm_cr=alarm_cr):
                break
            if attempt < len(profiles):
                log.warning("Connect attempt %d/%d failed -- retrying in 3 s ...",
                            attempt, len(profiles))
                time.sleep(3.0)
        else:
            log.error("AR Connect failed after %d attempts -- aborting", len(profiles))
            if self._ghost_ar_detected:
                log.error("??????????????????????????????????????????????????")
                log.error("GHOST AR LOCK confirmed on all %d profiles.", len(profiles))

                def _retry_connect_all_profiles(label: str, redcp_set_ip: bool = False) -> bool:
                    """
                    Re-init transport and retry all 6 profiles after a ghost-AR-clear attempt.

                    When redcp_set_ip=True, sends DCP Set IP first to re-register
                    the PROFINET endpoint (needed after DCP Reset clears network config).
                    """
                    if redcp_set_ip:
                        log.info("  Re-sending DCP Set IP to re-register PROFINET endpoint ...")
                        ack2, r2 = dcp_set_ip(
                            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
                            ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
                            permanent=False, timeout=3.0)
                        if ack2 and r2 == 0x00:
                            log.info("  DCP Set IP re-accepted. Waiting 3 s ...")
                            time.sleep(3.0)
                        else:
                            log.warning("  DCP Set IP re-send: acked=%s result=0x%02x",
                                        ack2, r2 if r2 >= 0 else 0xFF)

                    log.info("Retrying all AR Connect profiles after %s ...", label)
                    retry_profiles = [
                        ("cmd-with-alarm",      PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE,               True),
                        ("cmd-no-alarm",        PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
                        ("cmd-alt1-no-alarm",   PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
                        ("cmd-alt1-alarm",      PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1,           True),
                        ("cmd-alt2-no-alarm",   PNIO_CMD_OBJ_UUID, 0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT2_NO_ALARM,  False),
                        ("cmd-with-alarm-s1",   PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE,               True),
                        ("cmd-no-alarm-s1",     PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
                        ("cmd-alt1-no-alarm-s1",PNIO_CMD_OBJ_UUID, 0x0001, 0x0001, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
                        ("std-with-alarm",      PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE,               True),
                        ("std-no-alarm",        PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE_NO_ALARM,       False),
                        ("std-alt1-no-alarm",   PNIO_CM_OBJ_UUID,  0x0001, 0x0002, COMMANDER_WIRE_PROFILE_ALT1_NO_ALARM,  False),
                    ]
                    for pname, obj_uuid, subslot, sess_key, wprof, alarm_cr in retry_profiles:
                        self.wire_profile = wprof
                        self.obj_uuid = obj_uuid
                        self.process_subslot = subslot
                        self.session_key = sess_key
                        self.seq_num = 0
                        self.ar_uuid = uuid.uuid4()
                        self.act_uuid = self._new_activity_uuid(self.wire_profile)
                        self.frame_id_in = self.wire_profile.frame_id_in
                        self.frame_id_out = self.wire_profile.frame_id_out
                        self.rt_frame_id_out = (self.wire_profile.rt_output_frame_id
                                                or self.wire_profile.frame_id_out)
                        self._init_transport(self._select_sport(self.wire_profile))
                        if self.step_ar_connect(include_alarm_cr=alarm_cr):
                            log.info("  Profile %s succeeded after %s!", pname, label)
                            return True
                        time.sleep(1.0)
                    return False

                # --- Attempt 1: DCP ResetCommunication SubOpt=6 (new attempt) ----
                log.info("Attempt 1/3: DCP ResetCommunication (SubOpt=6, IEC 61158-6-10) ...")
                reset6_ok = dcp_reset_communication(
                    SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                if reset6_ok:
                    log.info("DCP ResetCommunication accepted -> waiting 5 s ...")
                    time.sleep(5.0)
                    if _retry_connect_all_profiles("DCP SubOpt6", redcp_set_ip=True):
                        pass  # success - fall through to rest of run()
                    else:
                        log.warning("  Still blocked after SubOpt6. Trying DCP Set IP ...")
                        acked_setip, r_setip = dcp_set_ip(
                            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
                            ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
                            permanent=False, timeout=3.0)
                        if acked_setip and r_setip == 0x00:
                            log.info("DCP Set IP accepted -> waiting 5 s ...")
                            time.sleep(5.0)
                            if not _retry_connect_all_profiles("DCP Set IP (post SubOpt6)"):
                                log.error("Connect still failing. Try: python tesys_pn_v10.py --force-release")
                                log.error("Or power-cycle TeSys Tera for 60+ seconds.")
                                return
                        else:
                            log.error("DCP Set IP failed after SubOpt6.")
                            log.error("Try: python tesys_pn_v10.py --force-release")
                            return
                else:
                    # --- Attempt 2: DCP Set IP -----------------------------------
                    log.info("Attempt 2/3: DCP Set IP (IEC 61158-6-10 mandates AR abort) ...")
                    acked, ip_result = dcp_set_ip(
                        SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
                        ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
                        permanent=False, timeout=3.0)
                    if acked and ip_result == 0x00:
                        log.info("DCP Set IP accepted -> waiting 5 s for device to abort AR ...")
                        time.sleep(5.0)
                        if _retry_connect_all_profiles("DCP Set IP"):
                            pass  # success - fall through to rest of run()
                        else:
                            # --- Attempt 3: DCP ResetToFactory (qualifier=0x0002) -----
                            log.info("Attempt 3/4: DCP ResetToFactory (SubOpt=5, qualifier=0x0002) ...")
                            reset_ok = dcp_reset_to_factory(
                                SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                            if reset_ok:
                                log.info("DCP Reset accepted -> waiting 25 s for NVM clear ...")
                                time.sleep(25.0)
                                # CRITICAL: re-send DCP Set IP after Reset to re-register endpoint
                                if _retry_connect_all_profiles("DCP ResetToFactory", redcp_set_ip=True):
                                    pass  # success
                                else:
                                    # --- Attempt 4: DCP ResetToFactory ALL (qualifier=0x0001) ------
                                    log.info("Attempt 4/4: DCP ResetToFactory ALL (SubOpt=5, qualifier=0x0001) ...")
                                    reset_all_ok = dcp_reset_all(
                                        SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                                    if reset_all_ok:
                                        log.info("DCP ResetToFactory ALL accepted -> waiting 25 s ...")
                                        time.sleep(25.0)
                                        if not _retry_connect_all_profiles("DCP ResetToFactory ALL", redcp_set_ip=True):
                                            log.error("Connect still failing after all 4 DCP methods.")
                                            log.error("??????????????????????????????????????????????????")
                                            log.error("FIRMWARE NVM LOCK confirmed.  Next steps:")
                                            log.error("  1. python tesys_pn_v10.py --spoof-connect")
                                            log.error("  2. python tesys_pn_v10.py --force-release")
                                            log.error("  3. Physically unplug TeSys Tera power")
                                            log.error("     cable for 60 seconds. After power-on wait 15 s,")
                                            log.error("     then rerun: python tesys_pn_v10.py --wait-hello")
                                            log.error("??????????????????????????????????????????????????")
                                            return
                                    else:
                                        log.error("DCP ResetToFactory ALL rejected/timed-out.")
                                        log.error("??????????????????????????????????????????????????")
                                        log.error("FIRMWARE NVM LOCK.  Next steps:")
                                        log.error("  1. python tesys_pn_v10.py --spoof-connect")
                                        log.error("  2. Physically unplug TeSys Tera power for 60+ seconds.")
                                        log.error("     After power-on wait 15 s, then rerun with --wait-hello.")
                                        log.error("??????????????????????????????????????????????????")
                                        return
                            else:
                                log.error("DCP ResetToFactory rejected/timed-out.")
                                log.error("??????????????????????????????????????????????????")
                                log.error("Next steps (in order):")
                                log.error("  1. python tesys_pn_v10.py --spoof-connect")
                                log.error("  2. python tesys_pn_v10.py --force-release")
                                log.error("  3. Physically unplug TeSys Tera power for 60+ seconds.")
                                log.error("     After power-on wait 15 s, then rerun with --wait-hello.")
                                log.error("??????????????????????????????????????????????????")
                                return
                    else:
                        log.warning("DCP Set IP no clean ACK (acked=%s, result=0x%02x). "
                                    "Trying DCP ResetToFactory ...",
                                    acked, ip_result if ip_result >= 0 else 0xFF)
                        reset_ok = dcp_reset_to_factory(
                            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                        if reset_ok:
                            log.info("DCP Reset accepted -> waiting 25 s for NVM clear ...")
                            time.sleep(25.0)
                            if not _retry_connect_all_profiles("DCP ResetToFactory", redcp_set_ip=True):
                                log.error("Connect still failing after DCP Reset.")
                                log.error("??????????????????????????????????????????????????")
                                log.error("Next steps:")
                                log.error("  1. python tesys_pn_v10.py --spoof-connect")
                                log.error("  2. python tesys_pn_v10.py --force-release")
                                log.error("  3. Power-cycle TeSys Tera for 60+ s, then --wait-hello")
                                log.error("??????????????????????????????????????????????????")
                                return
                        else:
                            log.error("All DCP methods failed/rejected.")
                            log.error("??????????????????????????????????????????????????")
                            log.error("Next steps:")
                            log.error("  1. python tesys_pn_v10.py --force-release")
                            log.error("  2. Power-cycle TeSys Tera for 60+ s, then --wait-hello")
                            log.error("??????????????????????????????????????????????????")
                            return
            else:
                log.error("Power-cycle TeSys Tera, wait 10 s, then retry.")
                return

        # ?? FIX: Start cyclic TX IMMEDIATELY after ConnectRes ?????????????????
        # Root cause of "0 valid input frames": the device watchdog is
        # WDF ? SendClock ? ReductionRatio = 3 ? 128 ? 31.25?s = 96 ms.
        # If no cyclic OUTPUT frame arrives within 96 ms the device enters
        # DATA_LOST mode and stops sending cyclic INPUT.
        # The reference pcap shows the real controller starts TX at pkt#312
        # (within ~10 ms of ConnectRes at pkt#310).  Our v7 waited until after
        # PrmEnd + AppReady + acyclic read ? roughly 500 ms ? so the watchdog
        # fired 5? before our first frame ever left the wire.
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
            log.error("PrmEnd failed ? aborting")
            stop_tx.set(); tx_thr.join(timeout=2.0)
            return
        time.sleep(0.05)

        # seq=2  ApplicationReady
        if not self.step_application_ready():
            log.error("ApplicationReady failed ? aborting")
            stop_tx.set(); tx_thr.join(timeout=2.0)
            return
        time.sleep(0.05)

        # seq=3  Acyclic: read I&M0 identity
        log.info("Reading I&M0 identity record (slot=0, sub=1, idx=0xF830)...")
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

        # Clean disconnect ? release AR so device doesn't hold ghost AR
        self.step_ar_release()

# ??????????????????????????????????????????????????????????????????????????
# Self-tests (run without hardware)
# ??????????????????????????????????????????????????????????????????????????

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

    # ?? CL-PDU header ??????????????????????????????????????????????????????
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

    # ?? ARBlock ????????????????????????????????????????????????????????????
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

    # ?? IOCRBlock ??????????????????????????????????????????????????????????
    spec = IOCRSpec(IOCR_INPUT, 1, FRAME_ID_IN, INPUT_LEN + 1)
    iocr = build_iocr_block(spec)
    lt_off = 6 + 2 + 2         # block_env(6) + IOCRType(2) + IOCRRef(2)
    chk("iocr.lt_type",  struct.unpack_from(">H", iocr, lt_off)[0], PROFINET_ETYPE, "0x{:04x}")  # FIX F
    dl_off = lt_off + 2 + 4    # LT(2) + IOCRProperties(4)
    chk("iocr.data_len", struct.unpack_from(">H", iocr, dl_off)[0], INPUT_LEN + 1)

    # ?? ExpectedSubmoduleBlock ????????????????????????????????????????????
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

    # ?? Control stubs ??????????????????????????????????????????????????????
    for cmd, cname in [(CTRL_PRM_END,"prm_end"),(CTRL_APP_READY,"app_ready")]:
        stub = build_control_stub(ar_uuid, cmd)
        chk(f"ctrl.{cname}.type", struct.unpack_from(">H",stub,0)[0], BT_IOCTRL_REQ, "0x{:04x}")
        # After type(2)+len(2)+ver(2)+pad(2) = 8 bytes ? ARUUID
        chk(f"ctrl.{cname}.ar_uuid",  _pu(stub, 8), ar_uuid)   # FIX I: padding present
        cmd_off = 8 + 16 + 2 + 2      # header(8)+ARUUID(16)+SessionKey(2)+Padding(2)
        chk(f"ctrl.{cname}.cmd", struct.unpack_from(">H",stub,cmd_off)[0], cmd, "0x{:04x}")  # FIX H/K

    # Request uses opnum=4 for both control operations
    for cmd, cname in [(CTRL_PRM_END,"prm_end_opnum"),(CTRL_APP_READY,"app_ready_opnum")]:
        stub = build_control_stub(ar_uuid, cmd)
        req  = build_request(1, OP_CONTROL, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, stub,
                             wire_profile=DEFAULT_WIRE_PROFILE)
        chk(f"req.{cname}", struct.unpack_from("<H",req,68)[0], OP_CONTROL)  # FIX G/J

    # ?? AlarmCR byte-exact test (verified against reference pcap) ?????????????
    alarm_body = build_alarm_cr_block()
    # Exact bytes from tesysprofinetdemo.pcapng AlarmCRBlockReq offset 356:
    # BlockType=0x0103 BlockLen=22(0x0016) BVH=1 BVL=0 + 20-byte body
    REF_ALARM = bytes.fromhex("010300160100" "000188920000000000010003000000c8c000a000")
    chk("alarm.full_block", alarm_body.hex(), REF_ALARM.hex())

    # ?? Summary ????????????????????????????????????????????????????????????
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
        log.error("?? SELF-TEST: %d/%d FAILED ??", len(failures), total)
        for f in failures:
            log.error("  %s", f)
        sys.exit(1)
    log.info("All %d self-tests passed", total)

# ??????????????????????????????????????????????????????????????????????????
# Entry point
# ??????????????????????????????????????????????????????????????????????????

def main():
    import argparse
    global CYCLIC_DURATION_S, SKIP_DCP_PREFLIGHT
    parser = argparse.ArgumentParser(
        description="PROFINET IO Controller for TeSys Tera [v10]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tesys_pn_v10.py                       # Connect and run cyclic exchange (60 s)
  python tesys_pn_v10.py --duration 120        # Run for 120 seconds
  python tesys_pn_v10.py --test                # Run self-tests only (no hardware needed)
  python tesys_pn_v10.py --discover            # DCP Identify + ARP ping only
  python tesys_pn_v10.py --reset               # DCP ResetToFactory then connect
  python tesys_pn_v10.py --force-release       # Force-clear ghost AR via blind Release + DCP
  python tesys_pn_v10.py --wait-hello          # Wait for device boot (WS-Discovery Hello), then connect
  python tesys_pn_v10.py --extract-uuid        # Extract ghost AR UUID from ConnectRes, try targeted Release
  python tesys_pn_v10.py --read-ardata         # ReadImplicit index 0xF820 (ARData) to extract ghost AR UUID
  python tesys_pn_v10.py --spoof-connect       # Spoof ghost PLC MAC to trigger §4.4.1.6 station-restart AR clear
  python tesys_pn_v10.py --modbus-scan         # Scan all Modbus registers 0x0001-0x03FF
  python tesys_pn_v10.py --verbose             # Enable DEBUG logging
  python tesys_pn_v10.py --list-interfaces     # Show all Scapy network interfaces

Requires: scapy, Npcap (Windows), run as Administrator
""",
    )
    parser.add_argument("--test",            action="store_true",
                        help="Run self-tests only (no hardware required)")
    parser.add_argument("--discover",        action="store_true",
                        help="DCP Identify + ARP ping only, then exit")
    parser.add_argument("--reset",           action="store_true",
                        help="Send DCP ResetToFactory before connecting (clears ghost AR)")
    parser.add_argument("--setup-ip",        action="store_true",
                        help="Assign IP 169.254.217.162 permanently to device after factory reset, then exit")
    parser.add_argument("--diagnose",        action="store_true",
                        help="Full Layer-2 diagnostic: ARP + DCP multicast + DCP unicast + report")
    parser.add_argument("--duration",        type=float, default=CYCLIC_DURATION_S,
                        metavar="SECONDS",
                        help=f"Cyclic exchange duration in seconds (default: {CYCLIC_DURATION_S})")
    parser.add_argument("--verbose",         action="store_true",
                        help="Enable DEBUG-level logging")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="Print all Scapy network interfaces and exit")
    parser.add_argument("--skip-dcp",        action="store_true",
                        help="Skip DCP pre-flight check (useful when device holds ghost AR)")
    parser.add_argument("--force-release",   action="store_true",
                        help="Send blind PROFINET AR Release + DCP name/reset to force-clear ghost AR")
    parser.add_argument("--http-probe",      action="store_true",
                        help="Probe HTTP/HTTPS/Modbus on device; read full SOAP body, then exit")
    parser.add_argument("--dpws-probe",      action="store_true",
                        help="DPWS WS-Discovery probe: discover device EPR, get hosted services, then exit")
    parser.add_argument("--scan",            action="store_true",
                        help="Full device scan: TCP ports, SNMP, EtherNet/IP, extended Modbus, then exit")
    parser.add_argument("--probe-8080",      action="store_true",
                        help="Deep probe of TCP port 8080 (raw/HTTPS/WS-Man/binary), then exit")
    parser.add_argument("--wait-hello",     action="store_true",
                        help="Listen for WS-Discovery Hello (device boot), then immediately connect")
    parser.add_argument("--extract-uuid",    action="store_true",
                        help="Send Connect, extract ghost AR UUID from rejection stub, try targeted Release")
    parser.add_argument("--demo-release",    action="store_true",
                        help="Send targeted Release for the known ghost AR UUID from the demo pcap "
                             "(f9c6c366-7e9d-4aef-8f6a-3cd730f5afce, sess=2) on both port 34964 and 49152")
    parser.add_argument("--spoof-release",   action="store_true",
                        help="Replay the EXACT Release packet from the original Siemens PLC session "
                             "(spoofs MAC 60:7d:09:5b:24:b6, IP 192.168.0.60, sport 59981, act_uuid). "
                             "Bypasses the device's session-owner check that rejects our normal Release.")
    parser.add_argument("--read-ardata",     action="store_true",
                        help="Send PROFINET IODReadImplicit (opnum=5) for index 0xF820 (ARData) to "
                             "extract the ghost AR UUID without needing an established AR")
    parser.add_argument("--spoof-connect",   action="store_true",
                        help="Spoof ghost PLC MAC (60:7d:09:5b:24:b6) to send a fresh ConnectReq. "
                             "Per PROFINET §4.4.1.6 the device MUST abort the ghost AR when the "
                             "same CMInitiatorMAC reconnects with a new ARUUID (station-restart).")
    parser.add_argument("--spoof-same-uuid", action="store_true",
                        help="Spoof ghost PLC MAC AND reuse the exact ghost AR UUID. "
                             "Device may treat this as the original PLC reconnecting to its "
                             "existing AR (reconnect path, not station-restart). "
                             "If accepted, sends PrmEnd + AppReady + Release to cleanly close the "
                             "ghost AR. Try after --spoof-connect fails.")
    parser.add_argument("--dcp-reset-comm",  action="store_true",
                        help="Send DCP Control Option=5/SubOption=6 qualifier=0x0002 "
                             "(ResetCommunicationParameter only — does not wipe application data). "
                             "Different code path from the full FactoryReset that returns IN_OPERATION.")
    parser.add_argument("--modbus-scan",     action="store_true",
                        help="FC03 scan Modbus registers 0x0001-0x03FF, log all non-zero values, then exit")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("PROFINET IO Controller -- TeSys Tera [v10]")

    if not SCAPY_OK:
        log.error("scapy is required.  Install with:  pip install scapy")
        log.error("Also install Npcap from https://npcap.com (run as Administrator)")
        sys.exit(1)

    if args.list_interfaces:
        list_interfaces()
        return

    # Auto-detect the NIC's real IP (may have changed to APIPA after factory reset)
    _resolve_controller_ip()

    run_self_tests()

    if args.test:
        log.info("Self-tests only -- exiting (use without --test to connect to hardware)")
        return

    if args.discover:
        log.info("== Discovery mode ==")
        list_interfaces()
        dcp_ok = dcp_identify(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
        if not dcp_ok:
            arp_ping(SCAPY_IFACE, CONTROLLER_MAC, CONTROLLER_IP, TARGET_IP, timeout=2.0)
        return

    if args.reset:
        log.info("== Ghost AR Cleanup (--reset) ==")
        log.info("Step 1/2: DCP Set IP (IEC 61158-6-10 mandates AR abort in any state) ...")
        acked, ip_result = dcp_set_ip(
            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
            ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
            permanent=False, timeout=4.0)
        if acked and ip_result == 0x00:
            log.info("  DCP Set IP accepted - ghost AR should be cleared. Waiting 5 s ...")
            time.sleep(5.0)
        else:
            log.warning("  DCP Set IP result: acked=%s result=0x%02x - trying ResetToFactory ...",
                        acked, ip_result if ip_result >= 0 else 0xFF)
            log.info("Step 2/2: DCP ResetToFactory ...")
            dcp_reset_to_factory(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
            time.sleep(3.0)

    if args.setup_ip:
        log.info("== Post-Factory-Reset IP Setup (--setup-ip) ==")
        log.info("Sending DCP Set IP (permanent) to %s -> assign %s/%s", TARGET_MAC, TARGET_IP, TARGET_SUBNET)
        if not CONTROLLER_IP.startswith("169.254."):
            log.warning(
                "PC NIC IP is %s - device will assign the IP but RPC/AR Connect "
                "will fail until the NIC is on the 169.254.x.x subnet.\n"
                "  Fix: Control Panel -> Network Connections -> Ethernet adapter "
                "({5F0A0BED-...}) -> Properties -> IPv4 -> "
                "Static: 169.254.0.100 / 255.255.0.0", CONTROLLER_IP)
        acked, result = dcp_set_ip(
            SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
            ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
            permanent=True, timeout=5.0)
        if acked and result == 0x00:
            log.info("  [OK] DCP Set IP accepted (permanent) - device assigned %s", TARGET_IP)
            wait_s = 3.0
        elif acked and result == 0x06:
            log.warning(
                "  DCP Set IP returned block_result=0x06 (IN OPERATION).\n"
                "  This can mean:\n"
                "    (a) Device already has IP=%s and has an active ghost AR.\n"
                "    (b) Factory reset cleared IP temporarily but device restored it from NVM.\n"
                "  Checking if device already has %s via ARP ...", TARGET_IP, TARGET_IP)
            wait_s = 1.0
        else:
            if acked:
                log.error("  DCP Set IP returned block_result=0x%02x - unexpected error.", result)
            else:
                log.error("  No DCP ACK from %s - device not responding on Layer 2.", TARGET_MAC)
                log.error("  Check: (1) Ethernet cable, (2) Device powered on, "
                          "(3) SCAPY_IFACE is the correct NIC ({5F0A0BED-...})")
            return
        log.info("  Waiting %.0f s for device to apply IP ...", wait_s)
        time.sleep(wait_s)
        log.info("  Verifying with ARP ping to %s ...", TARGET_IP)
        arp_ok = arp_ping(SCAPY_IFACE, CONTROLLER_MAC, CONTROLLER_IP, TARGET_IP, timeout=3.0)
        if arp_ok:
            log.info("  [OK] Device reachable at %s", TARGET_IP)
            if result == 0x06:
                log.warning(
                    "  Device already had IP=%s (restored from NVM after factory reset).\n"
                    "  It has a persistent ghost AR - fix NIC IP first, then run:\n"
                    "    python tesys_pn_v10.py --diagnose\n"
                    "  to see device state, then:\n"
                    "    python tesys_pn_v10.py --skip-dcp\n"
                    "  to attempt AR Connect directly.", TARGET_IP)
            else:
                log.info("  Run without --setup-ip to connect.")
        else:
            log.warning(
                "  ARP ping to %s failed.\n"
                "  Device has no IP yet, or the PC NIC (%s) is on the wrong subnet.\n"
                "  ACTION REQUIRED: Set NIC to static 169.254.0.100/255.255.0.0, "
                "then rerun --setup-ip.", TARGET_IP, CONTROLLER_IP)
        return

    if args.diagnose:
        log.info("== Full Layer-2 Diagnostic (--diagnose) ==")
        list_interfaces()
        log.info("-- Step 1: ARP ping to %s --", TARGET_IP)
        arp_ok = arp_ping(SCAPY_IFACE, CONTROLLER_MAC, CONTROLLER_IP, TARGET_IP, timeout=3.0)
        log.info("-- Step 2: DCP Identify multicast --")
        dcp_mc = dcp_identify(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
        log.info("-- Step 3: DCP Identify unicast -> %s --", TARGET_MAC)
        info = dcp_identify_unicast(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
        if info["alive"]:
            log.info("  [OK] Device responded to unicast DCP Identify")
            log.info("    IP       : %s / %s  (gw=%s, qualifier=0x%04x)",
                     info.get("ip", "?"), info.get("mask", "?"),
                     info.get("gw", "?"), info.get("ip_qualifier", 0))
            log.info("    Name     : %s", info.get("name", "(none)"))
            log.info("    Vendor   : 0x%04x  Device: 0x%04x",
                     info.get("vendor_id", 0), info.get("device_id", 0))
            st = info.get("status", -1)
            status_str = {0: "FACTORY DEFAULT", 1: "IP SET", 2: "NAME SET",
                          3: "READY", 4: "IN OPERATION", 5: "STOP"}.get(st, f"0x{st:02x}")
            log.info("    Status   : %s (raw=0x%02x)", status_str, st if st >= 0 else 0xFF)
        else:
            log.warning("  Device did NOT respond to unicast DCP Identify")
        log.info("-- Diagnostic Summary --")
        log.info("  ARP %s | DCP multicast %s | DCP unicast %s",
                 "OK" if arp_ok else "FAIL",
                 "OK" if dcp_mc else "FAIL",
                 "OK" if info["alive"] else "FAIL")
        if arp_ok and not dcp_mc and not info["alive"]:
            log.warning("  Device is alive (ARP) but ignores all DCP -> likely in DATA_EXCHANGE (ghost AR).\n"
                        "  Try:  python tesys_pn_v10.py --skip-dcp")
        elif not arp_ok and not dcp_mc and info["alive"]:
            log.warning("  Device responds to DCP unicast but not ARP - device has NO IP or IP mismatch.\n"
                        "  Try:  python tesys_pn_v10.py --setup-ip  (after fixing NIC to 169.254.0.100)")
        elif not arp_ok and not dcp_mc and not info["alive"]:
            log.error("  Device is completely unreachable - check cable and power.")
        elif arp_ok and (dcp_mc or info["alive"]):
            log.info("  Device is reachable and responding to DCP - run normally.")
        return

    if args.http_probe:
        log.info("== HTTP/HTTPS/Modbus Probe (--http-probe) ==")
        log.info("Probing device at %s for web services and Modbus ...", TARGET_IP)
        log.info("-- Modbus TCP (port 502) --")
        modbus_ok = modbus_tcp_force_ar_release(TARGET_IP, timeout=4.0)
        log.info("  Modbus result: %s", "accessible" if modbus_ok else "not accessible / no response")
        log.info("-- HTTP/HTTPS (ports 80, 443, 8889) --")
        http_ok = http_probe_ar_release(TARGET_IP, timeout=8.0)
        log.info("  HTTP/HTTPS result: %s", "server responded" if http_ok else "not reachable")
        return

    if args.dpws_probe:
        log.info("== DPWS WS-Discovery Probe (--dpws-probe) ==")
        log.info("Probing device at %s for DPWS hosted services ...", TARGET_IP)
        dpws_result = dpws_discover_and_probe(TARGET_IP, timeout=5.0)
        log.info("-- DPWS result --")
        log.info("  EPR       : %s", dpws_result.get('epr') or '(not found)')
        log.info("  XAddrs    : %s", dpws_result.get('xaddrs') or '(none)')
        log.info("  Services  : %s", dpws_result.get('services') or '(none - no Relationship section)')
        if not dpws_result.get('services'):
            log.info("  [result] Device does not expose a programmatic PROFINET management service via DPWS.")
            log.info("  [result] Only passive WS-Discovery device metadata is available via HTTP.")
        return

    if args.scan:
        log.info("== Full Device Scan (--scan) ==")
        log.info("Scanning %s for all known industrial ports and protocols ...", TARGET_IP)
        full_device_scan(TARGET_IP)
        return

    if args.probe_8080:
        log.info("== Port 8080 Deep Probe (--probe-8080) ==")
        probe_port_8080(TARGET_IP)
        return

    if args.modbus_scan:
        log.info("== Modbus Full Register Scan (--modbus-scan) ==")
        modbus_full_register_scan(TARGET_IP)
        return

    if args.extract_uuid:
        log.info("== Ghost AR UUID Extraction (--extract-uuid) ==")
        log.info("Step 1: Send Connect to device and parse rejection for ghost AR UUID ...")
        SKIP_DCP_PREFLIGHT = True
        found_uuids = extract_ghost_ar_uuid()
        if found_uuids:
            log.info("Step 2: Trying targeted Release for each extracted UUID ...")
            cleared = False
            for sess_key in (1, 2, 3, 0):
                for u in found_uuids:
                    log.info("  Trying UUID=%s  sess=%d", u, sess_key)
                    ok = pnio_targeted_release(u, sess_key=sess_key, timeout=5.0)
                    if ok:
                        log.info("  SUCCESS! Ghost AR cleared with UUID=%s sess=%d", u, sess_key)
                        cleared = True
                        break
                if cleared:
                    break
            if not cleared:
                log.warning("  Targeted Release with extracted UUIDs did not succeed.")
                log.warning("  Fallback: try --demo-release or --force-release or power-cycle the device.")
        else:
            log.warning("  No UUIDs found in ConnectRes stub. Device may be in REJECT mode.")
            log.warning("  Options: --demo-release, --force-release, or power-cycle for 60+ seconds.")
        return

    if args.demo_release:
        log.info("== Demo Ghost AR Targeted Release (--demo-release) ==")
        log.info("Ghost AR UUID (from tesysprofinetdemo.pcapng [304]): %s", DEMO_GHOST_AR_UUID)
        log.info("Session key: %d", DEMO_GHOST_AR_SESSKEY)
        log.info("This AR was created by a Siemens PLC session that released successfully in RAM")
        log.info("but the device NVM was not updated (firmware bug v000.000.005), causing the AR")
        log.info("to reappear after every power cycle.")
        cleared = False
        for sess_key in (DEMO_GHOST_AR_SESSKEY, 1, 0):
            log.info("-- Trying sess_key=%d --", sess_key)
            ok = pnio_targeted_release(DEMO_GHOST_AR_UUID, sess_key=sess_key, timeout=5.0)
            if ok:
                cleared = True
                log.info("SUCCESS! Ghost AR cleared. Waiting 2 s then attempting AR Connect ...")
                time.sleep(2.0)
                break
        if not cleared:
            log.error("Demo ghost AR Release failed on all ports and session keys.")
            log.error("The ghost AR UUID on this device may differ from the demo UUID.")
            log.error("Try --spoof-release to impersonate the original PLC session, or power-cycle the device.")
        return

    if args.spoof_release:
        ok = pnio_spoof_release(timeout=5.0)
        if ok:
            log.info("Ghost AR cleared! Waiting 2 s then attempting AR Connect ...")
            time.sleep(2.0)
            # Fall through to full connect sequence below
        else:
            log.error("Spoofed Release failed. Try power-cycling the device for 60+ seconds.")
            log.error("If the ghost AR has a DIFFERENT UUID than the demo, spoof will not help.")
            return

    if args.read_ardata:
        pnio_read_ardata(timeout=5.0)
        return

    if args.spoof_connect:
        ok = pnio_spoof_connect(timeout=8.0)
        if ok:
            log.info("Ghost AR cleared via station-restart spoof!")
            log.info("Waiting 3 s for device to settle, then attempting normal AR Connect ...")
            time.sleep(3.0)
            # Fall through to normal connect/cyclic exchange below
        else:
            log.error("Spoofed Connect did not clear the ghost AR.")
            log.error("Next option: --spoof-same-uuid  (reconnect as original PLC with same UUID)")
            return

    if args.spoof_same_uuid:
        ok = pnio_spoof_same_uuid(timeout=8.0)
        if ok:
            log.info("Ghost AR cleared via same-UUID spoof!")
            log.info("Waiting 3 s for device to settle, then attempting normal AR Connect ...")
            time.sleep(3.0)
            # Fall through to normal connect/cyclic exchange below
        else:
            log.error("SameUUID spoof did not clear the ghost AR.")
            log.error("Next option: --spoof-release, then power-cycle 60+ s, or SoMove USB")
            return

    if args.dcp_reset_comm:
        log.info("== DCP ResetCommunication (SubOption=6, qualifier=0x0002) ==")
        ok = dcp_reset_communication(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
        if ok:
            log.info("DCP ResetCommunication accepted — ghost AR cleared.")
            log.info("Waiting 3 s then attempting AR Connect ...")
            time.sleep(3.0)
            # Fall through to normal connect/cyclic exchange below
        else:
            log.error("DCP ResetCommunication failed (firmware still blocking).")
            log.error("All software options exhausted. Physical options:")
            log.error("  1. Power-cycle TeSys Tera for 60+ seconds")
            log.error("  2. SoMove via USB service cable -> 'Reset Communication'")
            log.error("  3. Firmware update from Schneider Electric support")
            return

    CYCLIC_DURATION_S = args.duration

    if args.wait_hello:
        log.info("== Wait for Device Boot (--wait-hello) ==")
        log.info("  Listens for WS-Discovery Hello (device restart), waits 15 s for PROFINET init, then connects.")
        log.info("  NOTE: TeSys Tera takes ~200 s (~3.5 min) to boot — timeout is 360 s.")
        hello_ok = wait_for_device_hello(timeout=360.0, post_hello_delay=15.0)
        if not hello_ok:
            log.error("  No Hello received — device did not reboot within 6 minutes.")
            log.error("  Power-cycle the device manually (hold power off 10+ s), then rerun --wait-hello.")
            return
        log.info("  Hello received! Proceeding with full DCP preflight + AR Connect ...")
        # Do NOT skip DCP preflight — ghost AR may still be present after reboot
        # Fall through to normal connect/cyclic exchange below

    if args.skip_dcp:
        SKIP_DCP_PREFLIGHT = True

    if args.force_release:
        log.info("== Force-Clear Ghost AR (--force-release) ==")
        log.info("This tries every known software method to release the ghost AR.")
        log.info("Method 1/6: Blind PROFINET AR Release (opnum=1, ARUUID=zeros, flags1=0x20) ...")
        released = pnio_force_release(timeout=5.0)
        if released:
            log.info("  Blind Release succeeded - ghost AR cleared. Waiting 2 s then connecting ...")
            time.sleep(2.0)
        else:
            # Method 2: DCP Set NameOfStation with a valid non-empty name.
            # IMPORTANT: the device returned 0x03 (block-length too short) for empty name,
            # meaning the NameOfStation DCP handler does NOT check DATA_EXCHANGE state.
            # A valid non-empty name should trigger AR abort per IEC 61158-6-10 §4.3.1.4.1.
            # First do a DCP Identify to retrieve the current station name so we can
            # set it to something different (which is the spec trigger for AR abort).
            log.info("  Fetching current device name via DCP Identify ...")
            devinfo = dcp_identify_unicast(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
            current_name = devinfo.get("name", "") or ""
            alt_name = "tesys-tera-ar-fix" if current_name != "tesys-tera-ar-fix" else "tera-reset-tmp"
            log.info("  Current name=%r  will try setting name=%r to trigger AR abort", current_name, alt_name)
            log.info("Method 2/6: DCP Set NameOfStation=%r (spec mandates AR abort on name change) ...", alt_name)
            acked, result = dcp_set_station_name(
                SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, name=alt_name, timeout=4.0)
            if acked and result == 0x00:
                log.info("  DCP Set Name accepted - waiting 3 s for AR teardown ...")
                time.sleep(3.0)
            else:
                # Method 2b: also try with the original empty-string form
                log.info("  Method 2b: also trying DCP Set NameOfStation='' (factory-reset name) ...")
                acked_b, result_b = dcp_set_station_name(
                    SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, name="", timeout=4.0)
                if acked_b and result_b == 0x00:
                    log.info("  DCP Set Name '' accepted - waiting 3 s for AR teardown ...")
                    time.sleep(3.0)
                else:
                    log.info("Method 3/6: DCP ResetToFactory SubOpt=6 (ResetCommunication only) ...")
                    ok = dcp_reset_communication(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                    if ok:
                        log.info("  DCP ResetCommunication accepted - ghost AR should be cleared.")
                        log.info("  Waiting 3 s then attempting AR Connect ...")
                        time.sleep(3.0)
                    else:
                        log.info("Method 4/6: DCP ResetToFactory SubOpt=5 ALL (qualifier=0x0001) ...")
                        ok = dcp_reset_all(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=4.0)
                        if ok:
                            log.info("  DCP ResetToFactory ALL accepted - device will reboot.")
                            log.info("  Wait 10 s after device power LED stabilises then rerun without --force-release.")
                            return
                        else:
                            log.info("Method 5/6: DCP Set IP permanent (qualifier=0x0001) ...")
                            acked2, r2 = dcp_set_ip(
                                SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC,
                                ip=TARGET_IP, subnet=TARGET_SUBNET, gateway="0.0.0.0",
                                permanent=True, timeout=4.0)
                            if acked2 and r2 == 0x00:
                                log.info("  DCP Set IP (permanent) accepted - waiting 3 s ...")
                                time.sleep(3.0)
                            else:
                                log.info("Method 6/6: Modbus TCP (port 502) communication-fault reset ...")
                                modbus_ok = modbus_tcp_force_ar_release(TARGET_IP, timeout=4.0)
                                log.info("  Modbus TCP result: %s", "accessible" if modbus_ok else "not accessible")

                                log.info("Method 7/7: HTTP web interface probe (port 80) ...")
                                http_ok = http_probe_ar_release(TARGET_IP, timeout=4.0)
                                log.info("  HTTP probe result: %s", "responded" if http_ok else "no HTTP server")

                                if not modbus_ok and not http_ok:
                                    log.error(
                                        "  All 7 software methods failed (device firmware bug confirmed).\n"
                                        "  REQUIRED: Physical power-off of TeSys Tera for 60+ seconds,\n"
                                        "  then wait 15 s after power-on before rerunning the script.\n"
                                        "  Alternative: Connect SoMove via USB service cable and use\n"
                                        "  'Reset Communication' or 'Force Disconnect' to clear the AR.\n"
                                        "  If a 60-s power-off still fails, contact Schneider Electric\n"
                                        "  support and request a firmware NVM clear procedure.")
                                    return
        log.info("Attempting AR Connect after force-release ...")

    ctrl = PNIOController()
    ctrl.run()


if __name__ == "__main__":
    main()
