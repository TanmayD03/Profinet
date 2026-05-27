#!/usr/bin/env python3
"""
PROFINET IO Controller — TeSys Tera Motor Management Relay  [v5]
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
import socket
import struct
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
        AsyncSniffer, Ether, IP, UDP, Dot1Q, Raw,
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
STATION_NAME       = "tesys-tera-pn"
INPUT_LEN          = 40        # process input bytes (device → controller)
OUTPUT_LEN         = 4         # process output bytes (controller → device)
CYCLIC_DURATION_S  = 60.0

# Windows NPF adapter GUID.  Find yours with:
#   python -c "from scapy.all import get_if_list; print(get_if_list())"
SCAPY_IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROTOCOL CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PNIO_UDP_PORT   = 34964
PROFINET_ETYPE  = 0x8892

# Object UUID of the device's Context Manager endpoint (Anybus/HMS stack)
PNIO_CM_OBJ_UUID  = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
# Interface UUID — fixed by PROFINET standard
PNIO_CM_IF_UUID   = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
# Controller's own Object UUID — placed in ARBlock.CMInitiatorObjectUUID
PNIO_CTRL_OBJ_UUID = uuid.UUID("dea00002-6c97-11d1-8271-00a02442df7d")

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
SESSION_KEY  = 0x0001

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
# DCE/RPC v4 CL-PDU builder
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def build_request(seq_num: int,
                  opnum: int,
                  obj_uuid: uuid.UUID,
                  if_uuid: uuid.UUID,
                  act_uuid: uuid.UUID,
                  stub: bytes) -> bytes:
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
    frag_len = 80 + len(stub)
    h  = struct.pack("<B", 4)
    h += struct.pack("<B", PKT_REQUEST)
    h += struct.pack("<B", PFC_FIRST | PFC_LAST | PFC_OBJ_UUID)
    h += struct.pack("<B", 0)
    h += struct.pack("<BBB", 0x10, 0x00, 0x00)
    h += struct.pack("<B", 0)
    h += _u(obj_uuid)
    h += _u(if_uuid)
    h += _u(act_uuid)
    h += struct.pack("<I", 0)             # server_boot
    h += struct.pack("<I", 0x00010000)    # if_version 1.0
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


def build_ar_block(ar_uuid: uuid.UUID,
                   ctrl_mac: str,
                   station_name: str) -> bytes:
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
    body  += struct.pack(">H", SESSION_KEY)         # SessionKey
    body  += mac_b                                  # CMInitiatorMACAdd  (6 B)
    body  += _u(PNIO_CTRL_OBJ_UUID)                # CMInitiatorObjectUUID  [FIX E]
    body  += struct.pack(">I", 0x00000000)          # ARProperties  [FIX C]
    body  += struct.pack(">H", 0x0064)              # CMInitiatorActivityTimeoutFactor [FIX D]
    body  += struct.pack(">H", PNIO_UDP_PORT)       # CMInitiatorUDPRTPort
    body  += struct.pack(">H", len(name_b))         # StationNameLength
    body  += name_b
    if len(name_b) % 2:
        body += b'\x00'                             # pad station name to even length
    return _block(BT_AR_REQ, body)


@dataclass
class IOCRSpec:
    cr_type:  int           # IOCR_INPUT or IOCR_OUTPUT
    cr_ref:   int           # 1 = input, 2 = output
    frame_id: int           # FRAME_ID_IN or FRAME_ID_OUT
    data_len: int           # payload bytes (process data + 1 IOPS byte)
    slot:     int = 1
    subslot:  int = 0x0001  # use 0x0001 (not 0x8000) for real process submodules
    api:      int = 0


def build_iocr_block(spec: IOCRSpec) -> bytes:
    """
    IOCRBlockReq  (0x0102) — IEC 61158-6-10 §6.3.5.1.3

    Bug fixed:
      F:  LT field is UINT16 (2 bytes).  Was packed as UINT32 (4 bytes),
          shifting DataLength, FrameID and every subsequent field by +2 bytes.
    """
    io_obj  = struct.pack(">H", spec.slot)
    io_obj += struct.pack(">H", spec.subslot)
    io_obj += struct.pack(">H", 0)             # FrameOffset

    api_blk  = struct.pack(">I", spec.api)     # API
    api_blk += struct.pack(">H", 1)            # NumberOfIODataObjects
    api_blk += struct.pack(">H", 0)            # NumberOfIOCS
    api_blk += io_obj

    body  = struct.pack(">H", spec.cr_type)    # IOCRType
    body += struct.pack(">H", spec.cr_ref)     # IOCRReference
    body += struct.pack(">H", PROFINET_ETYPE)  # LT  [FIX F: 2 bytes not 4]
    body += struct.pack(">I", 0x00000000)      # IOCRProperties
    body += struct.pack(">H", spec.data_len)   # DataLength
    body += struct.pack(">H", spec.frame_id)   # FrameID
    body += struct.pack(">H", 32)              # SendClockFactor (32 × 31.25 µs = 1 ms)
    body += struct.pack(">H", 32)              # ReductionRatio  (32 ms cycle)
    body += struct.pack(">H", 1)              # Phase  (1-indexed, not 0)
    body += struct.pack(">H", 0)              # Sequence
    body += struct.pack(">I", 0xFFFFFFFF)     # FrameSendOffset = best effort
    body += struct.pack(">H", 5)              # WatchdogFactor  (5 × 32 ms = 160 ms)
    body += struct.pack(">H", 5)              # DataHoldFactor
    body += struct.pack(">H", 0xC000)         # IOCRTagHeader   (prio=6, VID=0)
    body += b'\x00\x00\x00\x00\x00\x00'      # IOCRMulticastMACAdd (unicast = zeros)
    body += struct.pack(">H", 1)              # NumberOfAPIs
    body += api_blk
    return _block(BT_IOCR_REQ, body)


def build_expected_submodule_block(in_len: int, out_len: int) -> bytes:
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
    sub  = struct.pack(">H", 0x0001)           # SubslotNumber (matches IOCR)
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
    """AlarmCRBlockReq  (0x0103) — minimal alarm channel."""
    body  = struct.pack(">H", 0x0001)         # AlarmCRType
    body += struct.pack(">H", PROFINET_ETYPE) # LT
    body += struct.pack(">I", 0x00000000)     # AlarmCRProperties
    body += struct.pack(">H", 200)            # RTATimeoutFactor  (200 × 1 ms = 200 ms)
    body += struct.pack(">H", 3)              # RTARetries
    body += struct.pack(">H", 1)              # LocalAlarmReference
    body += struct.pack(">H", 200)            # MaxAlarmDataLength
    body += struct.pack(">H", 0x0000)         # AlarmCRTagHeaderHigh
    body += struct.pack(">H", 0x0000)         # AlarmCRTagHeaderLow
    return _block(BT_ALARM_CR, body)


def build_connect_stub(ar_uuid: uuid.UUID,
                       ctrl_mac: str,
                       station_name: str,
                       in_len: int,
                       out_len: int) -> bytes:
    """Full NDR stub for IODConnectReq (opnum 0). Blocks concatenated directly."""
    ar    = build_ar_block(ar_uuid, ctrl_mac, station_name)
    in_cr = build_iocr_block(IOCRSpec(IOCR_INPUT,  1, FRAME_ID_IN,  in_len + 1))
    ou_cr = build_iocr_block(IOCRSpec(IOCR_OUTPUT, 2, FRAME_ID_OUT, out_len + 1))
    esm   = build_expected_submodule_block(in_len, out_len)
    alarm = build_alarm_cr_block()
    return ar + in_cr + ou_cr + esm + alarm


def build_control_stub(ar_uuid: uuid.UUID, ctrl_cmd: int) -> bytes:
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
    body += struct.pack(">H", SESSION_KEY)      # SessionKey
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
                           src_mac: str, dst_mac: str):
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
    payload  = struct.pack(">H", FRAME_ID_OUT)   # [FIX L]
    payload += out_data
    payload += struct.pack(">B", 0x80)            # IOPS = GOOD
    payload += struct.pack(">H", cycle)
    payload += struct.pack(">B", 0x35)            # DataStatus
    payload += struct.pack(">B", 0x00)            # TransferStatus
    return (Ether(dst=dst_mac, src=src_mac) /
            Dot1Q(prio=6, id=0, vlan=0, type=PROFINET_ETYPE) /
            Raw(load=payload))


def parse_input_rt_frame(raw: bytes, in_len: int) -> Optional[bytes]:
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
    if struct.unpack_from(">H", raw, off)[0] != FRAME_ID_IN:   # [FIX N]
        return None
    off += 2
    if len(raw) < off + in_len:
        return None
    return raw[off: off + in_len]


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

        # BPF filter: capture UDP from the device back to us on port 34964
        self._bpf = (f"udp and src host {dst_ip} and dst host {src_ip} "
                     f"and src port {dport} and dst port {sport}")

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

    def send_recv(self, payload: bytes, label: str,
                  timeout: float = 3.0) -> Optional[bytes]:
        """
        Send a DCE/RPC payload, wait up to `timeout` seconds for a response.
        Returns the raw DCE/RPC bytes (without Ethernet/IP/UDP headers), or None.
        """
        resp_q: queue.Queue = queue.Queue()

        def _handler(pkt):
            if pkt.haslayer(Raw):
                raw = bytes(pkt[Raw])
                # Accept only Response or Fault packets (not echoes of our own Requests)
                if len(raw) > 1 and raw[1] in (PKT_RESPONSE, PKT_FAULT):
                    resp_q.put(raw)

        sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self._bpf,
            prn=_handler,
            store=False,
        )
        sniffer.start()
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

        if resp is None:
            log.error("TIMEOUT — no response to %s", label)
            log.error("  Check: (1) SCAPY_IFACE GUID is correct for the NIC with "
                      "IP %s", self.src_ip)
            log.error("  Check: (2) Npcap/WinPcap is installed (run as Administrator)")
            log.error("  Check: (3) TeSys Tera was power-cycled before this run")
            log.error("  Check: (4) 'ping %s' works from this PC", self.dst_ip)
            # ── Fallback diagnostic: listen for ANYTHING from the device ─────
            # If this catches packets, the device IS responding but on a port/
            # protocol not matched by the strict BPF above — helps narrow down
            # the problem without Wireshark.
            log.info("  Running 2 s fallback capture (any frame src=%s) …", self.dst_ip)
            wide_bpf = f"ether src {self.dst_mac}"
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
                log.warning("  Fallback captured %d frame(s) from %s — "
                            "device IS reachable but response didn't match BPF filter.",
                            len(seen), self.dst_mac)
                for frm in seen[:3]:
                    raw = bytes(frm)
                    log.warning("    frame len=%d  bytes[0:20]=%s", len(raw), raw[:20].hex())
            else:
                log.error("  Fallback: no frames at all from %s — "
                          "check cable, VLAN, and SCAPY_IFACE GUID.", self.dst_mac)
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

        return resp

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FIX 3 — DCP Identify probe  (Layer-2, no IP required)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def list_interfaces() -> None:
    """
    Print all Scapy-visible network interfaces with their IPv4 addresses.
    Helps the user identify the correct SCAPY_IFACE GUID.

    Call from a Python shell:  python -c "from tesys_pn_v5 import list_interfaces; list_interfaces()"
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


def dcp_identify(iface: str, src_mac: str, dst_mac: str,
                 timeout: float = 2.0) -> bool:
    """
    FIX 3: Send a PROFINET DCP Identify Request (unicast to dst_mac) and wait
    for the DCP Identify Response.  This is a pure Layer-2 probe — it works
    even when no IP address has been assigned yet — and is the correct
    pre-flight check before attempting a DCE/RPC AR Connect.

    DCP Identify Request frame (IEC 61158-6-10 §6.3.13):
      EtherType  0x8892
      FrameID    0xFEFF  (DCP-Identify-ReqPDU)
      ServiceID  0x05    (Identify)
      ServiceType 0x00   (Request)
      Xid        any 4-byte value
      ResponseDelay  1  (units of 10 ms)
      DCPDataLength  4
      Option/SubOption  0xFF/0xFF  (All)
      DCPBlockLength  0

    Returns True if the device responds (is alive on the wire).
    """
    # FrameID + ServiceID/Type + Xid + ResponseDelay + DataLength
    xid = 0x11223344
    dcp_req  = struct.pack(">H", 0xFEFF)          # FrameID
    dcp_req += struct.pack(">BB", 0x05, 0x00)     # ServiceID = Identify, Request
    dcp_req += struct.pack(">I", xid)             # Xid
    dcp_req += struct.pack(">H", 1)               # ResponseDelay  (10 ms unit)
    dcp_req += struct.pack(">H", 4)               # DCPDataLength
    dcp_req += struct.pack(">BB", 0xFF, 0xFF)     # Option/SubOption = All
    dcp_req += struct.pack(">H", 0)               # DCPBlockLength

    frame = (Ether(dst=dst_mac, src=src_mac, type=PROFINET_ETYPE) /
             Raw(load=dcp_req))

    found: list = []

    def _handler(pkt):
        if not pkt.haslayer(Raw):
            return
        raw = bytes(pkt[Raw])
        if len(raw) < 10:
            return
        fid = struct.unpack_from(">H", raw, 0)[0]
        # DCP Identify Response FrameIDs: 0xFEFD (multicast) or 0xFEFE (unicast)
        if fid in (0xFEFD, 0xFEFE):
            found.append(raw)

    bpf = f"ether src {dst_mac} and ether proto 0x{PROFINET_ETYPE:04x}"
    sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=_handler, store=False)
    sniffer.start()
    time.sleep(0.20)

    sendp(frame, iface=iface, verbose=False)
    log.debug("DCP Identify → %s", dst_mac)

    deadline = time.monotonic() + timeout
    while not found and time.monotonic() < deadline:
        time.sleep(0.05)

    try:
        sniffer.stop()
    except Exception:
        pass

    if found:
        log.info("DCP Identify OK — device %s is alive on the wire  (%d B)",
                 dst_mac, len(found[0]))
        return True
    else:
        log.error("DCP Identify TIMEOUT — no response from %s within %.1f s",
                  dst_mac, timeout)
        log.error("  The device is not reachable at Layer 2.  Check:")
        log.error("  (1) SCAPY_IFACE GUID — run list_interfaces() to find the right one")
        log.error("  (2) Cable and switch port between controller NIC and TeSys Tera")
        log.error("  (3) TeSys Tera is powered on and not in fault state")
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
        self.ar_uuid   = uuid.uuid4()
        self.act_uuid  = uuid.uuid4()
        self.seq_num   = 0

        self._out_data = b'\x00' * OUTPUT_LEN
        self._out_lock = threading.Lock()

        self.xport = ScapyTransport(
            iface   = SCAPY_IFACE,
            src_mac = CONTROLLER_MAC, src_ip = CONTROLLER_IP,
            dst_mac = TARGET_MAC,     dst_ip = TARGET_IP,
            sport   = PNIO_UDP_PORT,  dport  = PNIO_UDP_PORT,
        )

        log.info("══════════════════════════════════════════")
        log.info("PROFINET Controller")
        log.info("  Target     : %s  %s", TARGET_IP, TARGET_MAC)
        log.info("  Controller : %s  %s", CONTROLLER_IP, CONTROLLER_MAC)
        log.info("  Object UUID: %s", PNIO_CM_OBJ_UUID)
        log.info("  AR UUID    : %s", self.ar_uuid)
        log.info("  Activity   : %s", self.act_uuid)
        log.info("  IFACE      : %s", SCAPY_IFACE)
        log.info("══════════════════════════════════════════")

    # ── internal ─────────────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        s = self.seq_num
        self.seq_num += 1
        return s

    def _send(self, opnum: int, stub: bytes, label: str,
              timeout: float = 3.0) -> Optional[bytes]:
        pkt = build_request(
            seq_num  = self._next_seq(),
            opnum    = opnum,
            obj_uuid = PNIO_CM_OBJ_UUID,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
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
            self.ar_uuid, CONTROLLER_MAC, STATION_NAME, INPUT_LEN, OUTPUT_LEN)
        resp = self._send(OP_CONNECT, stub, "Connect")
        if resp is None:
            return False
        log.info("    ConnectRes OK  (%d bytes)", len(resp))
        if len(resp) > 96:
            log.debug("    stub[0:24]: %s", resp[80:104].hex())
        return True

    def step_prm_end(self) -> bool:
        """IODControlReq PrmEnd — opnum 2, ControlCommand=0x0008. [FIX G/H/I]"""
        log.info("── PrmEnd (opnum=%d, cmd=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_PRM_END, self.seq_num)
        resp = self._send(OP_CONTROL, build_control_stub(self.ar_uuid, CTRL_PRM_END),
                          "PrmEnd")
        if resp is None:
            return False
        log.info("    PrmEndRes OK")
        return True

    def step_application_ready(self) -> bool:
        """IODControlReq ApplicationReady — opnum 2, ControlCommand=0x0010. [FIX J/K/I]"""
        log.info("── ApplicationReady (opnum=%d, cmd=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_APP_READY, self.seq_num)
        resp = self._send(OP_CONTROL, build_control_stub(self.ar_uuid, CTRL_APP_READY),
                          "ApplicationReady")
        if resp is None:
            return False
        log.info("    ApplicationReadyRes OK — IO data exchange is now ACTIVE")
        return True

    # ── Acyclic services ─────────────────────────────────────────────────────

    def acyclic_read(self, slot: int = 1, subslot: int = 0x0001,
                     index: int = 0xF830, max_len: int = 0x8000) -> Optional[bytes]:
        """
        IODReadReq (opnum 3).

        Useful record indices:
          0xF830  I&M 0 — manufacturer/order/serial/revision
          0xF831  I&M 1 — installation tag
          0x8028  PDPortDataReal — port status
          0xB081  Diagnosis
        """
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
                      slot: int = 1, subslot: int = 0x0001,
                      index: int = 0x0000) -> bool:
        """IODWriteReq (opnum 4)."""
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
            frame = build_output_rt_frame(out, cycle, CONTROLLER_MAC, TARGET_MAC)
            try:
                sendp(frame, iface=SCAPY_IFACE, verbose=False)
            except Exception as e:
                log.warning("TX error: %s", e)
            stop.wait(0.032)

    def read_cyclic_data(self, duration_s: float = CYCLIC_DURATION_S):
        """Start TX thread and sniff input RT frames for `duration_s` seconds."""
        log.info("══ Cyclic exchange  %.0f s ══", duration_s)

        stop_tx = threading.Event()
        tx_thr  = threading.Thread(target=self._tx_loop, args=(stop_tx,), daemon=True)
        tx_thr.start()

        bpf = f"ether src {TARGET_MAC} and ether proto 0x8892"
        log.info("Sniffing: iface='%s'  filter='%s'", SCAPY_IFACE, bpf)
        count = 0
        try:
            frames = AsyncSniffer(iface=SCAPY_IFACE, filter=bpf, timeout=duration_s)
            frames.start()
            frames.join()
            for frm in (frames.results or []):
                raw = bytes(frm)
                inp = parse_input_rt_frame(raw, INPUT_LEN)
                if inp is None:
                    continue
                count += 1
                d = decode_tesys_input(inp)
                log.info("  [%4d]  V=%6.1f V  I=%5.1f %%FLC  "
                         "state=0x%02x  trip=0x%02x  thermal=%d  P=%.3f kW",
                         count, d["voltage_V"], d["current_pct_flc"],
                         d["motor_state"], d["last_trip_cause"],
                         d["thermal_state"], d["power_kW"])
        except Exception as e:
            log.error("Scapy sniff error: %s", e)
            log.error("Verify SCAPY_IFACE GUID and that Npcap is installed.")
        finally:
            stop_tx.set()
            tx_thr.join(timeout=2.0)

        log.info("Cyclic complete — %d valid input frames received", count)
        if count == 0:
            log.warning("Zero input frames.  Troubleshoot:")
            log.warning("  1. SCAPY_IFACE matches the NIC at %s", CONTROLLER_IP)
            log.warning("  2. Wireshark: device sends FrameID=0x%04x from %s",
                        FRAME_ID_IN, TARGET_MAC)
            log.warning("  3. Our output frames (FrameID=0x%04x) reach the device",
                        FRAME_ID_OUT)

    # ── Main run sequence ────────────────────────────────────────────────────

    def run(self):
        """Full AR establishment + cyclic exchange."""
        # Pre-flight: verify scapy is available
        if not SCAPY_OK:
            log.error("scapy is not installed.  Run:  pip install scapy")
            return

        # ── FIX 3: DCP Identify pre-flight ───────────────────────────────────
        # Verify the device is alive at Layer 2 before wasting time on
        # DCE/RPC.  If this fails the problem is the NIC selection or cable,
        # not the PROFINET protocol implementation.
        log.info("── DCP Identify pre-flight ──")
        list_interfaces()   # always show interface table — helps with GUID selection
        alive = dcp_identify(SCAPY_IFACE, CONTROLLER_MAC, TARGET_MAC, timeout=3.0)
        if not alive:
            log.error("Aborting — fix Layer-2 connectivity first, then retry.")
            return
        time.sleep(0.10)

        # seq=0  AR Connect  (no BIND — would steal seq=0)  [FIX O]
        # Retry up to 3 times; ghost-AR lock usually clears after a power-cycle
        for attempt in range(1, 4):
            if self.step_ar_connect():
                break
            if attempt < 3:
                log.warning("Connect attempt %d/3 failed — retrying in 3 s …", attempt)
                time.sleep(3.0)
                self.seq_num = 0   # reset sequence counter for fresh attempt
        else:
            log.error("AR Connect failed after 3 attempts — aborting")
            log.error("Power-cycle TeSys Tera, wait 10 s, then retry.")
            return
        time.sleep(0.15)

        # seq=1  PrmEnd
        if not self.step_prm_end():
            log.error("PrmEnd failed — aborting")
            return
        time.sleep(0.15)

        # seq=2  ApplicationReady
        if not self.step_application_ready():
            log.error("ApplicationReady failed — aborting")
            return
        time.sleep(0.15)

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

        # Cyclic exchange
        self.read_cyclic_data()

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
    pkt = build_request(0, OP_CONNECT, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'')
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
        p = build_request(1, op, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'')
        chk(f"hdr.opnum_{name}", struct.unpack_from("<H",p,68)[0], op)

    # ── ARBlock ────────────────────────────────────────────────────────────
    ar = build_ar_block(ar_uuid, CONTROLLER_MAC, STATION_NAME)
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
        req  = build_request(1, OP_CONTROL, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, stub)
        chk(f"req.{cname}", struct.unpack_from("<H",req,68)[0], OP_CONTROL)  # FIX G/J

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
    ])
    if failures:
        log.error("══ SELF-TEST: %d/%d FAILED ══", len(failures), total)
        for f in failures:
            log.error("  %s", f)
        sys.exit(1)
    log.info("══ All %d self-tests passed ══", total)

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
