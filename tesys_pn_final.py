#!/usr/bin/env python3
"""
PROFINET IO Controller — TeSys Tera Motor Management Relay
===========================================================
Fully corrected from 16-bug audit.  No EPM, no BIND, pure CL-PDU.

Execution sequence (all DCE/RPC v4 UDP, port 34964):
  seq=0  AR Connect   (opnum 0)  → ConnectRes
  seq=1  PrmEnd       (opnum 2, ControlCommand=0x0008) → ControlRes
  seq=2  AppReady     (opnum 2, ControlCommand=0x0010) → ControlRes
  seq=3+ Acyclic Read (opnum 3) / Write (opnum 4)  [optional]

Cyclic data runs in a background thread (Scapy raw frames).

Hardware (from DCP):
  Target IP  : 192.168.0.61     MAC: 88:01:f9:35:d9:a2
  Controller : 192.168.0.100    MAC: 18:3d:2d:61:f9:70
  Station    : tesys-tera-pn
  Object UUID: dea00000-6c97-11d1-8271-006428ce90d2
  Module 1   : 40 B input, 4 B output

Windows Scapy adapter — update SCAPY_IFACE to match your NPF GUID:
  Run in Python:  from scapy.all import get_if_list; print(get_if_list())
"""

import socket
import struct
import uuid
import time
import logging
import threading
import sys
from dataclasses import dataclass
from typing import Optional, Tuple

# ── Scapy (Windows NPF) ─────────────────────────────────────────────────────
try:
    from scapy.all import sendp, sniff, Ether, Dot1Q, Raw, get_if_hwaddr
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    log_pre = logging.getLogger("boot")
    log_pre.warning("scapy not available — cyclic layer disabled")

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("PNIO")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# USER CONFIGURATION — edit these before running
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET_IP          = "192.168.0.61"
TARGET_MAC         = "88:01:f9:35:d9:a2"
CONTROLLER_IP      = "192.168.0.100"
CONTROLLER_MAC     = "18:3d:2d:61:f9:70"
STATION_NAME       = "tesys-tera-pn"
INPUT_LEN          = 40        # bytes of process input data (from device)
OUTPUT_LEN         = 4         # bytes of process output data (to device)
CYCLIC_DURATION_S  = 60.0      # how long to run the cyclic exchange

# Windows NPF adapter GUID — run get_if_list() in scapy to find yours
SCAPY_IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROTOCOL CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PNIO_UDP_PORT         = 34964
PROFINET_ETYPE        = 0x8892

# Object UUID of the device's Context Manager endpoint (Anybus / HMS)
# This is what goes in the DCE/RPC CL-PDU Object field.
PNIO_CM_OBJ_UUID      = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
# Interface UUID for the PROFINET CM (fixed by standard)
PNIO_CM_IF_UUID       = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
# Controller's own CM UUID — placed in ARBlock.CMInitiatorObjectUUID
PNIO_CTRL_OBJ_UUID    = uuid.UUID("dea00002-6c97-11d1-8271-00a02442df7d")

# DCE/RPC v4 packet types (byte 1 of CL-PDU)
PKT_REQUEST           = 0x00
PKT_RESPONSE          = 0x02
PKT_FAULT             = 0x03

# PFC flags (byte 2)
PFC_FIRST_FRAG        = 0x01
PFC_LAST_FRAG         = 0x02
PFC_OBJECT_UUID       = 0x80   # object UUID field is present and valid

# PROFINET CM opnums (IEC 61158-6-10 §6.3)
OP_CONNECT            = 0      # IODConnectReq/Res
OP_RELEASE            = 1      # IODReleaseReq/Res
OP_CONTROL            = 2      # IODControlReq/Res  ← PrmEnd AND ApplicationReady
OP_READ               = 3      # IODReadReq/Res
OP_WRITE              = 4      # IODWriteReq/Res

# IODControlReq ControlCommand bits (IEC 61158-6-10 Table 566)
CTRL_PRM_END          = 0x0008  # bit 3
CTRL_APP_READY        = 0x0010  # bit 4

# PROFINET block types
BT_AR_REQ             = 0x0101
BT_IOCR_REQ           = 0x0102
BT_ALARM_CR_REQ       = 0x0103
BT_EXP_SUB_REQ        = 0x0104
BT_IOCTRL_REQ         = 0x0110  # IODControlReq

IOCR_INPUT            = 0x0001
IOCR_OUTPUT           = 0x0002
AR_IOCAR_SINGLE       = 0x0001

# Cyclic frame IDs (we configure these in the IOCR blocks)
FRAME_ID_IN           = 0x8000   # input from device → controller
FRAME_ID_OUT          = 0x8001   # output from controller → device

SESSION_KEY           = 0x0001   # fixed; echoed by device in responses

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DCE/RPC CL-PDU (v4) wire format helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _u(u: uuid.UUID) -> bytes:
    """UUID → 16-byte DCE/RPC little-endian wire bytes."""
    return u.bytes_le

def _pu(b: bytes, off: int = 0) -> uuid.UUID:
    """16 wire bytes → UUID."""
    return uuid.UUID(bytes_le=b[off:off+16])


def build_request(seq_num: int,
                  opnum: int,
                  obj_uuid: uuid.UUID,
                  if_uuid: uuid.UUID,
                  act_uuid: uuid.UUID,
                  stub: bytes) -> bytes:
    """
    Build a DCE/RPC v4 CL-PDU Request (80-byte header + stub).

    CL-PDU header layout — all fields little-endian to match drep[0]=0x10:
      [0]     rpc_vers        = 4
      [1]     pkt_type        = PKT_REQUEST (0x00)   ← byte 1, not byte 2!
      [2]     flags1          = FIRST|LAST|OBJECT_UUID
      [3]     flags2          = 0
      [4-6]   drep[3]         = 0x10, 0x00, 0x00   (LE ints, IEEE float, reserved)
      [7]     serial_hi       = 0
      [8-23]  object_uuid     ← device checks this against its endpoint registry
      [24-39] if_uuid
      [40-55] act_uuid
      [56-59] server_boot     = 0
      [60-63] if_version      = 0x00010000  (version 1.0, LE)  ← BUG A was here
      [64-67] seq_num         ← monotonically increasing per activity
      [68-69] opnum           ← 0=Connect 2=Control 3=Read 4=Write
      [70-71] ihint           = 0xFFFF
      [72-73] ahint           = 0xFFFF
      [74-75] frag_len        (LE)
      [76-77] frag_num        = 0
      [78]    auth_proto      = 0
      [79]    serial_lo       = 0
    """
    frag_len = 80 + len(stub)
    h  = struct.pack("<B", 4)                                 # rpc_vers
    h += struct.pack("<B", PKT_REQUEST)                        # pkt_type  [byte 1]
    h += struct.pack("<B", PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_OBJECT_UUID)  # flags1
    h += struct.pack("<B", 0)                                  # flags2
    h += struct.pack("<BBB", 0x10, 0x00, 0x00)                 # drep[3]
    h += struct.pack("<B", 0)                                  # serial_hi
    h += _u(obj_uuid)                                          # object  [8-23]
    h += _u(if_uuid)                                           # if_uuid [24-39]
    h += _u(act_uuid)                                          # act_uuid[40-55]
    h += struct.pack("<I", 0)                                  # server_boot
    h += struct.pack("<I", 0x00010000)                         # if_version 1.0  [FIX A]
    h += struct.pack("<I", seq_num)                            # seq_num
    h += struct.pack("<H", opnum)                              # opnum
    h += struct.pack("<H", 0xFFFF)                             # ihint
    h += struct.pack("<H", 0xFFFF)                             # ahint
    h += struct.pack("<H", frag_len)                           # frag_len
    h += struct.pack("<H", 0)                                  # frag_num
    h += struct.pack("<B", 0)                                  # auth_proto
    h += struct.pack("<B", 0)                                  # serial_lo
    assert len(h) == 80, f"CL-PDU header must be 80 bytes, got {len(h)}"
    return h + stub


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROFINET block builders  (IEC 61158-6-10)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _block(block_type: int, body: bytes, ver_hi: int = 1, ver_lo: int = 0) -> bytes:
    """
    Wrap body in a PROFINET block envelope.

    Wire layout:
      BlockType   (2B, BE)
      BlockLength (2B, BE)  = len(body) + 2   [counts Ver bytes, not Type/Len]
      BlockVersionHigh (1B)
      BlockVersionLow  (1B)
      body
    """
    block_len = 2 + len(body)   # +2 for the two version bytes
    return (struct.pack(">HH", block_type, block_len) +
            struct.pack(">BB", ver_hi, ver_lo) +
            body)


def build_ar_block(ar_uuid: uuid.UUID,
                   ctrl_mac: str,
                   ctrl_ip: str,
                   station_name: str) -> bytes:
    """
    ARBlockReq (block type 0x0101) — IEC 61158-6-10 §6.3.5.1.1

    Fixed bugs vs previous version:
      C: ARProperties = 0x00000000   (was 0x00000001 = PullModule flag)
      D: CMInitiatorActivityTimeoutFactor = 0x0064  (was 0x8892 = ethertype!)
      E: CMInitiatorObjectUUID = PNIO_CTRL_OBJ_UUID  (was PNIO_CM_IF_UUID)
    """
    mac = bytes(int(x, 16) for x in ctrl_mac.split(":"))
    name_b = station_name.encode("ascii")

    body  = struct.pack(">H", AR_IOCAR_SINGLE)        # ARType = IOCAR_SINGLE
    body += _u(ar_uuid)                                # ARUUID (LE, per PNIO spec)
    body += struct.pack(">H", SESSION_KEY)             # SessionKey
    body += mac                                        # CMInitiatorMACAdd (6B)
    body += _u(PNIO_CTRL_OBJ_UUID)                    # CMInitiatorObjectUUID [FIX E]
    body += struct.pack(">I", 0x00000000)              # ARProperties [FIX C]
    body += struct.pack(">H", 0x0064)                  # CMInitiatorActivityTimeoutFactor [FIX D]
    body += struct.pack(">H", PNIO_UDP_PORT)           # CMInitiatorUDPRTPort
    body += struct.pack(">H", len(name_b))             # StationNameLength
    body += name_b
    if len(name_b) % 2:
        body += b'\x00'                                # pad to even

    return _block(BT_AR_REQ, body)


@dataclass
class IOCRSpec:
    cr_type:  int    # IOCR_INPUT or IOCR_OUTPUT
    cr_ref:   int    # 1 = input IOCR, 2 = output IOCR
    frame_id: int    # FRAME_ID_IN or FRAME_ID_OUT
    data_len: int    # total bytes including IOPS byte(s)
    slot:     int = 1
    subslot:  int = 0x8000
    api:      int = 0


def build_iocr_block(spec: IOCRSpec) -> bytes:
    """
    IOCRBlockReq (block type 0x0102) — IEC 61158-6-10 §6.3.5.1.3

    Fixed bug vs previous version:
      F: LT field is 2 bytes (Ethertype UINT16), was packed as 4 bytes
         causing DataLength, FrameID, and every subsequent field to be wrong.
    """
    # API sub-block: one IO data object at this slot/subslot
    api_sub  = struct.pack(">I", spec.api)            # API
    api_sub += struct.pack(">H", 1)                   # NumberOfIODataObjects
    api_sub += struct.pack(">H", 0)                   # NumberOfIOCS
    # IO data object descriptor
    api_sub += struct.pack(">H", spec.slot)
    api_sub += struct.pack(">H", spec.subslot)
    api_sub += struct.pack(">H", 0)                   # FrameOffset

    body  = struct.pack(">H", spec.cr_type)           # IOCRType
    body += struct.pack(">H", spec.cr_ref)            # IOCRReference
    body += struct.pack(">H", PROFINET_ETYPE)         # LT = Ethertype  [FIX F: 2 bytes, not 4]
    body += struct.pack(">I", 0x00000000)             # IOCRProperties
    body += struct.pack(">H", spec.data_len)          # DataLength (data + IOPS byte)
    body += struct.pack(">H", spec.frame_id)          # FrameID
    body += struct.pack(">H", 32)                     # SendClockFactor (32 × 31.25µs = 1ms)
    body += struct.pack(">H", 32)                     # ReductionRatio  (32ms cycle)
    body += struct.pack(">H", 1)                      # Phase
    body += struct.pack(">H", 0)                      # Sequence
    body += struct.pack(">I", 0xFFFFFFFF)             # FrameSendOffset (best effort)
    body += struct.pack(">H", 5)                      # WatchdogFactor (5 × 32ms = 160ms)
    body += struct.pack(">H", 5)                      # DataHoldFactor
    body += struct.pack(">H", 0xC000)                 # IOCRTagHeader (prio=6, VID=0)
    body += b'\x00\x00\x00\x00\x00\x00'              # IOCRMulticastMACAdd (unicast)
    body += struct.pack(">H", 1)                      # NumberOfAPIs
    body += api_sub

    return _block(BT_IOCR_REQ, body)


def build_expected_submodule_block(in_len: int, out_len: int) -> bytes:
    """
    ExpectedSubmoduleBlockReq (0x0104) — one API, one slot, one submodule.
    SubmoduleDataDescription covers the input direction.
    """
    # Submodule descriptor
    sub  = struct.pack(">H", 0x8000)               # SubslotNumber
    sub += struct.pack(">I", 0x00000001)            # SubmoduleIdentNumber
    sub += struct.pack(">H", 0x0000)               # SubmoduleProperties
    # Input data description
    sub += struct.pack(">H", 0x0001)               # SubmoduleDataDescription = INPUT
    sub += struct.pack(">H", in_len)               # SubmoduleDataLength
    sub += struct.pack(">B", 1)                    # LengthIOCS
    sub += struct.pack(">B", 1)                    # LengthIOPS

    # Module descriptor at slot 1
    mod  = struct.pack(">H", 1)                    # SlotNumber
    mod += struct.pack(">I", 0x00001503)           # ModuleIdentNumber (TeSys Tera device ID)
    mod += struct.pack(">H", 0x0000)               # ModuleProperties
    mod += struct.pack(">H", 1)                    # NumberOfSubmodules
    mod += sub

    # API wrapper
    api  = struct.pack(">I", 0)                    # API = 0
    api += struct.pack(">H", 1)                    # NumberOfModules
    api += mod

    body = struct.pack(">H", 1) + api              # NumberOfAPIs = 1
    return _block(BT_EXP_SUB_REQ, body)


def build_alarm_cr_block() -> bytes:
    """AlarmCRBlockReq (0x0103) — minimal alarm channel configuration."""
    body  = struct.pack(">H", 0x0001)             # AlarmCRType
    body += struct.pack(">H", PROFINET_ETYPE)      # LT
    body += struct.pack(">I", 0x00000000)          # AlarmCRProperties
    body += struct.pack(">H", 200)                 # RTATimeoutFactor
    body += struct.pack(">H", 3)                   # RTARetries
    body += struct.pack(">H", 1)                   # LocalAlarmReference
    body += struct.pack(">H", 200)                 # MaxAlarmDataLength
    body += struct.pack(">H", 0x0000)              # AlarmCRTagHeaderHigh
    body += struct.pack(">H", 0x0000)              # AlarmCRTagHeaderLow
    return _block(BT_ALARM_CR_REQ, body)


def build_connect_stub(ar_uuid: uuid.UUID,
                       ctrl_mac: str,
                       ctrl_ip: str,
                       station_name: str,
                       in_len: int,
                       out_len: int) -> bytes:
    """
    Full NDR stub for IODConnectReq (opnum 0).
    Blocks are concatenated directly — no NDR length prefix for PROFINET.
    """
    ar    = build_ar_block(ar_uuid, ctrl_mac, ctrl_ip, station_name)
    in_cr = build_iocr_block(IOCRSpec(IOCR_INPUT,  1, FRAME_ID_IN,  in_len + 1))
    ou_cr = build_iocr_block(IOCRSpec(IOCR_OUTPUT, 2, FRAME_ID_OUT, out_len + 1))
    esm   = build_expected_submodule_block(in_len, out_len)
    alarm = build_alarm_cr_block()
    return ar + in_cr + ou_cr + esm + alarm


def build_control_stub(ar_uuid: uuid.UUID, control_command: int) -> bytes:
    """
    IODControlReq stub (opnum 2) for both PrmEnd and ApplicationReady.

    Block structure (IEC 61158-6-10 §6.3.10.1):
      BlockType          (2B): 0x0110
      BlockLength        (2B): 28  [= 2+2+16+2+2+2+2 — counts from Version onwards]
      BlockVersionHigh   (1B): 1
      BlockVersionLow    (1B): 0
      Padding            (2B): 0x0000   ← BUG I: these 2 bytes were missing!
      ARUUID            (16B): LE
      SessionKey         (2B): 0x0001
      Padding            (2B): 0x0000
      ControlCommand     (2B): 0x0008=PrmEnd  0x0010=ApplicationReady  [FIX H/K]
      ControlBlockProps  (2B): 0x0000

    opnum for both = 2 (IODControlReq)  [FIX G/J]
    """
    body  = struct.pack(">H", 0x0000)             # Padding [FIX I]
    body += _u(ar_uuid)                            # ARUUID
    body += struct.pack(">H", SESSION_KEY)         # SessionKey
    body += struct.pack(">H", 0x0000)             # Padding
    body += struct.pack(">H", control_command)     # ControlCommand [FIX H or K]
    body += struct.pack(">H", 0x0000)             # ControlBlockProperties
    return _block(BT_IOCTRL_REQ, body)


def build_read_stub(ar_uuid: uuid.UUID,
                    slot: int, subslot: int, index: int,
                    max_len: int = 0x8000) -> bytes:
    """
    IODReadReq stub (opnum 3) — acyclic record read.

    Stub layout (IEC 61158-6-10 §6.3.6.3.1):
      SeqNum    (2B)
      Padding   (2B)
      ARUUID   (16B)
      API       (4B)
      Slot      (2B)
      Subslot   (2B)
      Padding   (2B)
      Index     (2B)
      MaxLen    (4B)
      TargetARUUID (16B) = zeros (not used)
      Padding  (20B)
    """
    stub  = struct.pack(">HH", 0, 0)              # SeqNum, Padding
    stub += _u(ar_uuid)                            # ARUUID
    stub += struct.pack(">I", 0)                   # API
    stub += struct.pack(">H", slot)                # SlotNumber
    stub += struct.pack(">H", subslot)             # SubslotNumber
    stub += struct.pack(">H", 0)                   # Padding
    stub += struct.pack(">H", index)               # Index
    stub += struct.pack(">I", max_len)             # RecordDataLength
    stub += _u(uuid.UUID(int=0))                   # TargetARUUID (unused)
    stub += b'\x00' * 20                           # Reserved padding
    return stub


def build_write_stub(ar_uuid: uuid.UUID,
                     slot: int, subslot: int, index: int,
                     data: bytes) -> bytes:
    """
    IODWriteReq stub (opnum 4) — acyclic record write.

    Same header as IODReadReq, then RecordDataLength actual data bytes.
    """
    stub  = struct.pack(">HH", 0, 0)
    stub += _u(ar_uuid)
    stub += struct.pack(">I", 0)
    stub += struct.pack(">H", slot)
    stub += struct.pack(">H", subslot)
    stub += struct.pack(">H", 0)
    stub += struct.pack(">H", index)
    stub += struct.pack(">I", len(data))
    stub += _u(uuid.UUID(int=0))
    stub += b'\x00' * 20
    stub += data
    # Align to 4-byte boundary
    pad = (4 - len(data) % 4) % 4
    stub += b'\x00' * pad
    return stub


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROFINET RT cyclic frame builders
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def build_output_rt_frame(output_data: bytes,
                           cycle_counter: int,
                           src_mac: str,
                           dst_mac: str) -> bytes:
    """
    Build a PROFINET RT output frame (controller → device).

    Wire structure after Ethernet header + optional VLAN tag:
      FrameID        (2B, BE): FRAME_ID_OUT = 0x8001   [FIX L]
      OutputData     (n bytes): actual output values
      IOPS           (1B):      0x80 = Good             [FIX M: no phantom padding]
      CycleCounter   (2B, BE)
      DataStatus     (1B):      0x35 = Run|Primary|DataValid
      TransferStatus (1B):      0x00

    Notes:
      - DataStatus 0x35 = 0b00110101:
          bit0=1 (Run), bit1=0 (Primary), bit2=1 (DataValid),
          bit4=1 (IgnoreFrameID?), bit5=1 → standard "active" value
      - IOPS = 0x80 = provider status GOOD
      - Frame is VLAN-tagged (prio=6, VID=0) per PROFINET RT Class 1/2
    """
    payload  = struct.pack(">H", FRAME_ID_OUT)    # FrameID [FIX L: 0x8001 not 0x8002]
    payload += output_data                          # output process data
    payload += struct.pack(">B", 0x80)             # IOPS = GOOD
    payload += struct.pack(">H", cycle_counter)    # CycleCounter
    payload += struct.pack(">B", 0x35)             # DataStatus
    payload += struct.pack(">B", 0x00)             # TransferStatus

    if SCAPY_OK:
        # VLAN tag with priority 6, VID 0, PROFINET ethertype
        return (Ether(dst=dst_mac, src=src_mac) /
                Dot1Q(prio=6, id=0, vlan=0, type=PROFINET_ETYPE) /
                Raw(load=payload))
    return payload   # fallback: raw bytes only


def parse_input_rt_frame(raw: bytes, in_len: int) -> Optional[bytes]:
    """
    Extract input data from a captured Ethernet frame.
    Returns raw input bytes or None if not a valid PROFINET input frame.

    Expected frame structure:
      Ethernet header (14B)
      [optional VLAN tag (4B)]
      Ethertype (2B): 0x8892
      FrameID   (2B): FRAME_ID_IN = 0x8000   [FIX N]
      Input data (in_len bytes)
      IOPS (1B)
      CycleCounter (2B)
      DataStatus (1B)
      TransferStatus (1B)
    """
    offset = 12
    if raw[12:14] == b'\x81\x00':   # VLAN tag
        offset += 4
    if len(raw) < offset + 4:
        return None
    ethertype = struct.unpack_from(">H", raw, offset)[0]
    if ethertype != PROFINET_ETYPE:
        return None
    offset += 2
    frame_id = struct.unpack_from(">H", raw, offset)[0]
    if frame_id != FRAME_ID_IN:    # [FIX N: 0x8000, not 0x8001]
        return None
    offset += 2
    if len(raw) < offset + in_len + 1:
        return None
    return raw[offset: offset + in_len]


def decode_tesys_input(data: bytes) -> dict:
    """
    Decode TeSys Tera Module 1 process input data (40 bytes).
    Offsets derived from Schneider Electric PROFINET GSD / user manual.
    Adjust if your firmware version differs.
    """
    if len(data) < 40:
        return {"error": f"short frame ({len(data)} B)"}
    return {
        "status_word_1":   struct.unpack_from(">H", data, 0)[0],
        "status_word_2":   struct.unpack_from(">H", data, 2)[0],
        "current_pct_flc": struct.unpack_from(">I", data, 4)[0] * 0.1,
        "thermal_state":   struct.unpack_from(">H", data, 8)[0],
        "last_trip_cause": data[10],
        "motor_state":     data[11],
        "voltage_v":       struct.unpack_from(">I", data, 24)[0] * 0.1,
        "power_kw":        struct.unpack_from(">I", data, 28)[0] * 0.001,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# IO Controller state machine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

FAULT_CODES = {
    0x1c010003: "nca_unk_if       — wrong Object UUID",
    0x1c010002: "nca_op_rng_error — opnum not registered on this interface",
    0x1c000009: "nca_s_fault_ill_inst — malformed stub (bad block structure)",
    0x1c000008: "nca_s_fault_cancel",
    0x1c010001: "nca_s_unsupported_type — transfer syntax mismatch",
    0x1c00000e: "nca_wrong_boot_time — ghost AR lock (reboot device!)",
}


class PNIOController:
    """
    Full PROFINET IO Controller for TeSys Tera.

    Call .run() which executes:
      1. AR Connect (seq=0)
      2. PrmEnd     (seq=1)
      3. ApplicationReady (seq=2)
      4. Cyclic exchange loop
    """

    def __init__(self,
                 target_ip:    str = TARGET_IP,
                 target_mac:   str = TARGET_MAC,
                 ctrl_ip:      str = CONTROLLER_IP,
                 ctrl_mac:     str = CONTROLLER_MAC,
                 station_name: str = STATION_NAME,
                 in_len:       int = INPUT_LEN,
                 out_len:      int = OUTPUT_LEN):

        self.target_ip    = target_ip
        self.target_mac   = target_mac
        self.ctrl_ip      = ctrl_ip
        self.ctrl_mac     = ctrl_mac
        self.station_name = station_name
        self.in_len       = in_len
        self.out_len      = out_len

        # Fresh UUIDs for each AR
        self.ar_uuid      = uuid.uuid4()
        self.act_uuid     = uuid.uuid4()
        self.seq_num      = 0        # must be 0 for first packet (AR Connect)

        self.sock: Optional[socket.socket] = None
        self._output_data = b'\x00' * out_len   # current output values
        self._output_lock = threading.Lock()

        log.info("══════════════════════════════════════════")
        log.info("PROFINET Controller initialised")
        log.info("  Target     : %s  %s", target_ip, target_mac)
        log.info("  Controller : %s  %s", ctrl_ip, ctrl_mac)
        log.info("  AR UUID    : %s", self.ar_uuid)
        log.info("  Activity   : %s", self.act_uuid)
        log.info("  Object UUID: %s", PNIO_CM_OBJ_UUID)
        log.info("══════════════════════════════════════════")

    # ── Socket management ────────────────────────────────────────────────────

    def _open(self):
        """
        Open UDP socket bound to PNIO_UDP_PORT on the controller IP.

        BUG B FIX: Must bind to port 34964, not 0 (ephemeral).
        IEC 61784-2 §8.3: the CM Controller MUST use port 34964 as
        source port. Devices silently drop packets from any other port.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.ctrl_ip, PNIO_UDP_PORT))   # [FIX B]
        s.settimeout(3.0)
        self.sock = s
        log.debug("UDP socket bound to %s:%d", self.ctrl_ip, PNIO_UDP_PORT)

    def _close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ── Send/receive ─────────────────────────────────────────────────────────

    def _xact(self, pkt: bytes, label: str, timeout: float = 3.0) -> Optional[bytes]:
        """Send one DCE/RPC packet, wait for a response."""
        log.debug(">>> %s  seq=%d  len=%d", label, self.seq_num - 1, len(pkt))
        log.debug("    [0:32] %s", pkt[:32].hex())
        self.sock.settimeout(timeout)
        self.sock.sendto(pkt, (self.target_ip, PNIO_UDP_PORT))
        try:
            resp, addr = self.sock.recvfrom(65535)
        except socket.timeout:
            log.error("TIMEOUT — no response to %s", label)
            return None

        ptype = resp[1] if len(resp) > 1 else 0xFF
        log.debug("<<< %s  ptype=0x%02x  len=%d  from=%s", label, ptype, len(resp), addr)

        if ptype == PKT_FAULT:
            raw_code = resp[80:84] if len(resp) >= 84 else b'\x00' * 4
            code = struct.unpack_from("<I", raw_code)[0]
            desc = FAULT_CODES.get(code, "unknown fault")
            log.error("    DCE/RPC FAULT 0x%08x: %s", code, desc)
            if code == 0x1c00000e:
                log.error("    *** Ghost AR lock: power-cycle the TeSys Tera, wait 10s, retry ***")
            return None

        return resp

    def _next_seq(self) -> int:
        s = self.seq_num
        self.seq_num += 1
        return s

    def _req(self, opnum: int, stub: bytes) -> bytes:
        """Build a request using the next seq_num."""
        return build_request(
            seq_num  = self._next_seq(),
            opnum    = opnum,
            obj_uuid = PNIO_CM_OBJ_UUID,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
        )

    # ── AR establishment steps ───────────────────────────────────────────────

    def step_ar_connect(self) -> bool:
        """
        IODConnectReq — opnum 0, seq_num MUST be 0.

        BUG O FIX: No BIND step precedes this, so seq stays at 0.
        The device will return nca_wrong_boot_time (ghost AR lock) if
        seq != 0 on the first real packet it sees.
        """
        log.info("── AR Connect (opnum=%d, seq=%d) ──", OP_CONNECT, self.seq_num)
        stub = build_connect_stub(
            self.ar_uuid, self.ctrl_mac, self.ctrl_ip,
            self.station_name, self.in_len, self.out_len)

        resp = self._xact(self._req(OP_CONNECT, stub), "Connect")
        if resp is None:
            return False
        if resp[1] != PKT_RESPONSE:
            log.error("Connect: unexpected pkt_type 0x%02x", resp[1])
            return False

        # Parse ConnectRes to confirm success and log session key
        log.info("    ConnectRes received (%d bytes) — AR established", len(resp))
        if len(resp) > 84:
            log.debug("    ConnectRes stub[0:24]: %s", resp[80:104].hex())
        return True

    def step_prm_end(self) -> bool:
        """
        IODControlReq PrmEnd — opnum 2, ControlCommand = 0x0008.

        Fixes G (opnum was 4), H (ControlCommand was 1), I (missing padding).
        """
        log.info("── PrmEnd (opnum=%d, ControlCommand=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_PRM_END, self.seq_num)
        stub = build_control_stub(self.ar_uuid, CTRL_PRM_END)
        resp = self._xact(self._req(OP_CONTROL, stub), "PrmEnd")
        if resp is None:
            return False
        if resp[1] != PKT_RESPONSE:
            log.error("PrmEnd: unexpected pkt_type 0x%02x", resp[1])
            return False
        log.info("    PrmEndRes received — device processing parameters")
        return True

    def step_application_ready(self) -> bool:
        """
        IODControlReq ApplicationReady — opnum 2, ControlCommand = 0x0010.

        Fixes J (opnum was 4), K (ControlCommand was 2), I (missing padding).
        """
        log.info("── ApplicationReady (opnum=%d, ControlCommand=0x%04x, seq=%d) ──",
                 OP_CONTROL, CTRL_APP_READY, self.seq_num)
        stub = build_control_stub(self.ar_uuid, CTRL_APP_READY)
        resp = self._xact(self._req(OP_CONTROL, stub), "ApplicationReady")
        if resp is None:
            return False
        if resp[1] != PKT_RESPONSE:
            log.error("ApplicationReady: unexpected pkt_type 0x%02x", resp[1])
            return False
        log.info("    ApplicationReadyRes received — IO data exchange active!")
        return True

    # ── Acyclic services ─────────────────────────────────────────────────────

    def acyclic_read(self,
                     slot: int = 1,
                     subslot: int = 0x8000,
                     index: int = 0x0000,
                     max_len: int = 0x8000) -> Optional[bytes]:
        """
        IODReadReq — opnum 3.

        Example indices:
          0x0000  Submodule real identification
          0x8028  PDPortDataReal (port diagnostics)
          0xB081  Diagnosis data
          0xF830  I&M 0 (module identity, hardware version, etc.)
        """
        log.info("── Acyclic Read  slot=%d sub=0x%04x idx=0x%04x ──",
                 slot, subslot, index)
        stub = build_read_stub(self.ar_uuid, slot, subslot, index, max_len)
        resp = self._xact(self._req(OP_READ, stub), "Read", timeout=5.0)
        if resp is None:
            return None
        if resp[1] != PKT_RESPONSE:
            log.error("Read: unexpected pkt_type 0x%02x", resp[1])
            return None
        # IODReadRes stub starts at offset 80
        # Layout: SeqNum(2) Pad(2) ARUUID(16) API(4) Slot(2) Sub(2)
        #          Pad(2) Index(2) RecordDataLen(4) ... then data
        if len(resp) < 80 + 36:
            log.warning("Read response too short (%d B)", len(resp))
            return resp[80:]
        rec_len = struct.unpack_from(">I", resp, 80 + 32)[0]
        data_start = 80 + 36 + 20  # header + TargetARUUID(16) + reserved(20) = 36+20=56? 
        # Simpler: return everything after the fixed 80+4+2+2+16+4+2+2+2+2+4 header
        data_off = 80 + 2 + 2 + 16 + 4 + 2 + 2 + 2 + 2 + 4
        record = resp[data_off: data_off + rec_len]
        log.info("    Read returned %d bytes", len(record))
        log.debug("    data: %s", record[:32].hex())
        return record

    def acyclic_write(self,
                      data: bytes,
                      slot: int = 1,
                      subslot: int = 0x8000,
                      index: int = 0x0000) -> bool:
        """
        IODWriteReq — opnum 4.

        Example: write output process data via acyclic record index 0x0000.
        For most motor relay output control, use cyclic output data instead.
        """
        log.info("── Acyclic Write  slot=%d sub=0x%04x idx=0x%04x  len=%d ──",
                 slot, subslot, index, len(data))
        stub = build_write_stub(self.ar_uuid, slot, subslot, index, data)
        resp = self._xact(self._req(OP_WRITE, stub), "Write", timeout=5.0)
        if resp is None:
            return False
        if resp[1] != PKT_RESPONSE:
            log.error("Write: unexpected pkt_type 0x%02x", resp[1])
            return False
        log.info("    WriteRes OK")
        return True

    # ── Cyclic exchange ──────────────────────────────────────────────────────

    def set_output(self, data: bytes):
        """Thread-safe update of the output data sent in cyclic frames."""
        assert len(data) == self.out_len, \
            f"output must be {self.out_len} bytes, got {len(data)}"
        with self._output_lock:
            self._output_data = bytes(data)

    def _tx_loop(self, stop: threading.Event):
        """
        Background thread: transmit output RT frames at ~32ms intervals.

        BUG L FIX: frame_id = FRAME_ID_OUT (0x8001), was 0x8002
        BUG M FIX: exact frame structure, no phantom 30-byte padding
        """
        cycle = 0
        log.debug("Cyclic TX thread started  iface=%s", SCAPY_IFACE)
        while not stop.is_set():
            cycle = (cycle + 1) & 0xFFFF
            with self._output_lock:
                out_data = self._output_data

            frame = build_output_rt_frame(out_data, cycle, self.ctrl_mac, self.target_mac)
            try:
                sendp(frame, iface=SCAPY_IFACE, verbose=False)
            except Exception as exc:
                log.warning("TX error: %s", exc)
            stop.wait(0.032)   # 32ms cycle

    def read_cyclic_data(self, duration_s: float = CYCLIC_DURATION_S):
        """
        Main cyclic loop:
          1. Start TX thread (output frames to device)
          2. Sniff input frames from device (Scapy BPF filter)
          3. Decode and log TeSys Tera measurements
          4. Stop TX thread cleanly
        """
        log.info("══ Cyclic exchange  duration=%.0fs ══", duration_s)
        if not SCAPY_OK:
            log.error("scapy not available — cannot run cyclic layer")
            return

        stop_tx = threading.Event()
        tx_thr  = threading.Thread(target=self._tx_loop, args=(stop_tx,), daemon=True)
        tx_thr.start()

        bpf = f"ether src {self.target_mac}"
        log.info("Sniffing on '%s'  filter='%s'", SCAPY_IFACE, bpf)

        try:
            frames = sniff(iface=SCAPY_IFACE, filter=bpf, timeout=duration_s)
        except Exception as exc:
            log.error("Scapy sniff error: %s", exc)
            log.error("Check SCAPY_IFACE constant matches your NPF adapter GUID.")
            frames = []
        finally:
            stop_tx.set()
            tx_thr.join(timeout=2.0)

        count = 0
        for frm in frames:
            raw = bytes(frm)
            inp = parse_input_rt_frame(raw, self.in_len)
            if inp is None:
                continue
            count += 1
            decoded = decode_tesys_input(inp)
            log.info("  [%4d] V=%.1fV  I=%.1f%%FLC  "
                     "state=0x%02x  trip=0x%02x  thermal=%d  "
                     "sw1=0x%04x  sw2=0x%04x  P=%.3fkW",
                     count,
                     decoded.get("voltage_v", 0),
                     decoded.get("current_pct_flc", 0),
                     decoded.get("motor_state", 0),
                     decoded.get("last_trip_cause", 0),
                     decoded.get("thermal_state", 0),
                     decoded.get("status_word_1", 0),
                     decoded.get("status_word_2", 0),
                     decoded.get("power_kw", 0),
                     )

        log.info("Cyclic exchange complete — %d valid input frames received", count)
        if count == 0:
            log.warning("No input frames seen.  Check:")
            log.warning("  1. SCAPY_IFACE GUID matches the NIC with IP %s", self.ctrl_ip)
            log.warning("  2. Wireshark confirms device is sending frames with "
                        "FrameID=0x%04x from %s", FRAME_ID_IN, self.target_mac)
            log.warning("  3. Output IOCR (FrameID=0x%04x) frames are reaching the device",
                        FRAME_ID_OUT)

    # ── Main run sequence ────────────────────────────────────────────────────

    def run(self):
        """
        Execute the full AR establishment sequence then cyclic exchange.

        BUG O FIX: BIND is skipped entirely.
          - DCE/RPC v4 CL protocol does not require a BIND handshake.
          - BIND would consume seq_num=0, causing the device to reject
            AR Connect (seq=1) with nca_wrong_boot_time (ghost AR lock).
          - seq_num=0 is reserved for the first real operation = Connect.
        """
        self._open()
        try:
            # seq=0  Connect
            if not self.step_ar_connect():
                log.error("AR Connect failed — aborting.  Device may need power-cycle.")
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

            # Optional: read I&M0 identity record (slot 0, subslot 1, index 0xF830)
            log.info("Reading I&M0 identity record…")
            im0 = self.acyclic_read(slot=0, subslot=1, index=0xF830)
            if im0 and len(im0) >= 10:
                vendor_id = struct.unpack_from(">H", im0, 0)[0]
                order_id  = im0[2:22].decode("ascii", errors="replace").strip()
                log.info("    VendorID=0x%04x  OrderID=%s", vendor_id, order_id)

            # Cyclic exchange (runs for CYCLIC_DURATION_S seconds)
            self.read_cyclic_data()

        finally:
            self._close()
            log.info("Socket closed — done.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Self-tests — run before touching real hardware
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def run_self_tests():
    """Validate packet structures without sending anything."""
    import traceback
    failures = []

    def check(name, expr, expected=True, msg=""):
        if expr != expected:
            failures.append(f"FAIL [{name}] {msg}")
            log.error("FAIL [%s] %s", name, msg)
        else:
            log.info("PASS [%s]", name)

    ar_uuid  = uuid.UUID("12345678-1234-5678-1234-567812345678")
    act_uuid = uuid.uuid4()

    # ── CL-PDU header ──────────────────────────────────────────────────────
    pkt = build_request(0, OP_CONNECT, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'')
    check("hdr.rpc_vers",      pkt[0] == 4,    msg=f"byte[0]={pkt[0]}")
    check("hdr.pkt_type",      pkt[1] == PKT_REQUEST, msg=f"byte[1]={pkt[1]:02x}")
    check("hdr.flags_obj",     bool(pkt[2] & PFC_OBJECT_UUID), msg=f"flags={pkt[2]:02x}")
    check("hdr.flags2",        pkt[3] == 0,    msg=f"byte[3]={pkt[3]}")
    check("hdr.drep[0]",       pkt[4] == 0x10, msg=f"drep={pkt[4:7].hex()}")

    obj_r = _pu(pkt, 8)
    check("hdr.obj_uuid",      obj_r == PNIO_CM_OBJ_UUID,
          msg=f"got {obj_r}")

    if_r  = _pu(pkt, 24)
    check("hdr.if_uuid",       if_r == PNIO_CM_IF_UUID, msg=f"got {if_r}")

    if_ver = struct.unpack_from("<I", pkt, 60)[0]
    check("hdr.if_version",    if_ver == 0x00010000,    # FIX A
          msg=f"got 0x{if_ver:08x}")

    opnum = struct.unpack_from("<H", pkt, 68)[0]
    check("hdr.opnum_connect", opnum == OP_CONNECT, msg=f"got {opnum}")

    for op, label in [(OP_CONTROL, "control"), (OP_READ, "read"), (OP_WRITE, "write")]:
        p2 = build_request(1, op, PNIO_CM_OBJ_UUID, PNIO_CM_IF_UUID, act_uuid, b'')
        got_op = struct.unpack_from("<H", p2, 68)[0]
        check(f"hdr.opnum_{label}", got_op == op, msg=f"got {got_op}")

    # ── ARBlock ────────────────────────────────────────────────────────────
    ar = build_ar_block(ar_uuid, "18:3d:2d:61:f9:70", CONTROLLER_IP, STATION_NAME)
    check("ar.block_type",     struct.unpack_from(">H", ar, 0)[0] == BT_AR_REQ)
    props_off = 6 + 2 + 16 + 2 + 6 + 16
    props = struct.unpack_from(">I", ar, props_off)[0]
    check("ar.ar_properties",  props == 0x00000000, msg=f"got 0x{props:08x}")  # FIX C
    to_off = props_off + 4
    timeout_f = struct.unpack_from(">H", ar, to_off)[0]
    check("ar.timeout_factor", timeout_f == 0x0064, msg=f"got 0x{timeout_f:04x}")  # FIX D
    cm_init_obj = _pu(ar, 6 + 2 + 16 + 2 + 6)
    check("ar.cm_init_obj_uuid", cm_init_obj == PNIO_CTRL_OBJ_UUID,
          msg=f"got {cm_init_obj}")  # FIX E

    # ── IOCRBlock ──────────────────────────────────────────────────────────
    spec = IOCRSpec(IOCR_INPUT, 1, FRAME_ID_IN, INPUT_LEN + 1)
    iocr = build_iocr_block(spec)
    lt_off = 6 + 2 + 2   # blockenv(6) + IOCRType(2) + IOCRRef(2)
    lt_val = struct.unpack_from(">H", iocr, lt_off)[0]
    check("iocr.lt_2bytes",    lt_val == PROFINET_ETYPE,
          msg=f"got 0x{lt_val:04x}")  # FIX F
    dl_off = lt_off + 2 + 4   # LT(2) + IOCRProps(4)
    dl_val = struct.unpack_from(">H", iocr, dl_off)[0]
    check("iocr.data_len",     dl_val == INPUT_LEN + 1,
          msg=f"got {dl_val}")  # verifies no byte-shift from old 4-byte LT

    # ── Control stubs ──────────────────────────────────────────────────────
    for cmd, label in [(CTRL_PRM_END, "prm_end"), (CTRL_APP_READY, "app_ready")]:
        stub = build_control_stub(ar_uuid, cmd)
        bt   = struct.unpack_from(">H", stub, 0)[0]
        check(f"ctrl.{label}.block_type", bt == BT_IOCTRL_REQ,
              msg=f"got 0x{bt:04x}")
        # After type(2)+len(2)+ver(2)+pad(2) = offset 8 → ARUUID
        recovered_ar = _pu(stub, 8)     # type2+len2+ver2+pad2 = 8
        check(f"ctrl.{label}.ar_uuid", recovered_ar == ar_uuid,
              msg=f"got {recovered_ar}")    # FIX I: padding present, ARUUID at right offset
        ctrl_cmd_off = 8 + 16 + 2 + 2  # header(8) + ARUUID(16) + SessionKey(2) + pad(2)
        ctrl_cmd = struct.unpack_from(">H", stub, ctrl_cmd_off)[0]
        check(f"ctrl.{label}.command",   ctrl_cmd == cmd,
              msg=f"got 0x{ctrl_cmd:04x}")  # FIX H / FIX K

    # ── RT frame structure ─────────────────────────────────────────────────
    out_data = b'\xDE\xAD\xBE\xEF'
    rt_raw   = build_output_rt_frame(out_data, 42, CONTROLLER_MAC, TARGET_MAC)
    if SCAPY_OK:
        rt_bytes = bytes(rt_raw)
        # With VLAN tag: Ether(14) + 802.1Q(4) + PROFINET_ETYPE(2) hidden in Dot1Q
        # Scapy puts etype in Dot1Q header; actual wire: dst(6)+src(6)+8100(2)+TCI(2)+etype(2)+payload
        # offset 18 = after Ether(14) + Dot1Q tag(4, includes 0x8892 etype already encoded)
        # Actually Scapy encodes: dst(6)+src(6)+8100(2)+TCI(2)+8892(2)+payload
        # So PROFINET payload starts at offset 18 (after 14+4=18 bytes of headers)
        # But Scapy's Dot1Q nests the type so the Raw payload starts after the Dot1Q header
        # Let's find FrameID in the raw bytes
        # Ethernet (14B) + VLAN (4B) = 18B, then payload starts
        fid_off = 18   # Ether(14) + Dot1Q(4)
        if len(rt_bytes) > fid_off + 2:
            fid = struct.unpack_from(">H", rt_bytes, fid_off)[0]
            check("rt.frame_id",  fid == FRAME_ID_OUT,
                  msg=f"got 0x{fid:04x}")  # FIX L
            # After FrameID(2): output data, then IOPS
            # Check output data
            rt_data = rt_bytes[fid_off+2: fid_off+2+OUTPUT_LEN]
            check("rt.output_data", rt_data == out_data[:OUTPUT_LEN],
                  msg=f"got {rt_data.hex()}")
            # Check IOPS
            iops = rt_bytes[fid_off+2+OUTPUT_LEN]
            check("rt.iops",  iops == 0x80, msg=f"got 0x{iops:02x}")  # FIX M
    else:
        log.info("SKIP [rt.*] — scapy not available")

    # ── Summary ────────────────────────────────────────────────────────────
    if failures:
        log.error("══ SELF-TEST FAILED ══")
        for f in failures:
            log.error("  %s", f)
        sys.exit(1)
    else:
        log.info("══ All self-tests passed ══")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    log.info("PROFINET IO Controller — TeSys Tera  (self-test then connect)")
    run_self_tests()

    ctrl = PNIOController()
    ctrl.run()


if __name__ == "__main__":
    main()
