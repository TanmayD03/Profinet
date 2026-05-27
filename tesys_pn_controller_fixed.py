#!/usr/bin/env python3
"""
PROFINET IO Controller for Schneider Electric TeSys Tera
=========================================================
Implements the full PROFINET AR establishment sequence:
  1. EPM query (DCE/RPC v5, TCP port 135) to resolve Context Manager Object UUID
  2. AR Connect Request  (DCE/RPC v4, UDP port 34964)
  3. PrmEnd Request
  4. ApplicationReady Request
  5. Cyclic read loop (RT frame, Ethertype 0x8892)

Hardware constants come from DCP discovery:
  Target IP  : 192.168.0.61
  Target MAC : 88:01:f9:35:d9:a2
  Controller : 192.168.0.100
  Station    : tesys-tera-pn
  Vendor ID  : 0x1559   Device ID : 0x1503
  IO Interface UUID : dea00001-6c97-11d1-8271-00a02442df7d
  Module 1   : 40 bytes Input, 4 bytes Output

References
----------
IEC 61158-6-10 (PROFINET IO), MS-RPCE §2.2.2 (EPM), RFC 1833 (portmap)
"""

import socket
import struct
import uuid
import time
import logging
import threading
import sys
from scapy.all import sniff, sendp, Ether, Dot1Q, Raw
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("PNIO-Controller")

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------
TARGET_IP          = "192.168.0.61"
TARGET_MAC_STR     = "88:01:f9:35:d9:a2"
CONTROLLER_IP      = "192.168.0.100"
CONTROLLER_MAC_STR = "18:3d:2d:61:f9:70"   # fill in if doing raw RT frames

PROFINET_RT_ETHERTYPE = 0x8892
PNIO_DCEPORT_UDP      = 34964   # PROFINET context manager, DCE/RPC v4
EPM_TCP_PORT          = 135     # endpoint mapper, DCE/RPC v5

# ---------------------------------------------------------------------------
# Well-known UUIDs (IEC 61158 / Anybus)
# ---------------------------------------------------------------------------
# The PROFINET IO Context Manager *interface* UUID (fixed by the standard)
PNIO_CM_IF_UUID      = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d")
# The PROFINET IO Controller *interface* UUID (we advertise this to the device)
PNIO_CTRL_IF_UUID    = uuid.UUID("dea00002-6c97-11d1-8271-00a02442df7d")
# EPM interface UUID (fixed by DCE/RPC spec)
EPM_IF_UUID          = uuid.UUID("e1af8308-5d1f-11c9-91a4-08002b14a0fa")

# Transfer syntax (NDR, fixed)
NDR_SYNTAX_UUID      = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
NDR_SYNTAX_VERSION   = (2, 0)

# ---------------------------------------------------------------------------
# DCE/RPC packet type constants (§12.6.3.1 of DCE/RPC spec)
# ---------------------------------------------------------------------------
DCERPC_PKT_REQUEST   = 0x00
DCERPC_PKT_RESPONSE  = 0x02
DCERPC_PKT_FAULT     = 0x03
DCERPC_PKT_BIND      = 0x0B
DCERPC_PKT_BIND_ACK  = 0x0C
DCERPC_PKT_BIND_NACK = 0x0D

# PFC flags
PFC_FIRST_FRAG       = 0x01
PFC_LAST_FRAG        = 0x02
PFC_OBJECT_UUID      = 0x80   # Request PDU carries an Object UUID

# ---------------------------------------------------------------------------
# PROFINET AR / Block constants
# ---------------------------------------------------------------------------
AR_TYPE_IOCAR_SINGLE = 0x0001
AR_PROP_PULLMODULE   = 0x00000001

BLOCK_TYPE_AR_BLOCK_REQ          = 0x0101
BLOCK_TYPE_IOCR_BLOCK_REQ        = 0x0102
BLOCK_TYPE_EXPECTED_SUBMOD_BLOCK = 0x0104
BLOCK_TYPE_ALARM_CR_BLOCK_REQ    = 0x0103
BLOCK_TYPE_PRMSRV_BLOCK_REQ      = 0x0115  # PrmServer (if needed)
BLOCK_TYPE_IOXS                  = 0x8001

IOCR_TYPE_INPUT  = 0x0001
IOCR_TYPE_OUTPUT = 0x0002

# ---------------------------------------------------------------------------
# Helper: UUID ↔ bytes (little-endian DCE/RPC wire format)
# ---------------------------------------------------------------------------
def uuid_to_le(u: uuid.UUID) -> bytes:
    """Pack a UUID into the 16-byte DCE/RPC little-endian wire format."""
    # uuid.bytes_le = fields 1-3 in LE, fields 4-5 in BE (correct for DCE wire)
    return u.bytes_le

def le_to_uuid(data: bytes, offset: int = 0) -> uuid.UUID:
    return uuid.UUID(bytes_le=data[offset:offset+16])

# ---------------------------------------------------------------------------
# Sequence-number + call-id state
# ---------------------------------------------------------------------------
_call_id = 0

def next_call_id() -> int:
    global _call_id
    _call_id += 1
    return _call_id

# ---------------------------------------------------------------------------
# DCE/RPC v5 helpers (used for EPM on TCP port 135)
# ---------------------------------------------------------------------------

def build_dcerpc_v5_bind(call_id: int,
                          if_uuid: uuid.UUID,
                          if_ver_major: int = 1,
                          if_ver_minor: int = 0) -> bytes:
    """
    Build a DCE/RPC v5 BIND PDU for EPM discovery.

    Header layout (little-endian):
      0  version_major    1B
      1  version_minor    1B   ← byte 1 is minor, not pkt_type!
      2  pkt_type         1B   = 0x0B (BIND)
      3  pfc_flags        1B
      4  data_rep         4B
      8  frag_len         2B
      10 auth_len         2B
      12 call_id          4B
      16 [bind body]
    """
    p_context_id = 0
    # Presentation context element
    ctx  = struct.pack("<H", p_context_id)          # p_context_elem.p_cont_id
    ctx += struct.pack("<H", 1)                      # n_transfer_syn
    ctx += struct.pack("<H", 0)                      # reserved
    ctx += uuid_to_le(if_uuid)                       # abstract syntax UUID
    ctx += struct.pack("<HH", if_ver_major, if_ver_minor)  # abstract syntax version
    ctx += uuid_to_le(NDR_SYNTAX_UUID)               # transfer syntax UUID
    ctx += struct.pack("<HH", *NDR_SYNTAX_VERSION)   # transfer syntax version

    bind_body  = struct.pack("<H", 4096)             # max_xmit_frag
    bind_body += struct.pack("<H", 4096)             # max_recv_frag
    bind_body += struct.pack("<I", 0)                # assoc_group_id
    bind_body += struct.pack("<B", 1)                # p_context_elem.n_context_items
    bind_body += struct.pack("<BBH", 0, 0, 0)        # reserved padding
    bind_body += ctx

    frag_len = 16 + len(bind_body)
    hdr  = struct.pack("<BB", 5, 0)                  # version 5.0
    hdr += struct.pack("<BB", DCERPC_PKT_BIND, PFC_FIRST_FRAG | PFC_LAST_FRAG)
    hdr += struct.pack("<BBBB", 0x10, 0x00, 0x00, 0x00)  # little-endian data rep
    hdr += struct.pack("<H", frag_len)
    hdr += struct.pack("<H", 0)                      # auth_len
    hdr += struct.pack("<I", call_id)
    return hdr + bind_body


def build_epm_lookup_request(call_id: int, object_uuid: Optional[uuid.UUID],
                              if_uuid: uuid.UUID) -> bytes:
    """
    Build an EPM Map (lookup) Request PDU (opnum 3) to resolve endpoints.

    EPM Map NDR body:
      object      (UUID, 16 B)
      map_tower   (twr_p_t pointer + twr_t)
      entry_handle (20 B, zero = fresh query)
      max_ents    (4 B)
    """
    # --- Tower floors for PNIO CM interface ---
    # Floor 1: RPC interface (UUID + version)
    fl1  = struct.pack("<H", 19)               # lhs_length  (UUID 16B + version 2B + prot 1B)
    fl1 += struct.pack("<B", 0x0D)             # protocol = UUID
    fl1 += uuid_to_le(if_uuid)
    fl1 += struct.pack("<H", 1)                # version major
    fl1 += struct.pack("<H", 2)                # rhs_length
    fl1 += struct.pack("<H", 0)                # minor version

    # Floor 2: Transfer syntax (NDR)
    fl2  = struct.pack("<H", 19)
    fl2 += struct.pack("<B", 0x0D)
    fl2 += uuid_to_le(NDR_SYNTAX_UUID)
    fl2 += struct.pack("<H", 2)
    fl2 += struct.pack("<H", 2)
    fl2 += struct.pack("<H", 0)

    # Floor 3: RPC over connection-oriented protocol (0x0B = CO TCP)
    fl3  = struct.pack("<H", 1)               # lhs: just protocol byte
    fl3 += struct.pack("<B", 0x0B)            # CO protocol
    fl3 += struct.pack("<H", 2)               # rhs: port number (2 bytes)
    fl3 += struct.pack(">H", 135)             # big-endian port

    # Floor 4: TCP/IP (protocol = 0x07)
    fl4  = struct.pack("<H", 1)
    fl4 += struct.pack("<B", 0x07)            # TCP
    fl4 += struct.pack("<H", 2)
    fl4 += struct.pack(">H", 0)              # any port

    # Floor 5: IP address (protocol = 0x09)
    fl5  = struct.pack("<H", 1)
    fl5 += struct.pack("<B", 0x09)            # IP
    fl5 += struct.pack("<H", 4)
    fl5 += socket.inet_aton(TARGET_IP)

    floors = fl1 + fl2 + fl3 + fl4 + fl5
    n_floors = 5
    # twr_t: num_floors (2B) + floors
    twr_t = struct.pack("<H", n_floors) + floors
    twr_len = len(twr_t)

    # NDR encoding of the tower pointer (conformant + varying)
    # pointer ref ID
    REF_ID = 0x00020000
    tower_ndr  = struct.pack("<I", REF_ID)      # referent ID
    tower_ndr += struct.pack("<I", twr_len)     # max_count (conformant)
    tower_ndr += twr_t
    # Align to 4 bytes
    pad = (4 - (twr_len % 4)) % 4
    tower_ndr += b'\x00' * pad

    # Object UUID (zero if none)
    obj_bytes = uuid_to_le(object_uuid) if object_uuid else b'\x00' * 16

    # entry_handle (20 bytes, zeroed → new query)
    entry_handle = b'\x00' * 20

    # max_ents
    max_ents = struct.pack("<I", 10)

    # Full NDR stub
    stub  = obj_bytes          # object UUID
    stub += tower_ndr          # tower pointer
    stub += entry_handle       # entry_handle
    stub += max_ents           # max_ents

    alloc_hint = len(stub)
    # DCE/RPC v5 Request header
    frag_len = 16 + 8 + alloc_hint      # hdr + request hdr + stub
    hdr  = struct.pack("<BB", 5, 0)
    hdr += struct.pack("<BB", DCERPC_PKT_REQUEST, PFC_FIRST_FRAG | PFC_LAST_FRAG)
    hdr += struct.pack("<BBBB", 0x10, 0x00, 0x00, 0x00)
    hdr += struct.pack("<H", frag_len)
    hdr += struct.pack("<H", 0)          # auth_len
    hdr += struct.pack("<I", call_id)
    # Request body header
    hdr += struct.pack("<I", alloc_hint)
    hdr += struct.pack("<H", 0)          # context id
    hdr += struct.pack("<H", 3)          # opnum = 3 (ept_map)
    return hdr + stub


def parse_epm_response(data: bytes) -> Optional[uuid.UUID]:
    """
    Parse EPM Map response, return the Object UUID of the first entry.
    Walks the NDR-encoded twr_entry array looking for a UUID floor.
    """
    # Locate the DCE/RPC response body (skip 16-byte common header + 8 request/response hdr)
    # v5 response has: hdr(16) + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1)
    if len(data) < 24:
        log.warning("EPM response too short (%d bytes)", len(data))
        return None

    pkt_type = data[2]
    if pkt_type == DCERPC_PKT_FAULT:
        fault_code = struct.unpack_from("<I", data, 16)[0] if len(data) >= 20 else 0
        log.error("EPM returned FAULT 0x%08x", fault_code)
        return None

    stub = data[24:]   # skip common + response common header
    if len(stub) < 4:
        return None

    # NDR: num_entries (4B) then array of twr_entry_t
    # twr_entry_t: object(16B) + twr_p_t (pointer) + annotation + pad
    # We take the simpler approach: scan for UUID floors in the raw stub
    # that match the PNIO_CM_IF_UUID pattern (first 4 bytes in LE)
    target_prefix = PNIO_CM_IF_UUID.bytes_le[:4]

    i = 0
    while i < len(stub) - 16:
        if stub[i:i+4] == target_prefix:
            candidate = le_to_uuid(stub, i)
            if candidate == PNIO_CM_IF_UUID:
                # The Object UUID of this entry is 16 bytes before the tower
                # in a twr_entry_t if aligned correctly — scan backwards
                # for the object field (which should NOT equal CM_IF_UUID)
                # Look at i-16 as the object UUID:
                if i >= 16:
                    obj = le_to_uuid(stub, i - 16)
                    if obj.int != 0 and obj != PNIO_CM_IF_UUID:
                        log.info("EPM resolved Object UUID: %s", obj)
                        return obj
        i += 1

    # Fallback: return first non-zero UUID found after offset 4
    log.warning("Could not extract Object UUID from EPM tower scan; trying raw UUID scan")
    for i in range(4, len(stub) - 16, 4):
        candidate = le_to_uuid(stub, i)
        if candidate.int != 0 and candidate != PNIO_CM_IF_UUID and \
           candidate != NDR_SYNTAX_UUID and candidate != EPM_IF_UUID:
            log.info("EPM fallback Object UUID: %s", candidate)
            return candidate
    return None


# ---------------------------------------------------------------------------
# EPM query over TCP
# ---------------------------------------------------------------------------

def query_epm(target_ip: str) -> Optional[uuid.UUID]:
    """
    Connect to EPM (port 135/TCP), bind, send ept_map, parse response.
    Returns the Object UUID to use in the PNIO AR Connect.
    """
    log.info("=== Step 1: EPM Query (TCP %s:135) ===", target_ip)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target_ip, EPM_TCP_PORT))
        log.debug("EPM TCP connected")

        cid = next_call_id()
        bind_pkt = build_dcerpc_v5_bind(cid, EPM_IF_UUID, if_ver_major=3, if_ver_minor=0)
        s.sendall(bind_pkt)
        log.debug("EPM BIND sent (%d bytes)", len(bind_pkt))

        resp = b""
        while len(resp) < 16:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        frag_len = struct.unpack_from("<H", resp, 8)[0] if len(resp) >= 10 else 0
        while len(resp) < frag_len:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk

        if resp[2] != DCERPC_PKT_BIND_ACK:
            log.error("EPM BIND did not get ACK (pkt_type=0x%02x)", resp[2])
            s.close()
            return None
        log.debug("EPM BIND_ACK received")

        cid = next_call_id()
        map_req = build_epm_lookup_request(cid, None, PNIO_CM_IF_UUID)
        s.sendall(map_req)
        log.debug("EPM Map Request sent (%d bytes)", len(map_req))

        resp2 = b""
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
                if len(resp2) >= 16:
                    frag_len = struct.unpack_from("<H", resp2, 8)[0]
                    if len(resp2) >= frag_len:
                        break
            except socket.timeout:
                break
        s.close()
        log.debug("EPM Map Response received (%d bytes)", len(resp2))

        obj_uuid = parse_epm_response(resp2)
        if obj_uuid:
            log.info("EPM resolved Object UUID => %s", obj_uuid)
        else:
            log.warning("EPM query yielded no UUID; will use zero-UUID fallback")
        return obj_uuid

    except Exception as exc:
        log.error("EPM query failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# DCE/RPC v4 helpers (PROFINET, UDP port 34964)
# ---------------------------------------------------------------------------

def build_dcerpc_v4_bind(call_id: int,
                          if_uuid: uuid.UUID,
                          obj_uuid: uuid.UUID) -> bytes:
    """
    DCE/RPC v4 BIND PDU for PROFINET.

    v4 header (big-endian for PROFINET):
      0  rpc_version      1B  = 4
      1  pkt_type         1B  ← byte 1 = packet type (not minor version!)
      2  pfc_flags        1B
      3  packed_drep      1B  (0x10 = little-endian data, big-endian integers)
      4  serial_hi        1B
      5  object_uuid      16B
      21 if_uuid          16B
      37 act_uuid         16B (activity UUID, random)
      53 server_boot      4B
      57 if_version       4B
      61 seqnum           4B
      65 opnum            2B
      67 ihint            2B
      69 ahint            2B
      71 frag_len         2B  (little-endian per PROFINET)
      73 frag_num         2B
      75 auth_proto       1B
      76 serial_lo        1B
    Total header = 80 bytes (including padding to align)

    PROFINET Context Manager BIND body is then the p_context list.
    """
    act_uuid = uuid.uuid4()
    serial = 1

    # Build body: presentation contexts
    # p_context_id=0, abstract=PNIO_CM_IF, transfer=NDR
    ctx_body  = struct.pack("<H", 1)                   # n_context_items
    ctx_body += struct.pack("<H", 0)                   # p_cont_id
    ctx_body += struct.pack("<H", 1)                   # n_transfer_syn
    ctx_body += struct.pack("<H", 0)                   # reserved
    ctx_body += uuid_to_le(if_uuid)                    # abstract syntax UUID
    ctx_body += struct.pack("<H", 1)                   # abstract version major
    ctx_body += struct.pack("<H", 0)                   # abstract version minor
    ctx_body += uuid_to_le(NDR_SYNTAX_UUID)            # transfer syntax UUID
    ctx_body += struct.pack("<HH", *NDR_SYNTAX_VERSION)

    bind_specific  = struct.pack("<H", 4096)           # max_xmit_frag
    bind_specific += struct.pack("<H", 4096)           # max_recv_frag
    bind_specific += struct.pack("<I", 0)              # assoc_group

    body = bind_specific + ctx_body
    frag_len = 80 + len(body)

    # CL-PDU header layout (DCE/RPC CL spec §12.6.3.1 — 80 bytes):
    #  0: rpc_vers    1B
    #  1: pkt_type    1B
    #  2: flags1      1B  (PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_OBJECT_UUID)
    #  3: flags2      1B  (always 0 for PROFINET)
    #  4: drep[0]     1B  (0x10 = little-endian integer, ASCII char)
    #  5: drep[1]     1B  (0x00 = IEEE float)
    #  6: drep[2]     1B  (0x00 reserved)
    #  7: serial_hi   1B
    #  8: object_uuid 16B
    # 24: if_uuid     16B
    # 40: act_uuid    16B
    # 56: server_boot  4B
    # 60: if_vers      4B
    # 64: seq_num      4B
    # 68: opnum        2B
    # 70: ihint        2B
    # 72: ahint        2B
    # 74: frag_len     2B  (little-endian per PROFINET convention)
    # 76: frag_num     2B
    # 78: auth_proto   1B
    # 79: serial_lo    1B
    hdr  = struct.pack(">B", 4)                                      # rpc_vers = 4
    hdr += struct.pack(">B", DCERPC_PKT_BIND)                        # pkt_type (byte 1)
    hdr += struct.pack(">B", PFC_FIRST_FRAG | PFC_LAST_FRAG)         # flags1
    hdr += struct.pack(">B", 0)                                      # flags2
    hdr += struct.pack(">BBB", 0x10, 0x00, 0x00)                     # drep[3]: LE integers
    hdr += struct.pack(">B", (serial >> 8) & 0xFF)                   # serial_hi
    hdr += uuid_to_le(obj_uuid)                                      # object UUID (16B)
    hdr += uuid_to_le(if_uuid)                                       # interface UUID (16B)
    hdr += uuid_to_le(act_uuid)                                      # activity UUID (16B)
    hdr += struct.pack(">I", 0)                                      # server_boot
    hdr += struct.pack(">I", 0x00010000)                             # if_version 1.0
    hdr += struct.pack(">I", call_id)                                # seq_num
    hdr += struct.pack(">H", 0)                                      # opnum = 0 (BIND)
    hdr += struct.pack(">H", 0xFFFF)                                 # ihint
    hdr += struct.pack(">H", 0xFFFF)                                 # ahint
    hdr += struct.pack("<H", frag_len)                               # frag_len (LE!)
    hdr += struct.pack(">H", 0)                                      # frag_num
    hdr += struct.pack(">B", 0)                                      # auth_proto
    hdr += struct.pack(">B", serial & 0xFF)                          # serial_lo
    assert len(hdr) == 80, f"v4 CL-PDU header must be 80 bytes, got {len(hdr)}"

    return hdr + body


def build_dcerpc_v4_request(call_id: int,
                              seq_num: int,
                              opnum: int,
                              obj_uuid: uuid.UUID,
                              if_uuid: uuid.UUID,
                              act_uuid: uuid.UUID,
                              stub: bytes) -> bytes:
    """
    DCE/RPC v4 Request PDU.
    """
    frag_len = 80 + len(stub)
    hdr  = struct.pack(">B", 4)                                      # rpc_vers = 4
    hdr += struct.pack(">B", DCERPC_PKT_REQUEST)                     # pkt_type = 0x00
    hdr += struct.pack(">B", PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_OBJECT_UUID)  # flags1
    hdr += struct.pack(">B", 0)                                      # flags2
    
    # PROFINET strictly uses Little Endian (0x10) for DCE/RPC headers
    hdr += struct.pack(">BBB", 0x10, 0x00, 0x00)                     # drep[3]
    hdr += struct.pack(">B", 0)                                      # serial_hi
    hdr += uuid_to_le(obj_uuid)                                      # Object UUID 
    hdr += uuid_to_le(if_uuid)                                       # Interface UUID
    hdr += uuid_to_le(act_uuid)                                      # Activity UUID
    
    # --- THE ENDIANNESS FIX ---
    # We MUST pack these integers as Little Endian (<I, <H) to match the drep flag.
    hdr += struct.pack("<I", 0)                                      # server_boot
    # FIX BUG 3: if_version encodes major.minor as a 32-bit LE integer.
    # Version 1.0 → major=1 (high 16 bits), minor=0 (low 16 bits) → 0x00010000.
    # Packing as LE: 00 00 01 00 on the wire. Previous code used value=1 which
    # gave 0x00000001 (= version 0.0.0.1), causing the device to reject the AR.
    hdr += struct.pack("<I", 0x00010000)                             # if_version = 1.0
    hdr += struct.pack("<I", seq_num)                                # sequence number
    hdr += struct.pack("<H", opnum)                                  # opnum  
    hdr += struct.pack("<H", 0xFFFF)                                 # ihint
    hdr += struct.pack("<H", 0xFFFF)                                 # ahint
    hdr += struct.pack("<H", frag_len)                               # frag_len
    hdr += struct.pack("<H", 0)                                      # frag_num
    hdr += struct.pack("B", 0)                                       # auth_proto
    hdr += struct.pack("B", 0)                                       # serial_lo
    
    assert len(hdr) == 80, f"v4 CL-PDU request header must be 80 bytes, got {len(hdr)}"
    return hdr + stub


# ---------------------------------------------------------------------------
# PROFINET block builders (IEC 61158-6-10)
# ---------------------------------------------------------------------------

@dataclass
class IOCRConfig:
    """Describes one IO Communication Relation (input or output)."""
    cr_type: int        # IOCR_TYPE_INPUT or IOCR_TYPE_OUTPUT
    cr_ref: int         # 1-based index
    frame_id: int       # e.g. 0x8000 for input, 0x8001 for output
    data_len: int       # payload bytes (includes 2B IOPS/IOCS overhead)
    api: int = 0
    slot: int = 1
    subslot: int = 0x8000


def build_ar_block(ar_uuid: uuid.UUID,
                   controller_mac: str,
                   controller_ip: str,
                   station_name: str) -> bytes:
    """ARBlockReq (block type 0x0101)."""
    mac = bytes(int(x, 16) for x in controller_mac.split(":"))
    ip  = socket.inet_aton(controller_ip)
    name_bytes = station_name.encode("ascii")
    name_len   = len(name_bytes)

    body  = struct.pack(">H", AR_TYPE_IOCAR_SINGLE)  # ARType
    body += uuid_to_le(ar_uuid)                       # ARUUID (LE per PNIO)
    body += struct.pack(">H", 0x0100)                 # SessionKey
    body += mac                                        # CMInitiatorMACAdd
    body += uuid_to_le(PNIO_CM_IF_UUID)               # CMInitiatorObjectUUID
    # FIX BUG 5: ARProperties = 0x00000000 for a standard IO-Controller AR.
    # The previous value 0x00000001 set the PullModuleAlarmsEnabled bit, which
    # is only valid in pull-module / shared-device scenarios. On a standard
    # TeSys Tera single-AR connection this causes the device to reject the request.
    body += struct.pack(">I", 0x00000000)      # ARProperties
    # FIX BUG 4: CMInitiatorActivityTimeoutFactor must be a watchdog timeout in
    # units of 100ms. The previous value was 0x8892 (= 34962 = the PROFINET
    # ethertype!), which is 3496 seconds — absurd and rejected by the device.
    # 0x0064 = 100 × 100ms = 10-second CM watchdog (standard default).
    body += struct.pack(">H", 0x0064)          # CMInitiatorActivityTimeoutFactor
    body += struct.pack(">H", PNIO_DCEPORT_UDP) # CMInitiatorUDPRTPort = 34964
    body += struct.pack(">H", name_len)               # StationNameLength
    body += name_bytes
    # Pad to even
    if name_len % 2:
        body += b'\x00'

    block_len = 2 + len(body)  # block_len field does NOT count type and length fields themselves (4B)
    return struct.pack(">HH", BLOCK_TYPE_AR_BLOCK_REQ, block_len) + \
           struct.pack(">BB", 1, 0) + body   # version 1.0


def build_iocr_block(cr: IOCRConfig, ar_uuid: uuid.UUID) -> bytes:
    """IOCRBlockReq (block type 0x0102)."""
    # API entry: one API with one slot/subslot
    api_entry  = struct.pack(">I", cr.api)      # API
    api_entry += struct.pack(">H", 1)           # NumberOfIODataObjects
    api_entry += struct.pack(">H", 0)           # NumberOfIOCS

    io_data_obj  = struct.pack(">H", cr.slot)
    io_data_obj += struct.pack(">H", cr.subslot)
    io_data_obj += struct.pack(">H", 0)         # FrameOffset

    n_api = 1
    body  = struct.pack(">H", cr.cr_type)       # IOCRType
    body += struct.pack(">H", cr.cr_ref)        # IOCRReference
    # FIX BUG 6: LT (Link-layer Type / Ethertype) is 2 bytes, not 4.
    # IEC 61158-6-10 §6.2.12: LT is a UINT16. Previous code used '>I' (4 bytes)
    # which ate 2 bytes from the IOCRProperties field, corrupting every
    # subsequent field in the block (DataLength, FrameID, clocks, etc.).
    body += struct.pack(">H", 0x8892)           # LT = PROFINET ethertype (2 B)
    body += struct.pack(">I", 0x00000000)       # IOCRProperties
    body += struct.pack(">H", cr.data_len)      # DataLength
    body += struct.pack(">H", cr.frame_id)      # FrameID
    body += struct.pack(">H", 32)               # SendClockFactor (1ms)
    body += struct.pack(">H", 32)               # ReductionRatio  (32 ms)
    body += struct.pack(">H", 0)                # Phase
    body += struct.pack(">H", 0)                # Sequence
    body += struct.pack(">I", 0)                # FrameSendOffset
    body += struct.pack(">H", 0x0000)           # WatchdogFactor
    body += struct.pack(">H", 0x0000)           # DataHoldFactor
    body += struct.pack(">H", cr.frame_id)      # IOCRTagHeader
    body += b'\xff\xff\xff\xff\xff\xff'          # IOCRMulticastMACAdd (broadcast)
    body += struct.pack(">H", n_api)            # NumberOfAPIs
    body += api_entry
    body += io_data_obj

    block_len = 2 + len(body)
    return struct.pack(">HH", BLOCK_TYPE_IOCR_BLOCK_REQ, block_len) + \
           struct.pack(">BB", 1, 0) + body


def build_expected_submodule_block(input_len: int, output_len: int) -> bytes:
    """ExpectedSubmoduleBlockReq (block type 0x0104)."""
    # API=0, Slot=1, Module=TeSys Tera module, Subslot=0x8000
    sub_body  = struct.pack(">H", 1)            # Slot number
    sub_body += struct.pack(">I", 0x00001503)   # ModuleIdentNumber (Device ID)
    sub_body += struct.pack(">H", 0x0000)       # ModuleProperties
    sub_body += struct.pack(">H", 1)            # NumberOfSubmodules
    # Submodule
    sub_body += struct.pack(">H", 0x8000)       # SubslotNumber
    sub_body += struct.pack(">I", 0x00000001)   # SubmoduleIdentNumber
    sub_body += struct.pack(">H", 0x0000)       # SubmoduleProperties
    # Input data description
    sub_body += struct.pack(">H", 0x0001)       # SubmoduleDataDescription - INPUT
    sub_body += struct.pack(">H", input_len)    # SubmoduleDataLength (input bytes)
    sub_body += struct.pack(">B", 1)            # LengthIOCS
    sub_body += struct.pack(">B", 1)            # LengthIOPS

    api_block  = struct.pack(">I", 0)           # API = 0
    api_block += struct.pack(">H", 1)           # NumberOfModules
    api_block += sub_body

    body  = struct.pack(">H", 1)                # NumberOfAPIs
    body += api_block

    block_len = 2 + len(body)
    return struct.pack(">HH", BLOCK_TYPE_EXPECTED_SUBMOD_BLOCK, block_len) + \
           struct.pack(">BB", 1, 0) + body


def build_alarm_cr_block() -> bytes:
    """AlarmCRBlockReq (block type 0x0103) - minimal."""
    body  = struct.pack(">H", 0x0001)           # AlarmCRType = ALARM_CR
    body += struct.pack(">H", 0x8892)           # LT
    body += struct.pack(">I", 0x00000000)       # AlarmCRProperties
    body += struct.pack(">H", 200)              # RTATimeoutFactor (200 ms)
    body += struct.pack(">H", 3)                # RTARetries
    body += struct.pack(">H", 1)                # LocalAlarmReference
    body += struct.pack(">H", 200)              # MaxAlarmDataLength
    body += struct.pack(">H", 0x0000)           # AlarmCRTagHeaderHigh
    body += struct.pack(">H", 0x0000)           # AlarmCRTagHeaderLow

    block_len = 2 + len(body)
    return struct.pack(">HH", BLOCK_TYPE_ALARM_CR_BLOCK_REQ, block_len) + \
           struct.pack(">BB", 1, 0) + body


# ---------------------------------------------------------------------------
# AR Connect Request NDR stub
# ---------------------------------------------------------------------------

# def build_ar_connect_stub(ar_uuid: uuid.UUID,
#                            controller_mac: str,
#                            controller_ip: str,
#                            station_name: str,
#                            input_len: int,
#                            output_len: int) -> bytes:
#     """
#     Build the full NDR stub for the PNIO CM Connect RPC call (opnum 0).
#     """
#     ar_block   = build_ar_block(ar_uuid, controller_mac, controller_ip, station_name)
#     # Input IOCR
#     in_cr  = IOCRConfig(IOCR_TYPE_INPUT,  1, 0x8000, input_len + 2)
#     out_cr = IOCRConfig(IOCR_TYPE_OUTPUT, 2, 0x8001, output_len + 2)
#     iocr_in    = build_iocr_block(in_cr,  ar_uuid)
#     iocr_out   = build_iocr_block(out_cr, ar_uuid)
#     esm_block  = build_expected_submodule_block(input_len, output_len)
#     alarm_block= build_alarm_cr_block()

#     blocks = ar_block + iocr_in + iocr_out + esm_block + alarm_block

#     # NDR stub: 4-byte args_length + blocks
#     stub = struct.pack(">I", len(blocks)) + blocks
#     return stub
def build_ar_connect_stub(ar_uuid: uuid.UUID,
                           controller_mac: str,
                           controller_ip: str,
                           station_name: str,
                           input_len: int,
                           output_len: int) -> bytes:
    ar_block   = build_ar_block(ar_uuid, controller_mac, controller_ip, station_name)
    in_cr  = IOCRConfig(IOCR_TYPE_INPUT,  1, 0x8000, input_len + 2)
    out_cr = IOCRConfig(IOCR_TYPE_OUTPUT, 2, 0x8001, output_len + 2)
    iocr_in    = build_iocr_block(in_cr,  ar_uuid)
    iocr_out   = build_iocr_block(out_cr, ar_uuid)
    esm_block  = build_expected_submodule_block(input_len, output_len)
    alarm_block= build_alarm_cr_block()

    # THE FIX: Remove the 4-byte length prefix. PROFINET NDR doesn't use it here!
    return ar_block + iocr_in + iocr_out + esm_block + alarm_block

# ---------------------------------------------------------------------------
# PROFINET AR state machine
# ---------------------------------------------------------------------------

class PNIOController:
    def __init__(self,
                 target_ip: str,
                 target_mac: str,
                 controller_ip: str,
                 controller_mac: str,
                 station_name: str,
                 obj_uuid: Optional[uuid.UUID],
                 input_len: int = 40,
                 output_len: int = 4):
        self.target_ip       = target_ip
        self.target_mac      = target_mac
        self.controller_ip   = controller_ip
        self.controller_mac  = controller_mac
        self.station_name    = station_name
        self.obj_uuid        = obj_uuid or uuid.UUID(int=0)
        self.input_len       = input_len
        self.output_len      = output_len

        self.ar_uuid         = uuid.uuid4()
        self.act_uuid        = uuid.uuid4()
        self.seq_num         = 0
        self.sock: Optional[socket.socket] = None

        log.info("AR UUID     : %s", self.ar_uuid)
        log.info("Activity    : %s", self.act_uuid)
        log.info("Object UUID : %s", self.obj_uuid)

    # ------------------------------------------------------------------
    def _open_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # FIX BUG 2: Must bind to port 34964 (not 0/ephemeral).
        # IEC 61784-2 §8.3: the CM Controller MUST use UDP port 34964 as its
        # source port. PROFINET devices check the source port and silently drop
        # any packet that doesn't arrive from 34964 — no DCE/RPC Fault is
        # generated, so you just get a timeout.
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.controller_ip, PNIO_DCEPORT_UDP))
        self.sock.settimeout(3)
        log.debug("UDP socket bound to %s:%d", self.controller_ip, PNIO_DCEPORT_UDP)

    def _send_recv(self, pkt: bytes, label: str) -> Optional[bytes]:
        log.debug(">>> %s (%d bytes)", label, len(pkt))
        log.debug("    hex: %s", pkt[:80].hex())
        self.sock.sendto(pkt, (self.target_ip, PNIO_DCEPORT_UDP))
        try:
            resp, addr = self.sock.recvfrom(65535)
            pkt_type = resp[1] if len(resp) > 1 else 0xFF
            log.debug("<<< %s response (%d bytes) from %s pkt_type=0x%02x",
                      label, len(resp), addr, pkt_type)
            if pkt_type == DCERPC_PKT_FAULT:
                fault = struct.unpack_from(">I", resp, 80)[0] if len(resp) >= 84 else 0
                log.error("    FAULT code: 0x%08x", fault)
                self._decode_fault(fault)
            return resp
        except socket.timeout:
            log.error("    TIMEOUT waiting for %s response", label)
            return None

    @staticmethod
    def _decode_fault(code: int):
        faults = {
            0x1c010003: "nca_unk_if      — Object UUID not registered (wrong Object UUID)",
            0x1c010002: "nca_op_rng_error — opnum out of range for this interface",
            0x1c000009: "nca_s_fault_ill_inst — illegal instruction (malformed stub)",
            0x1c000008: "nca_s_fault_cancel — operation cancelled",
            0x1c010001: "nca_s_unsupported_type — unsupported transfer syntax",
        }
        desc = faults.get(code, "unknown fault")
        log.error("    Fault meaning: %s", desc)

    # ------------------------------------------------------------------
    def _next_seq(self) -> int:
        s = self.seq_num
        self.seq_num += 1
        return s

    # ------------------------------------------------------------------
    def step_bind(self) -> bool:
        log.info("=== Step 2a: DCE/RPC v4 BIND ===")
        pkt = build_dcerpc_v4_bind(self._next_seq(),
                                    PNIO_CM_IF_UUID, self.obj_uuid)
        resp = self._send_recv(pkt, "BIND")
        if resp is None:
            return False
        pkt_type = resp[1]
        if pkt_type == DCERPC_PKT_BIND_ACK:
            log.info("    BIND_ACK received — negotiation OK")
            return True
        elif pkt_type == DCERPC_PKT_BIND_NACK:
            reason = struct.unpack_from(">H", resp, 80)[0] if len(resp) > 80 else -1
            log.error("    BIND_NACK, reject reason = %d", reason)
            return False
        log.error("    Unexpected response pkt_type=0x%02x", pkt_type)
        return False

    # ------------------------------------------------------------------
    def step_ar_connect(self) -> bool:
        log.info("=== Step 2b: AR Connect Request (opnum 0) ===")
        stub = build_ar_connect_stub(
            self.ar_uuid,
            self.controller_mac,
            self.controller_ip,
            self.station_name,
            self.input_len,
            self.output_len,
        )
        pkt = build_dcerpc_v4_request(
            call_id  = next_call_id(),
            seq_num  = self._next_seq(),     # must be AFTER bind seq
            opnum    = 0,                    # Connect = opnum 0
            obj_uuid = self.obj_uuid,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
        )
        resp = self._send_recv(pkt, "AR Connect")
        if resp is None:
            return False
        if resp[1] == DCERPC_PKT_RESPONSE:
            log.info("    AR Connect Response received — AR established!")
            # Parse the PNIO error code from the response stub (offset 80+)
            if len(resp) > 84:
                pnio_status = struct.unpack_from(">I", resp, 80)[0]
                if pnio_status != 0:
                    log.warning("    PNIO status code in response: 0x%08x", pnio_status)
                else:
                    log.info("    PNIO status: OK (0x00000000)")
            return True
        if resp[1] == DCERPC_PKT_FAULT:
            # Fault already decoded in _send_recv; check if it's nca_unk_if
            if len(resp) >= 84:
                fault = struct.unpack_from("<I", resp, 80)[0]
                if fault == 0x1c010003:
                    log.error("    nca_unk_if: Object UUID %s not registered.", self.obj_uuid)
                    log.error("    If EPM failed, try running with obj_uuid=uuid.UUID(int=0)")
                    log.error("    or capture the EPM response with Wireshark to find the real UUID.")
        return False

    # ------------------------------------------------------------------
    # def step_prm_end(self) -> bool:
    #     log.info("=== Step 3: PrmEnd Request (opnum 1) ===")
    #     # PrmEnd stub: AR UUID + padding (minimal)
    #     stub  = uuid_to_le(self.ar_uuid)
    #     stub += struct.pack(">H", 1)    # ARUUID valid
    #     stub += struct.pack(">H", 0)    # reserved

    #     pkt = build_dcerpc_v4_request(
    #         call_id  = next_call_id(),
    #         seq_num  = self._next_seq(),
    #         opnum    = 1,               # PrmEnd = opnum 1
    #         obj_uuid = self.obj_uuid,
    #         if_uuid  = PNIO_CM_IF_UUID,
    #         act_uuid = self.act_uuid,
    #         stub     = stub,
    #     )
    #     resp = self._send_recv(pkt, "PrmEnd")
    #     if resp is None:
    #         return False
    #     if resp[1] == DCERPC_PKT_RESPONSE:
    #         log.info("    PrmEnd Response received")
    #         return True
    #     return False
    
    def step_prm_end(self) -> bool:
        log.info("=== Step 3: PrmEnd Request ===")
        # THE FIX: Proper PROFINET Control Block Header (0x0110) and Command (1)
        ctrl_data = uuid_to_le(self.ar_uuid) + struct.pack(">H H H H", 1, 0, 1, 0)
        stub = struct.pack(">H H B B", 0x0110, len(ctrl_data)+2, 1, 0) + ctrl_data

        pkt = build_dcerpc_v4_request(
            call_id  = next_call_id(),
            seq_num  = self._next_seq(),
            opnum    = 4,               # THE FIX: Control is OpNum 4
            obj_uuid = self.obj_uuid,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
        )
        resp = self._send_recv(pkt, "PrmEnd")
        if resp is None: return False
        if resp[1] == DCERPC_PKT_RESPONSE:
            log.info("    PrmEnd Response received")
            return True
        return False

    # ------------------------------------------------------------------
    # def step_application_ready(self) -> bool:
    #     log.info("=== Step 4: ApplicationReady Request (opnum 2) ===")
    #     # ApplicationReady stub: AR UUID
    #     stub  = uuid_to_le(self.ar_uuid)
    #     stub += struct.pack(">H", 1)    # ready
    #     stub += struct.pack(">H", 0)    # reserved

    #     pkt = build_dcerpc_v4_request(
    #         call_id  = next_call_id(),
    #         seq_num  = self._next_seq(),
    #         opnum    = 2,               # ApplicationReady = opnum 2
    #         obj_uuid = self.obj_uuid,
    #         if_uuid  = PNIO_CM_IF_UUID,
    #         act_uuid = self.act_uuid,
    #         stub     = stub,
    #     )
    #     resp = self._send_recv(pkt, "ApplicationReady")
    #     if resp is None:
    #         return False
    #     if resp[1] == DCERPC_PKT_RESPONSE:
    #         log.info("    ApplicationReady Response received — IO active!")
    #         return True
    #     return False

    def step_application_ready(self) -> bool:
        log.info("=== Step 4: ApplicationReady Request ===")
        # THE FIX: Proper PROFINET Control Block Header (0x0110) and Command (2)
        ctrl_data = uuid_to_le(self.ar_uuid) + struct.pack(">H H H H", 1, 0, 2, 0)
        stub = struct.pack(">H H B B", 0x0110, len(ctrl_data)+2, 1, 0) + ctrl_data

        pkt = build_dcerpc_v4_request(
            call_id  = next_call_id(),
            seq_num  = self._next_seq(),
            opnum    = 4,               # THE FIX: Control is OpNum 4
            obj_uuid = self.obj_uuid,
            if_uuid  = PNIO_CM_IF_UUID,
            act_uuid = self.act_uuid,
            stub     = stub,
        )
        resp = self._send_recv(pkt, "ApplicationReady")
        if resp is None: return False
        if resp[1] == DCERPC_PKT_RESPONSE:
            log.info("    ApplicationReady Response received — IO active!")
            return True
        return False
    
    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    def read_cyclic_data(self, duration_s: float = 10.0):
        log.info("=== Step 5: Cyclic Data Read & Transmit ===")
        
        # 1. Start the Master Cyclic Keep-Alive
        stop_tx = threading.Event()
        tx_thread = threading.Thread(target=self._cyclic_tx_loop, args=(stop_tx,))
        tx_thread.start()

        # 2. Sniff for the incoming measurements using Windows NPF
        IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"
        bpf_filter = f"ether src {self.target_mac}"
        
        try:
            captured = sniff(iface=IFACE, filter=bpf_filter, timeout=duration_s)
            count = 0
            for frame in captured:
                raw_bytes = bytes(frame)
                offset = 12
                # Account for VLAN tags
                if raw_bytes[12:14] == b"\x81\x00": 
                    offset += 4
                
                # Verify PROFINET Ethertype and Input Frame ID
                if raw_bytes[offset:offset+2] == b"\x88\x92":
                    fid = struct.unpack(">H", raw_bytes[offset+2 : offset+4])[0]
                    if fid == 0x8001:
                        payload = raw_bytes[offset+4 : offset+4+self.input_len]
                        count += 1
                        
                        # TeSys Tera Module 1 Decoding
                        volts = struct.unpack(">I", payload[24:28])[0] * 0.1
                        amps = struct.unpack(">I", payload[4:8])[0] * 0.1
                        log.info(f"  Live Reading -> Voltage: {volts:.1f} V | Current: {amps:.1f} %FLC")
                        
            log.info(f"Captured {count} valid PROFINET cyclic frames.")
        finally:
            # Cleanly shut down the transmitter before the release
            stop_tx.set()
            tx_thread.join(timeout=1.0)

    def _cyclic_tx_loop(self, stop_event):
        cyc = 1
        padding = b"\x00" * 30
        IFACE = r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"
        
        while not stop_event.is_set():
            cyc = (cyc + 1) % 65536
            # Flawless Output Data + IOPS + IOCS + Pad + CycleCounter + DataStatus
            pn_payload = struct.pack("!H", 0x8002) + b"\x00\x00\x00\x00" + b"\x80\x80" + padding + struct.pack("!H", cyc) + b"\x35\x00"
            
            pkt = Ether(dst=self.target_mac, src=self.controller_mac) / Dot1Q(vlan=0, prio=6, type=0x8892) / Raw(load=pn_payload)
            try:
                sendp(pkt, iface=IFACE, verbose=False)
            except Exception:
                pass
            time.sleep(0.032)

    # ------------------------------------------------------------------
    def run(self):
        self._open_socket()
        try:
            # We MUST skip the BIND phase completely so AR Connect gets seq_num = 0
            
            if not self.step_ar_connect():
                log.error("AR Connect failed — aborting")
                return
            time.sleep(0.1)

            if not self.step_prm_end():
                log.error("PrmEnd failed — aborting")
                return
            time.sleep(0.1)

            if not self.step_application_ready():
                log.error("ApplicationReady failed — aborting")
                return

            self.read_cyclic_data(duration_s=30.0)
        finally:
            if self.sock:
                self.sock.close()
    # def run(self):
    #     self._open_socket()
    #     try:
    #         # BIND step: negotiates the presentation context (interface UUID ↔ NDR
    #         # transfer syntax).  Some embedded stacks skip the BIND phase entirely
    #         # and accept a bare Request — we try BIND first and continue regardless.
    #         if not self.step_bind():
    #             log.warning("BIND got no ACK — device may not require BIND. Continuing...")
    #         time.sleep(0.1)

    #         if not self.step_ar_connect():
    #             # If we used the null UUID and got nca_unk_if or a timeout,
    #             # retry once with the Anybus well-known UUID before giving up.
    #             anybus_uuid = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
    #             if self.obj_uuid.int == 0:
    #                 log.warning("Null UUID failed — retrying with Anybus UUID %s", anybus_uuid)
    #                 self.obj_uuid  = anybus_uuid
    #                 self.ar_uuid   = uuid.uuid4()   # fresh AR UUID for retry
    #                 self.act_uuid  = uuid.uuid4()   # fresh activity UUID
    #                 self.seq_num   = 0              # reset sequence counter
    #                 if not self.step_ar_connect():
    #                     log.error("AR Connect failed with both null and Anybus UUIDs — aborting")
    #                     log.error("Run Wireshark on the device and filter: udp.port==34964")
    #                     log.error("Look for a working controller's BIND/Request to extract the Object UUID")
    #                     return
    #             else:
    #                 log.error("AR Connect failed — aborting")
    #                 return
    #         time.sleep(0.1)

    #         if not self.step_prm_end():
    #             log.error("PrmEnd failed — aborting")
    #             return
    #         time.sleep(0.1)

    #         if not self.step_application_ready():
    #             log.error("ApplicationReady failed — aborting")
    #             return

    #         self.read_cyclic_data(duration_s=30.0)
    #     finally:
    #         if self.sock:
    #             self.sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    log.info("PROFINET IO Controller for TeSys Tera — starting")
    log.info("Target : %s (%s)  Station : %s", TARGET_IP, TARGET_MAC_STR, "tesys-tera-pn")
    log.info("Controller : %s", CONTROLLER_IP)

    # We bypass EPM and the Null UUID completely. We strike directly 
    # with the proven Anybus Context Manager Object UUID.
    obj_uuid = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2")
    
    # ── Steps 2–5: AR establish + cyclic read ─────────────────────────
    ctrl = PNIOController(
        target_ip      = TARGET_IP,
        target_mac     = TARGET_MAC_STR,
        controller_ip  = CONTROLLER_IP,
        controller_mac = CONTROLLER_MAC_STR,
        station_name   = "tesys-tera-pn",
        obj_uuid       = obj_uuid,
        input_len      = 40,
        output_len     = 4,
    )
    ctrl.run()

# def main():
#     log.info("PROFINET IO Controller for TeSys Tera — starting")
#     log.info("Target : %s (%s)  Station : %s", TARGET_IP, TARGET_MAC_STR, "tesys-tera-pn")
#     log.info("Controller : %s", CONTROLLER_IP)

#     # ── Step 1: EPM query ──────────────────────────────────────────────
#     # FIX BUG 1: EPM was commented out and replaced with a hardcoded Anybus
#     # UUID (dea00000...) that TeSys Tera does not accept.  We now attempt EPM
#     # and fall through two well-known fallbacks if it fails.
#     #
#     # UUID resolution order:
#     #  1. EPM (TCP 135) — authoritative; some embedded stacks don't support it
#     #  2. Null UUID (all zeros) — accepted by many PROFINET devices as "any"
#     #  3. Anybus well-known UUID — last resort for HMS-based stacks
#     obj_uuid = query_epm(TARGET_IP)

#     if obj_uuid is None:
#         log.warning("EPM returned no UUID — falling back to null Object UUID.")
#         log.warning("Many PROFINET devices (including some TeSys Tera firmware")
#         log.warning("versions) accept the null UUID on the first AR Connect.")
#         obj_uuid = uuid.UUID(int=0)   # null UUID = accept any registered endpoint
    
#     # ── Steps 2–5: AR establish + cyclic read ─────────────────────────
#     ctrl = PNIOController(
#         target_ip      = TARGET_IP,
#         target_mac     = TARGET_MAC_STR,
#         controller_ip  = CONTROLLER_IP,
#         controller_mac = CONTROLLER_MAC_STR,
#         station_name   = "tesys-tera-pn",
#         obj_uuid       = obj_uuid,
#         input_len      = 40,
#         output_len     = 4,
#     )
#     ctrl.run()


if __name__ == "__main__":
    main()
