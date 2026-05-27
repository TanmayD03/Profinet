#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║          PROFINET Commander — Schneider Electric TeSys Tera         ║
║                    Single-file · python tesys_tera_profinet.py      ║
╚══════════════════════════════════════════════════════════════════════╝

One file. Zero configuration. Run and go.

  python tesys_tera_profinet.py

REQUIREMENTS (one-time setup)
──────────────────────────────
  1.  pip install scapy netifaces
  2.  Install Npcap from https://npcap.com
      → Run installer as Administrator once
      → Leave "Restrict to Admins only" UNCHECKED  (default)
      → After that, no admin needed for daily use

DEVICE
──────
  Schneider Electric TeSys Tera PROFINET
  Order refs: LTMTPNFM (AC) / LTMTPNBD (DC)
  VendorID = 0x0129   DeviceID = 0x0701
  Default station name: tesys-tera-pn
  Minimum cycle time: 16 ms  (hardware limit from GSDML)
"""

# ══════════════════════════════════════════════════════════════════════
# STDLIB IMPORTS
# ══════════════════════════════════════════════════════════════════════
import collections, ctypes, json, logging, os, platform, queue
import socket, struct, sys, threading, time, uuid, csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logging.disable(logging.CRITICAL)   # silence all library noise

# ══════════════════════════════════════════════════════════════════════
# PART 1 — PROFINET PROTOCOL CONSTANTS & PACKET BUILDERS
# ══════════════════════════════════════════════════════════════════════

_PN_ETYPE       = 0x8892
_PN_MCAST_DCP   = b"\x01\x0e\xcf\x00\x00\x00"
_RPC_PORT       = 34964
_IOPS_GOOD      = 0x80
_DS_RUN         = 0x01
_DS_VALID       = 0x04
_DS_PRIMARY     = 0x20
_DS_OPERATE     = _DS_RUN | _DS_VALID | _DS_PRIMARY    # 0x25
_DS_STOP        = _DS_VALID | _DS_PRIMARY               # 0x24
_ALARM_LO       = 0xFC01
_ALARM_HI       = 0xFC0F

# DCP option/subopt
_DCP_OPT_IP    = 0x01; _DCP_SUB_IP_MAC = 0x01; _DCP_SUB_IP_PARAM = 0x02
_DCP_OPT_DEV   = 0x02; _DCP_SUB_NAME   = 0x02; _DCP_SUB_DEVID    = 0x03
_DCP_OPT_ALL   = 0xFF; _DCP_SUB_ALL    = 0xFF
_DCP_FID_IDENT_REQ  = 0xFEFE
_DCP_FID_IDENT_RESP = 0xFEFF
_DCP_FID_SET        = 0xFEFD

# Timing limits from GSDML (MinDeviceInterval = 512 × 31.25 µs = 16 ms)
_BASE_US        = 31.25
_MIN_INTERVAL   = 512
_MIN_CYCLE_MS   = 16.0
_VALID_SC       = {8, 16, 32, 64, 128}
_VALID_RR       = {1, 2, 4, 8, 16, 32, 64, 128, 256, 512}

# TeSys Tera identity
_VENDOR_ID = 0x0129
_DEVICE_ID = 0x0701


def _dcp_identify_request(name: str, xid: int = 1) -> bytes:
    name_b = name.lower().encode("ascii")
    pad    = b"\x00" if len(name_b) % 2 else b""
    blk    = struct.pack("!BBH", _DCP_OPT_DEV, _DCP_SUB_NAME, len(name_b))
    blk   += name_b + pad
    return struct.pack("!HBBIHH", _DCP_FID_IDENT_REQ, 0x05, 0x00,
                       xid, 0, len(blk)) + blk


def _dcp_parse_response(frame: bytes) -> Optional[Dict]:
    try:
        fid = struct.unpack_from("!H", frame, 0)[0]
        if fid != _DCP_FID_IDENT_RESP: return None
        dcp_len = struct.unpack_from("!H", frame, 8)[0]
        res: Dict = {}; pos = 10; end = 10 + dcp_len
        while pos + 4 <= end:
            opt, sub = frame[pos], frame[pos+1]
            blen = struct.unpack_from("!H", frame, pos+2)[0]
            bd   = frame[pos+4: pos+4+blen]
            if opt == _DCP_OPT_DEV and sub == _DCP_SUB_NAME:
                res["name"] = bd.decode("ascii", errors="replace").rstrip("\x00")
            elif opt == _DCP_OPT_IP and sub == _DCP_SUB_IP_PARAM and blen >= 12:
                res["ip"]     = socket.inet_ntoa(bd[0:4])
                res["subnet"] = socket.inet_ntoa(bd[4:8])
                res["gw"]     = socket.inet_ntoa(bd[8:12])
            elif opt == _DCP_OPT_DEV and sub == _DCP_SUB_DEVID and blen >= 4:
                res["vendor_id"] = struct.unpack_from("!H", bd, 0)[0]
                res["device_id"] = struct.unpack_from("!H", bd, 2)[0]
            step = 4 + blen + (blen % 2)
            pos += step
        return res
    except Exception: return None


def _dcp_set_name_frame(name: str, xid: int = 2) -> bytes:
    name_b = name.lower().encode("ascii")
    pad    = b"\x00" if len(name_b) % 2 else b""
    blk    = struct.pack("!BBH", _DCP_OPT_DEV, _DCP_SUB_NAME, len(name_b))
    blk   += name_b + pad
    return struct.pack("!HBBIHH", _DCP_FID_SET, 0x04, 0x00,
                       xid, 0, len(blk)) + blk


def _dcp_set_ip_frame(ip: str, subnet: str, gw: str, xid: int = 3) -> bytes:
    blk  = struct.pack("!BBH", _DCP_OPT_IP, _DCP_SUB_IP_PARAM, 12)
    blk += socket.inet_aton(ip) + socket.inet_aton(subnet) + socket.inet_aton(gw)
    return struct.pack("!HBBIHH", _DCP_FID_SET, 0x04, 0x00,
                       xid, 0, len(blk)) + blk


def _rpc_header(pkt_type: int, op: int, call_id: int,
                obj_uuid: uuid.UUID, alloc: int = 0) -> bytes:
    hdr  = struct.pack("!BBBB", 4, pkt_type, 0x20, 0x00)
    hdr += b"\x10\x00\x00\x00"
    frag = 16 + 16 + 8 + alloc
    hdr += struct.pack("!HHI", frag, 0, call_id)
    hdr += struct.pack("!IHH", alloc, 0, op)
    hdr += obj_uuid.bytes
    return hdr


def _rpc_connect_payload(ar_uuid: uuid.UUID, session_key: int,
                          ctrl_mac: bytes, ctrl_ip: str,
                          slot: int, subslot: int,
                          mod_ident: int, sm_ident: int,
                          in_len: int, out_len: int,
                          sc: int, rr: int) -> bytes:
    # ARBlockReq
    ar  = struct.pack("!HH", 0x0101, 40-4)
    ar += struct.pack("!BB", 1, 0)
    ar += struct.pack("!H", 0x0001)       # IOCAR_Single
    ar += ar_uuid.bytes
    ar += struct.pack("!H", session_key)
    ar += ctrl_mac
    ar += struct.pack("!I", struct.unpack("!I", socket.inet_aton(ctrl_ip))[0])
    ar += struct.pack("!H", _RPC_PORT)
    ar += struct.pack("!I", 0x00000008)   # PullModuleAlarmAllowed
    ar += struct.pack("!HHH", 10, 0x0001, 2)

    def iocr(itype, iref, fid, dlen):
        b  = struct.pack("!HH", 0x0102, 36-4)
        b += struct.pack("!BB", 1, 0)
        b += struct.pack("!HHHIHHHHHH",
                         itype, iref, _PN_ETYPE, 0, dlen+2, fid,
                         sc, rr, 1, 0)
        b += struct.pack("!I", 0xFFFFFFFF)
        b += struct.pack("!HH", 5, 3)
        b += struct.pack("!H", 0) + b"\x00"*6
        b += struct.pack("!IH", 1, 0x0000)  # NumberOfAPIs, API
        # IO data objects
        b += struct.pack("!HHHH", 1, slot, subslot, 1)
        # IOCS objects
        b += struct.pack("!HHHH", 1, slot, subslot, 1)
        return b

    icr = iocr(1, 1, 0x8001, in_len)
    ocr = iocr(2, 2, 0x8002, out_len)

    # ExpectedSubmoduleBlockReq
    esm  = struct.pack("!HH", 0x0104, 24-4)
    esm += struct.pack("!BB", 1, 0)
    esm += struct.pack("!HIHIHHHIHHHHHB",
                       1, 0x00000000, slot, mod_ident, 0,
                       1, subslot, sm_ident, 0,
                       0x0001, in_len, 0x0002, out_len, _IOPS_GOOD)
    return ar + icr + ocr + esm


def _parse_rt_frame(raw: bytes, in_len: int,
                     ts_ns: int = 0) -> Optional[Any]:
    try:
        pos = 12
        if raw[pos:pos+2] == b"\x81\x00": pos += 4   # skip 802.1Q VLAN tag
        if struct.unpack_from("!H", raw, pos)[0] != _PN_ETYPE: return None
        pos += 2
        fid = struct.unpack_from("!H", raw, pos)[0]; pos += 2
        # Accept all non-DCP, non-alarm FrameIDs (0x0001..0xFBFF)
        # TeSys Tera uses 0x8001 (input CR) and 0x8002 (output CR)
        if fid == 0x0000 or fid >= 0xFC00: return None
        if pos + in_len + 4 > len(raw): return None
        payload = raw[pos: pos+in_len]
        iops    = raw[pos+in_len]
        iocs    = raw[pos+in_len+1]
        pos2    = pos + in_len + 2
        cc      = struct.unpack_from("!H", raw, pos2)[0]
        ds      = raw[pos2+2]
        ts      = raw[pos2+3]
        return _RTFrame(fid, cc, ds, ts, iops, iocs, payload,
                        (iops & 0x80) != 0, ts_ns)
    except Exception: return None


@dataclass
class _RTFrame:
    frame_id: int; cycle_ctr: int; data_status: int; xfer_status: int
    iops: int; iocs: int; payload: bytes; data_valid: bool; ts_ns: int

    @property
    def provider_ok(self): return bool(self.iops & 0x80)

    @property
    def consumer_ok(self): return bool(self.iocs & 0x80)

    @property
    def run_bit(self): return bool(self.data_status & 0x01)

    @property
    def problem(self): return bool(self.data_status & 0x10)


def _build_read_req(ar_uuid, session_key, slot, subslot, index, seq):
    b  = struct.pack("!HH", 0x0081, 36-4)
    b += struct.pack("!BB", 1, 0)
    b += struct.pack("!H", seq)
    b += ar_uuid.bytes
    b += struct.pack("!IHHHI", 0, slot, subslot, 0, index)
    b += struct.pack("!I", 0x8000)
    b += b"\x00"*24
    return b


def _build_write_req(ar_uuid, session_key, slot, subslot, index, data, seq):
    b  = struct.pack("!HH", 0x0082, 36-4)
    b += struct.pack("!BB", 1, 0)
    b += struct.pack("!H", seq)
    b += ar_uuid.bytes
    b += struct.pack("!IHHHI", 0, slot, subslot, 0, index)
    b += struct.pack("!I", len(data))
    b += b"\x00"*24
    b += data
    return b


def _parse_read_resp(data: bytes) -> Optional[bytes]:
    try:
        if struct.unpack_from("!H", data, 0)[0] != 0x0083: return None
        rlen = struct.unpack_from("!I", data, 36)[0]
        return data[64: 64+rlen]
    except Exception: return None


# ══════════════════════════════════════════════════════════════════════
# PART 2 — TESYS TERA SIGNAL DEFINITIONS  (all 13 modules, English)
# Source: Schneider Electric NVE84303 + GSDML V2.43
# ══════════════════════════════════════════════════════════════════════

@dataclass
class Sig:
    name: str; byte_off: int; enc: str
    bit: int = 0; length: int = 1; scale: float = 1.0; unit: str = ""

    def decode(self, data: bytes) -> Any:
        end = self.byte_off + self._sz()
        if end > len(data): return None
        raw = data[self.byte_off: end]
        return self._dec(raw)

    def _sz(self):
        if self.enc in ("U16","I16"): return 2
        if self.enc in ("U32","I32","F32"): return 4
        if self.enc == "BYTES": return self.length
        return 1   # BIT or BYTE

    def _dec(self, raw):
        if self.enc == "U16": return struct.unpack(">H", raw)[0] * self.scale
        if self.enc == "I16": return struct.unpack(">h", raw)[0] * self.scale
        if self.enc == "U32": return struct.unpack(">I", raw)[0] * self.scale
        if self.enc == "I32": return struct.unpack(">i", raw)[0] * self.scale
        if self.enc == "F32": return struct.unpack(">f", raw)[0]
        if self.enc == "BIT": return bool((raw[0] >> self.bit) & 1)
        if self.enc == "BYTES": return raw
        return raw[0] * self.scale  # BYTE

    def encode(self, value: Any, buf: bytearray) -> bytearray:
        b = bytearray(buf)
        if self.enc == "BIT":
            if value: b[self.byte_off] |=  (1 << self.bit)
            else:     b[self.byte_off] &= ~(1 << self.bit)
        elif self.enc == "U16": struct.pack_into(">H", b, self.byte_off, int(value/self.scale if self.scale!=1 else value)&0xFFFF)
        elif self.enc == "I16": struct.pack_into(">h", b, self.byte_off, int(value/self.scale if self.scale!=1 else value))
        elif self.enc == "U32": struct.pack_into(">I", b, self.byte_off, int(value/self.scale if self.scale!=1 else value)&0xFFFFFFFF)
        elif self.enc == "I32": struct.pack_into(">i", b, self.byte_off, int(value/self.scale if self.scale!=1 else value))
        elif self.enc == "F32": struct.pack_into(">f", b, self.byte_off, float(value))
        elif self.enc == "BYTE": b[self.byte_off] = int(value) & 0xFF
        return b


def _bit(name, byte, bit, unit=""): return Sig(name, byte, "BIT", bit=bit, unit=unit)
def _u16(name, byte, scale=1.0, unit=""): return Sig(name, byte, "U16", scale=scale, unit=unit)
def _u32(name, byte, scale=1.0, unit=""): return Sig(name, byte, "U32", scale=scale, unit=unit)
def _i32(name, byte, scale=1.0, unit=""): return Sig(name, byte, "I32", scale=scale, unit=unit)
def _i16(name, byte, scale=1.0, unit=""): return Sig(name, byte, "I16", scale=scale, unit=unit)


# ── Module 1: Tera Profile  0x10400003  IN=40B  OUT=4B ───────────────
_M1_IN = [
    _bit("Ready",                  0,0), _bit("Running_Forward",        0,1),
    _bit("Running_Reverse",        0,2), _bit("Tripped",                0,3),
    _bit("Warning_Active",         0,4), _bit("Fault_Active",           0,5),
    _bit("Local_Mode",             0,6), _bit("Remote_Mode",            0,7),
    _bit("Motor_Running",          1,0), _bit("K1_Closed",              1,1),
    _bit("K2_Closed",              1,2), _bit("Power_Section_Healthy",  1,3),
    _bit("Stopped_After_Command",  1,4), _bit("Overload_Warning",       1,5),
    _bit("Maintenance_Indicator",  1,6), _bit("Config_Valid",           1,7),
    _u16("Thermal_Capacity_Used_pct",  2, 0.1, "%"),
    _u32("Average_Current_pct_FLC",    4, 0.1, "%FLC"),
    _u32("Phase_A_Current_pct_FLC",    8, 0.1, "%FLC"),
    _u32("Phase_B_Current_pct_FLC",   12, 0.1, "%FLC"),
    _u32("Phase_C_Current_pct_FLC",   16, 0.1, "%FLC"),
    _u32("Current_Unbalance_pct",     20, 0.1, "%"),
    _u32("Voltage_L1_L2",            24, 0.1, "V"),
    _u32("Voltage_L2_L3",            28, 0.1, "V"),
    _u32("Voltage_L3_L1",            32, 0.1, "V"),
    _u16("Frequency_Hz",             36, 0.01, "Hz"),
    _u16("Earth_Leakage_Current_pct",38, 0.1, "%FLC"),
]
_M1_OUT = [
    _bit("Cmd_Stop",            0,0), _bit("Cmd_Run_Forward",  0,1),
    _bit("Cmd_Run_Reverse",     0,2), _bit("Cmd_Fault_Reset",  0,3),
    _bit("Cmd_Emergency_Stop",  0,4), _bit("Cmd_Bit5",         0,5),
    _bit("Cmd_Bit6",            0,6), _bit("Cmd_Bit7",         0,7),
]

# ── Module 2/3: Basic/Extended Overload  IN=1B  OUT=1B ───────────────
_MOL_IN = [
    _bit("OL_Ready",0,0), _bit("OL_Running",0,1), _bit("OL_Tripped",0,2),
    _bit("OL_Warning",0,3), _bit("OL_Reset_Required",0,4),
    _bit("OL_Local_Mode",0,5), _bit("OL_Overload_Class",0,6), _bit("OL_Spare",0,7),
]
_MOL_OUT = [_bit("OL_Cmd_Reset",0,0), _bit("OL_Cmd_Spare",0,1)]

# ── Module 4/5: Basic Motor Starter / Extended Contractor  IN=1B  OUT=1B
_MS_IN = [
    _bit("Starter_Ready",0,0), _bit("Starter_Running",0,1), _bit("Starter_Tripped",0,2),
    _bit("Starter_Warning",0,3), _bit("Starter_K1",0,4), _bit("Starter_Local",0,5),
    _bit("Starter_Spare6",0,6), _bit("Starter_Spare7",0,7),
]
_MS_OUT = [_bit("Starter_Cmd_Run",0,0), _bit("Starter_Cmd_Stop",0,1), _bit("Starter_Cmd_Reset",0,2)]

# ── Module 6/7: Extended Motor Starter 1/2  IN=1B  OUT=1B ────────────
_ES_IN = [
    _bit("ExtStarter_Ready",0,0), _bit("ExtStarter_Running_Fwd",0,1),
    _bit("ExtStarter_Running_Rev",0,2), _bit("ExtStarter_Tripped",0,3),
    _bit("ExtStarter_Warning",0,4), _bit("ExtStarter_K1",0,5),
    _bit("ExtStarter_K2",0,6), _bit("ExtStarter_Local",0,7),
]
_ES_OUT = [
    _bit("ExtStarter_Cmd_Stop",0,0), _bit("ExtStarter_Cmd_Fwd",0,1),
    _bit("ExtStarter_Cmd_Rev",0,2), _bit("ExtStarter_Cmd_Reset",0,3),
]

# ── Module 8: LTMT Control & Monitoring  IN=8B  OUT=6B ───────────────
_M8_IN = [
    _bit("LTMT_Ready",0,0), _bit("LTMT_Running_Fwd",0,1), _bit("LTMT_Running_Rev",0,2),
    _bit("LTMT_Tripped",0,3), _bit("LTMT_Warning",0,4), _bit("LTMT_Fault",0,5),
    _bit("LTMT_Local",0,6), _bit("LTMT_Remote",0,7),
    _bit("LTMT_K1",1,0), _bit("LTMT_K2",1,1), _bit("LTMT_DI1",1,2), _bit("LTMT_DI2",1,3),
    _bit("LTMT_DI3",1,4), _bit("LTMT_DI4",1,5), _bit("LTMT_DO1",1,6), _bit("LTMT_DO2",1,7),
    _u16("LTMT_Avg_Current_pct",2,0.1,"%FLC"), _u16("LTMT_Thermal_Capacity_pct",4,0.1,"%"),
    _u16("LTMT_Last_Trip_Code",6,1.0,"code"),
]
_M8_OUT = [
    _bit("LTMT_Cmd_Stop",0,0), _bit("LTMT_Cmd_Run_Fwd",0,1), _bit("LTMT_Cmd_Run_Rev",0,2),
    _bit("LTMT_Cmd_Reset",0,3), _bit("LTMT_Cmd_DO1",0,4), _bit("LTMT_Cmd_DO2",0,5),
]

# ── Module 9/10: PKW  IN=8B  OUT=8B ──────────────────────────────────
_PKW_IN  = [_u16("PKW_Response_ID",0,1.0,"code"), _u16("PKW_Param_Number",2),
            _u16("PKW_Param_Value_Hi",4), _u16("PKW_Param_Value_Lo",6)]
_PKW_OUT = [_u16("PKW_Request_ID",0,1.0,"code"), _u16("PKW_Param_Number",2),
            _u16("PKW_Write_Value_Hi",4), _u16("PKW_Write_Value_Lo",6)]

# ── Module 11: PKW + LTMT Management  IN=16B  OUT=14B ────────────────
_M11_IN  = _M8_IN  + [_u16("MGMT_PKW_Resp_ID",8), _u16("MGMT_PKW_Param_Num",10),
                       _u16("MGMT_PKW_Val_Hi",12), _u16("MGMT_PKW_Val_Lo",14)]
_M11_OUT = _M8_OUT + [_u16("MGMT_PKW_Req_ID",6),  _u16("MGMT_PKW_Param_Num",8),
                       _u16("MGMT_PKW_Write_Hi",10),_u16("MGMT_PKW_Write_Lo",12)]

# ── Module 12: E_Fast Access  IN=12B  OUT=6B ─────────────────────────
_M12_IN = [
    _bit("EFA_Ready",0,0), _bit("EFA_Running_Fwd",0,1), _bit("EFA_Running_Rev",0,2),
    _bit("EFA_Tripped",0,3), _bit("EFA_Warning",0,4), _bit("EFA_Fault",0,5),
    _bit("EFA_Local",0,6), _bit("EFA_Remote",0,7),
    _u16("EFA_Avg_Current_pct",2,0.1,"%FLC"), _u16("EFA_Thermal_Cap_pct",4,0.1,"%"),
    _u16("EFA_Voltage_L1L2",6,0.1,"V"), _u16("EFA_Voltage_L2L3",8,0.1,"V"),
    _u16("EFA_Voltage_L3L1",10,0.1,"V"),
]
_M12_OUT = [_bit("EFA_Cmd_Stop",0,0), _bit("EFA_Cmd_Run_Fwd",0,1),
            _bit("EFA_Cmd_Run_Rev",0,2), _bit("EFA_Cmd_Reset",0,3)]

# ── Module 13: EIOS  IN=128B  OUT=10B ────────────────────────────────
_M13_IN = _M8_IN + [
    _u32("EIOS_Phase_A_Current_pct",8,0.1,"%FLC"), _u32("EIOS_Phase_B_Current_pct",12,0.1,"%FLC"),
    _u32("EIOS_Phase_C_Current_pct",16,0.1,"%FLC"),
    _u32("EIOS_Voltage_L1L2",20,0.1,"V"), _u32("EIOS_Voltage_L2L3",24,0.1,"V"),
    _u32("EIOS_Voltage_L3L1",28,0.1,"V"),
    _i32("EIOS_Active_Power_W",32,1.0,"W"), _i32("EIOS_Reactive_Power_VAR",36,1.0,"VAR"),
    _u32("EIOS_Apparent_Power_VA",40,1.0,"VA"), _i16("EIOS_Power_Factor",44,0.01,""),
    _u16("EIOS_Frequency_Hz",46,0.01,"Hz"), _u16("EIOS_Thermal_Cap_pct",48,0.1,"%"),
    _u16("EIOS_Current_Unbal_pct",50,0.1,"%"), _u16("EIOS_Voltage_Unbal_pct",52,0.1,"%"),
    _u16("EIOS_Earth_Leakage_pct",54,0.1,"%FLC"), _u16("EIOS_Trip_Code",56,1.0,"code"),
    _u16("EIOS_Trip_Current_pct",58,0.1,"%FLC"),
]
_M13_OUT = [_bit("EIOS_Cmd_Stop",0,0), _bit("EIOS_Cmd_Run_Fwd",0,1),
            _bit("EIOS_Cmd_Run_Rev",0,2), _bit("EIOS_Cmd_Reset",0,3),
            _bit("EIOS_Cmd_Emrg_Stop",0,4)]

# Lookup tables: SubmoduleIdentNumber → (name, in_len, out_len, in_sigs, out_sigs)
MODULES: Dict[int, Dict] = {
    1:  {"ident": 0x10400003, "name": "Tera Profile",           "in": 40,  "out": 4,  "in_sigs": _M1_IN,   "out_sigs": _M1_OUT},
    2:  {"ident": 0x10400004, "name": "Basic Overload",         "in": 1,   "out": 1,  "in_sigs": _MOL_IN,  "out_sigs": _MOL_OUT},
    3:  {"ident": 0x10400005, "name": "Extended Overload",      "in": 1,   "out": 1,  "in_sigs": _MOL_IN,  "out_sigs": _MOL_OUT},
    4:  {"ident": 0x10400006, "name": "Basic Motor Starter",    "in": 1,   "out": 1,  "in_sigs": _MS_IN,   "out_sigs": _MS_OUT},
    5:  {"ident": 0x10400007, "name": "Extended Contractor",    "in": 1,   "out": 1,  "in_sigs": _MS_IN,   "out_sigs": _MS_OUT},
    6:  {"ident": 0x10400008, "name": "Ext Motor Starter 1",   "in": 1,   "out": 1,  "in_sigs": _ES_IN,   "out_sigs": _ES_OUT},
    7:  {"ident": 0x10400009, "name": "Ext Motor Starter 2",   "in": 1,   "out": 1,  "in_sigs": _ES_IN,   "out_sigs": _ES_OUT},
    8:  {"ident": 0x10400010, "name": "LTMT Control+Monitor",  "in": 8,   "out": 6,  "in_sigs": _M8_IN,   "out_sigs": _M8_OUT},
    9:  {"ident": 0x10400011, "name": "PKW",                   "in": 8,   "out": 8,  "in_sigs": _PKW_IN,  "out_sigs": _PKW_OUT},
    10: {"ident": 0x10400012, "name": "PKW+Ext Motor Starter", "in": 10,  "out": 10, "in_sigs": _PKW_IN,  "out_sigs": _PKW_OUT},
    11: {"ident": 0x10400013, "name": "PKW+LTMT Management",  "in": 16,  "out": 14, "in_sigs": _M11_IN,  "out_sigs": _M11_OUT},
    12: {"ident": 0x10400014, "name": "E_Fast Access",        "in": 12,  "out": 6,  "in_sigs": _M12_IN,  "out_sigs": _M12_OUT},
    13: {"ident": 0x10400015, "name": "EIOS",                 "in": 128, "out": 10, "in_sigs": _M13_IN,  "out_sigs": _M13_OUT},
}

# English alarm/trip texts keyed by ErrorType (from GSDML PrimaryLanguage section)
DIAG_TEXTS: Dict[int, str] = {
    0x1001:"Overload Alarm",        0x1002:"Locked Rotor Alarm",
    0x1003:"Stalled Rotor Alarm",   0x1004:"Over Current Alarm",
    0x1005:"Over Current IDMT Alarm",0x1006:"Short Circuit Alarm",
    0x1007:"Earth Fault Internal Alarm",0x1008:"Earth Fault External Alarm",
    0x1009:"Under Current Alarm",   0x100A:"Current Unbalance Alarm",
    0x100B:"Current Phase Loss Alarm",0x100C:"Current Phase Reversal Alarm",
    0x1011:"Under Voltage Alarm",   0x1012:"Over Voltage Alarm",
    0x1013:"Voltage Phase Loss Alarm",0x1014:"Voltage Unbalance Alarm",
    0x1015:"Voltage Phase Reversal Alarm",0x1016:"Under Frequency Alarm",
    0x1017:"Over Frequency Alarm",  0x1018:"Under Power Alarm",
    0x1019:"Over Power Alarm",      0x101A:"Under PF Alarm",
    0x1021:"Interlock-1 Alarm",     0x1022:"Interlock-2 Alarm",
    0x1023:"Interlock-3 Alarm",     0x1024:"Interlock-4 Alarm",
    0x1025:"Interlock-5 Alarm",     0x1026:"Interlock-6 Alarm",
    0x1031:"Overload Trip",         0x1032:"Locked Rotor Trip",
    0x1033:"Stalled Rotor Trip",    0x1034:"Over Current Trip",
    0x1035:"Over Current IDMT Trip",0x1036:"Short Circuit Trip",
    0x1037:"Earth Fault Internal Trip",0x1038:"Earth Fault External Trip",
    0x1039:"Under Current Trip",    0x103A:"Current Unbalance Trip",
    0x103B:"Current Phase Loss Trip",0x103C:"Current Phase Reversal Trip",
    0x1041:"Under Voltage Trip",    0x1042:"Over Voltage Trip",
    0x1043:"Voltage Phase Loss Trip",0x1044:"Voltage Unbalance Trip",
    0x1045:"Voltage Phase Reversal Trip",0x1046:"Under Frequency Trip",
    0x1047:"Over Frequency Trip",   0x1048:"Under Power Trip",
    0x1049:"Over Power Trip",       0x104A:"Under PF Trip",
    0x1051:"Interlock-1 Trip",      0x1052:"Interlock-2 Trip",
    0x10A9:"Communication Fail Alarm",0x10AA:"Communication Fail Trip",
    0x10AB:"Excessive Start Time Trip",
}

ALARM_NAMES = {0x01:"Diagnosis",0x02:"Process",0x03:"Pull",0x04:"Plug",
               0x05:"Status",0x06:"Update",0x0C:"Diagnosis Disappears"}


def decode_inputs(mod_id: int, raw: bytes) -> Dict[str, Any]:
    m = MODULES.get(mod_id, MODULES[1])
    return {s.name: s.decode(raw) for s in m["in_sigs"]
            if s.decode(raw) is not None}


def build_output(mod_id: int, signals: Dict[str,Any],
                 base: bytearray) -> bytearray:
    buf = bytearray(base)
    sigs = MODULES.get(mod_id, MODULES[1])["out_sigs"]
    for name, val in signals.items():
        sig = next((s for s in sigs if s.name==name), None)
        if sig: buf = sig.encode(val, buf)
    return buf


# ══════════════════════════════════════════════════════════════════════
# PART 3 — IO CONTROLLER
# ══════════════════════════════════════════════════════════════════════

_IS_WIN = platform.system() == "Windows"
_hires  = False

def _hires_on():
    global _hires
    if _IS_WIN and not _hires:
        try: ctypes.windll.winmm.timeBeginPeriod(1); _hires=True
        except Exception: pass

def _hires_off():
    global _hires
    if _IS_WIN and _hires:
        try: ctypes.windll.winmm.timeEndPeriod(1)
        except Exception: pass
        _hires=False

def _thr_high():
    if _IS_WIN:
        try: ctypes.windll.kernel32.SetThreadPriority(
            ctypes.windll.kernel32.GetCurrentThread(), 2)
        except Exception: pass

def _load_scapy():
    try:
        import scapy.all as s  # type: ignore
        return True, s
    except Exception: return False, None

_SCAPY_OK, _SCAPY = _load_scapy()

# ── Capture backend: Scapy → pyshark → tshark subprocess ─────────────
# Npcap is the kernel driver that ALL three use underneath.
# TShark/Wireshark ship Npcap as part of their installer, so if
# TShark is present, Npcap is present – Scapy will work too.
# pyshark/tshark are capture-only (cannot inject frames).
# The TX thread always requires Scapy+Npcap for frame injection.

def _resolve_adapter_names() -> List[Dict]:
    r"""
    Resolve raw Npcap \Device\NPF_{GUID} names to human-readable Windows
    adapter names like 'Ethernet', 'Wi-Fi', 'Ethernet 2'.

    Returns a list of dicts:
      {
        "index":   1,
        "raw":     r"\Device\NPF_{GUID}",   ← what Scapy uses internally
        "name":    "Ethernet",               ← human-readable display name
        "guid":    "F7EC155F-...",
        "hint":    "← physical Ethernet",   ← category hint
        "skip":    False,                    ← True for virtual/loopback
      }

    Resolution order (most reliable first):
      1. winreg  – direct Windows Registry lookup (no external process)
      2. PowerShell Get-NetAdapter – works on Windows 8+
      3. wmic – works on older Windows
      4. netifaces – cross-platform, sometimes has friendly names
      5. Raw GUID (fallback – shows first 8 chars of GUID)
    """
    import re

    if not _SCAPY_OK:
        return []

    raw_ifaces: List[str] = []
    try:
        raw_ifaces = _SCAPY.get_if_list()
    except Exception:
        return []

    # ── Step 1: build GUID → friendly-name map using every method ────
    guid_to_name: Dict[str, str] = {}

    # Method A: winreg (Windows Registry, always available, no admin)
    if platform.system() == "Windows":
        try:
            import winreg
            NET_KEY = (r"SYSTEM\CurrentControlSet\Control\Network"
                       r"\{4D36E972-E325-11CE-BFC1-08002BE10318}")
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_KEY) as net:
                i = 0
                while True:
                    try:
                        guid = winreg.EnumKey(net, i); i += 1
                        conn_path = f"{NET_KEY}\\{guid}\\Connection"
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                                conn_path) as conn:
                                name, _ = winreg.QueryValueEx(conn, "Name")
                                guid_to_name[guid.upper().strip("{}")] = name
                        except OSError:
                            pass
                    except OSError:
                        break
        except Exception:
            pass

    # Method B: PowerShell Get-NetAdapter (if winreg gave nothing)
    if not guid_to_name and platform.system() == "Windows":
        try:
            import subprocess, shutil
            ps = shutil.which("powershell") or shutil.which("powershell.exe")
            if ps:
                cmd = [ps, "-NoProfile", "-NonInteractive", "-Command",
                       "Get-NetAdapter | Select-Object Name,InterfaceGuid"
                       " | ConvertTo-Json -Compress"]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if r.returncode == 0 and r.stdout.strip():
                    import json
                    data = json.loads(r.stdout.strip())
                    if isinstance(data, dict):
                        data = [data]
                    for item in data:
                        g = item.get("InterfaceGuid","").upper().strip("{}")
                        n = item.get("Name","")
                        if g and n:
                            guid_to_name[g] = n
        except Exception:
            pass

    # Method C: wmic (older Windows)
    if not guid_to_name and platform.system() == "Windows":
        try:
            import subprocess, shutil
            wmic = shutil.which("wmic")
            if wmic:
                r = subprocess.run(
                    [wmic, "nic", "get",
                     "Name,GUID,NetConnectionID", "/format:csv"],
                    capture_output=True, text=True, timeout=8)
                for line in r.stdout.splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 4:
                        guid_val = parts[2].upper().strip("{}")
                        conn_id  = parts[3]
                        if guid_val and conn_id:
                            guid_to_name[guid_val] = conn_id
        except Exception:
            pass

    # Method D: netifaces (cross-platform, sometimes has info)
    try:
        import netifaces  # type: ignore
        for iface_name in netifaces.interfaces():
            # netifaces on Windows sometimes returns friendly names directly
            guid_m = re.search(r'\{([A-F0-9\-]+)\}', iface_name, re.I)
            if guid_m:
                g = guid_m.group(1).upper()
                if g not in guid_to_name:
                    guid_to_name[g] = iface_name  # at least the raw GUID
    except (ImportError, AttributeError, Exception):
        pass

    # ── Step 2: build display list ────────────────────────────────────
    def _categorise(name: str) -> Tuple[str, bool]:
        """Return (hint_text, should_skip)."""
        n = name.lower()
        if any(x in n for x in ["loopback", "npcap loopback"]):
            return "← loopback / skip", True
        if any(x in n for x in ["vmware", "vmnet", "virtualbox",
                                  "vboxnet", "hyper-v", "hyper_v",
                                  "vethernet", "virtual"]):
            return "← virtual adapter / skip", True
        if "bluetooth" in n:
            return "← Bluetooth / skip", True
        if any(x in n for x in ["ethernet", "lan", "realtek", "intel®",
                                  "broadcom", "killer", "aquantia"]):
            return "← physical Ethernet  ★ use this for PROFINET", False
        if any(x in n for x in ["wi-fi", "wifi", "wireless", "wlan", "802.11"]):
            return "← Wi-Fi (only if relay is on same Wi-Fi segment)", False
        if any(x in n for x in ["tap", "tun", "vpn", "cisco", "juniper",
                                  "nordvpn", "openvpn"]):
            return "← VPN adapter / skip", True
        return "", False

    result = []
    for raw in raw_ifaces:
        guid_m  = re.search(r'\{([A-F0-9\-]+)\}', raw, re.I)
        guid    = guid_m.group(1).upper() if guid_m else ""
        if "Loopback" in raw and not guid:
            friendly = "Npcap Loopback"
            skip     = True
            hint     = "← loopback / skip"
        elif guid and guid in guid_to_name:
            friendly = guid_to_name[guid]
            hint, skip = _categorise(friendly)
        elif guid:
            # Could not resolve: show shortened GUID as last resort
            friendly = f"Adapter {guid[:8]}…"
            hint, skip = "← (run option 21 to identify)", False
        else:
            friendly = raw
            hint, skip = "", False

        result.append({
            "index":  len(result) + 1,
            "raw":    raw,
            "name":   friendly,
            "guid":   guid,
            "hint":   hint,
            "skip":   skip,
        })

    return result


def _detect_capture_backends() -> Dict[str, bool]:
    """Return which capture backends are available on this machine."""
    result = {"scapy": False, "pyshark": False, "tshark": False}
    # Scapy
    if _SCAPY_OK:
        result["scapy"] = True
    # pyshark
    try:
        import pyshark  # type: ignore
        result["pyshark"] = True
    except ImportError:
        pass
    # tshark binary
    import shutil
    if shutil.which("tshark") or shutil.which("tshark.exe"):
        result["tshark"] = True
    # Npcap DLL (Windows)
    import platform
    if platform.system() == "Windows":
        npcap_dll = Path(os.environ.get("SYSTEMROOT","C:\\Windows"),
                         "System32","Npcap","wpcap.dll")
        result["npcap_dll"] = npcap_dll.exists()
    return result


class _TSharkCapture:
    """
    Fallback passive capture using tshark subprocess.
    RECEIVE ONLY – cannot inject TX frames (use Scapy for that).
    Used when Scapy Python bindings fail but tshark is installed.
    """
    def __init__(self, iface: str, bpf: str = "ether proto 0x8892"):
        self._iface = iface
        self._bpf   = bpf
        self._proc  = None
        self._queue : queue.SimpleQueue = queue.SimpleQueue()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        import subprocess, shutil
        tshark = shutil.which("tshark") or shutil.which("tshark.exe")
        if not tshark:
            raise RuntimeError("tshark not found on PATH")
        cmd = [tshark, "-i", self._iface, "-f", self._bpf,
               "-l", "-n", "-x", "-T", "text"]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0)
        self._thread = threading.Thread(
            target=self._reader, daemon=True, name="TShark-Cap")
        self._thread.start()

    def _reader(self):
        """Parse tshark hex dump output into raw bytes and queue them."""
        buf: List[int] = []
        for line in self._proc.stdout:
            line = line.decode("latin-1", errors="replace").rstrip()
            # tshark hex lines look like:  0000  01 0e cf 00 00 00 ...
            import re
            m = re.match(r'\s*[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s?)+)', line)
            if m:
                hex_part = m.group(1).replace(" ","")
                try:
                    buf.extend(bytes.fromhex(hex_part))
                except ValueError:
                    pass
            elif line.strip() == "" and buf:
                self._queue.put_nowait(bytes(buf))
                buf = []
        if buf:
            self._queue.put_nowait(bytes(buf))

    def recv(self, max_size: int = 65535) -> Optional[bytes]:
        try:
            return self._queue.get(timeout=0.1)
        except queue.Empty:
            return None

    def send(self, _frame):
        raise RuntimeError(
            "TShark capture is receive-only.\n"
            "Install Npcap + scapy to enable TX frame injection.")

    def close(self):
        if self._proc:
            try: self._proc.terminate()
            except Exception: pass
            self._proc = None


@dataclass
class AlarmEvent:
    ts: float; alarm_type: int; alarm_name: str
    slot: int; subslot: int; error_type: int; text: str; raw: bytes = b""


@dataclass
class _Conn:
    ar_uuid:  uuid.UUID = field(default_factory=uuid.uuid4)
    sess_key: int  = 0
    fid_in:   int  = 0x8001
    fid_out:  int  = 0x8002
    dev_mac:  bytes = b"\x00"*6
    dev_ip:   str   = ""
    ctrl_mac: bytes = b"\x00"*6
    ctrl_ip:  str   = ""
    ok:       bool  = False
    cid:      int   = 1


@dataclass
class _RTBuf:
    _lk:  threading.Lock            = field(default_factory=threading.Lock)
    _fr:  Optional[_RTFrame]       = None
    _sig: Dict[str,Any]            = field(default_factory=dict)

    def put(self, fr, sig):
        with self._lk: self._fr=fr; self._sig=sig.copy()
    def signals(self):
        with self._lk: return self._sig.copy()
    def frame(self):
        with self._lk: return self._fr
    @property
    def valid(self):
        with self._lk: return self._fr is not None and self._fr.data_valid


@dataclass
class _Stats:
    _lk:  threading.Lock  = field(default_factory=threading.Lock)
    _win: collections.deque = field(default_factory=lambda: collections.deque(maxlen=200))
    total:int=0; missed:int=0; last_ns:int=0
    min_ms:float=float("inf"); max_ms:float=0.0; avg_ms:float=0.0

    def record(self, ns):
        with self._lk:
            if self.last_ns:
                dt = (ns-self.last_ns)/1e6
                self._win.append(dt)
                if dt<self.min_ms: self.min_ms=dt
                if dt>self.max_ms: self.max_ms=dt
                self.avg_ms = sum(self._win)/len(self._win)
            self.last_ns=ns; self.total+=1

    def snap(self):
        with self._lk:
            return {"total":self.total,"missed":self.missed,
                    "min_ms":round(self.min_ms,3) if self.min_ms!=float("inf") else None,
                    "max_ms":round(self.max_ms,3),"avg_ms":round(self.avg_ms,3)}


class Controller:
    """
    Full PROFINET IO Controller for Schneider TeSys Tera.
    Implements: AR establishment, cyclic RT, operate/stop, force table,
    alarm receive+decode, IM0-4 records, auto-reconnect, watch list.
    """

    def __init__(self, iface:str, station:str="tesys-tera-pn",
                 mod_id:int=1, sc:int=32, rr:int=16,
                 timeout:float=10.0, auto_recon:bool=True,
                 recon_delay:float=5.0):
        self._iface   = iface
        self._station = station.lower()
        self._mod_id  = mod_id
        self._timeout = timeout
        self._auto_rc = auto_recon
        self._rc_dly  = recon_delay
        self._manual_ip: Optional[str] = None

        sc, rr = self._clamp(sc, rr)
        self._sc = sc; self._rr = rr
        self._cycle_ms = sc*rr*_BASE_US/1000
        self._cycle_s  = self._cycle_ms/1000

        mod = MODULES[mod_id]
        self._in_len  = mod["in"]
        self._out_len = mod["out"]
        self._mod_name= mod["name"]
        self._mod_ident= 0x10400000   # all TeSys Tera modules share this
        self._sm_ident = mod["ident"]

        self._conn   = _Conn()
        self._rtbuf  = _RTBuf()
        self._stats  = _Stats()

        self._outbuf = bytearray(self._out_len)
        self._outlk  = threading.Lock()
        self._dirty  = True
        self._operate= True

        self._force: Dict[str,Any] = {}
        self._flk    = threading.Lock()

        self.alarm_log: collections.deque = collections.deque(maxlen=500)
        self._alarm_cbs: List[Callable] = []
        self._watches: List[Dict] = []
        self._wlk    = threading.Lock()

        self._capq   = queue.SimpleQueue()
        self._almq   = queue.SimpleQueue()
        self._stop   = threading.Event()
        self._l2s    = None
        self._l2lk   = threading.Lock()
        self._rpc_s: Optional[socket.socket] = None
        self._frame_pre = b""; self._frame_suf = b""

    # ── Properties ────────────────────────────────────────────────────
    @property
    def cycle_ms(self) -> float: return self._cycle_ms
    @property
    def is_operate(self) -> bool: return self._operate
    @property
    def connected(self) -> bool: return self._conn.ok

    # ── Connect / Disconnect ──────────────────────────────────────────
    def connect(self) -> bool:
        _hires_on()
        info2 = self._dcp_discover()
        if not info2:
            if self._manual_ip:
                info2 = {"ip":self._manual_ip,"mac":b"\x00"*6}
            else:
                raise ConnectionError(
                    f"DCP discovery failed for '{self._station}'.\n"
                    "  Check: device powered, same network, Npcap installed.\n"
                    "  Or use Settings → Enter device IP manually.")
        self._conn.dev_ip  = info2["ip"]
        self._conn.dev_mac = info2["mac"]
        self._conn.ctrl_ip, self._conn.ctrl_mac = self._local_addr()
        if not self._rpc_connect():
            raise ConnectionError("RPC Connect failed – AR not established.")
        self._open_l2()
        self._stop.clear()
        for name, fn in [("PNIO-RX",self._rx_loop),("PNIO-Dec",self._dec_loop),
                          ("PNIO-TX",self._tx_loop),("PNIO-Alm",self._alm_loop)]:
            threading.Thread(target=fn, name=name, daemon=True).start()
        if self._auto_rc:
            threading.Thread(target=self._recon_loop,name="PNIO-RC",daemon=True).start()
        self._conn.ok = True
        return True

    def disconnect(self):
        self._stop.set()
        try: self._rpc_release()
        except Exception: pass
        self._close_l2()
        if self._rpc_s:
            try: self._rpc_s.close()
            except Exception: pass
            self._rpc_s = None
        _hires_off(); self._conn.ok = False

    def set_device_ip(self, ip:str):
        self._manual_ip = ip; self._conn.dev_ip = ip

    # ── Operate / Stop ────────────────────────────────────────────────
    def set_operate(self, run:bool):
        self._operate = run
        with self._outlk: self._dirty = True

    # ── Force table ───────────────────────────────────────────────────
    def force_set(self, name:str, val:Any):
        sigs = MODULES[self._mod_id]["out_sigs"]
        if not any(s.name==name for s in sigs):
            raise KeyError(f"Output '{name}' not found.")
        with self._flk: self._force[name]=val

    def force_clear(self, name:str):
        with self._flk: self._force.pop(name,None)

    def force_clear_all(self):
        with self._flk: self._force.clear()

    def force_table(self) -> Dict[str,Any]:
        with self._flk: return dict(self._force)

    # ── Cyclic inputs ─────────────────────────────────────────────────
    def read_inputs(self) -> Dict[str,Any]:
        if not self._conn.ok: raise RuntimeError("Not connected.")
        if not self._rtbuf.valid: raise RuntimeError("IOPS BAD – no valid data yet.")
        return self._rtbuf.signals()

    def read_signal(self, name:str) -> Any:
        d = self.read_inputs()
        if name not in d: raise KeyError(f"Signal '{name}' not found.")
        return d[name]

    def wait_valid(self, timeout:float=10.0) -> bool:
        end = time.monotonic()+timeout
        while time.monotonic()<end:
            if self._rtbuf.valid: return True
            time.sleep(0.005)
        return False

    # ── Cyclic outputs ────────────────────────────────────────────────
    def write(self, name:str, val:Any):
        sigs = MODULES[self._mod_id]["out_sigs"]
        sig  = next((s for s in sigs if s.name==name),None)
        if not sig: raise KeyError(f"Output '{name}' not found.")
        with self._outlk: self._outbuf=sig.encode(val,self._outbuf); self._dirty=True

    def write_many(self, signals:Dict[str,Any]):
        sigs = MODULES[self._mod_id]["out_sigs"]
        with self._outlk:
            for n,v in signals.items():
                s=next((x for x in sigs if x.name==n),None)
                if s: self._outbuf=s.encode(v,self._outbuf)
            self._dirty=True

    def clear_outputs(self):
        with self._outlk: self._outbuf=bytearray(self._out_len); self._dirty=True

    # ── Motor shortcuts ───────────────────────────────────────────────
    def cmd_run_fwd(self):  self.write_many({"Cmd_Stop":False,"Cmd_Run_Forward":True,"Cmd_Run_Reverse":False})
    def cmd_run_rev(self):  self.write_many({"Cmd_Stop":False,"Cmd_Run_Forward":False,"Cmd_Run_Reverse":True})
    def cmd_stop(self):     self.write_many({"Cmd_Stop":True,"Cmd_Run_Forward":False,"Cmd_Run_Reverse":False})
    def cmd_reset(self):    self.write("Cmd_Fault_Reset",True); time.sleep(0.2); self.write("Cmd_Fault_Reset",False)
    def cmd_estop(self):    self.write("Cmd_Emergency_Stop",True)

    # ── Watch list ────────────────────────────────────────────────────
    def watch_add(self, name:str, cond:str, threshold:Any, cb:Optional[Callable]=None):
        with self._wlk:
            self._watches.append({"name":name,"cond":cond,"thr":threshold,
                                   "cb":cb,"triggered":False,"last":None})

    def watch_remove(self, name:str):
        with self._wlk: self._watches=[w for w in self._watches if w["name"]!=name]

    def watch_list(self) -> List[Dict]:
        with self._wlk: return list(self._watches)

    def _eval_watches(self, signals:Dict[str,Any]):
        ops={"gt":lambda a,b:a>b,"lt":lambda a,b:a<b,"ge":lambda a,b:a>=b,
             "le":lambda a,b:a<=b,"eq":lambda a,b:a==b,"ne":lambda a,b:a!=b}
        with self._wlk:
            for w in self._watches:
                v=signals.get(w["name"]); w["last"]=v
                if v is None: continue
                fn=ops.get(w["cond"])
                if fn and fn(v,w["thr"]):
                    if not w["triggered"]:
                        w["triggered"]=True
                        if w["cb"]:
                            try: w["cb"]({"signal":w["name"],"value":v,"threshold":w["thr"]})
                            except Exception: pass
                else: w["triggered"]=False

    # ── Alarm callbacks ───────────────────────────────────────────────
    def alarm_cb_add(self, cb:Callable): self._alarm_cbs.append(cb)

    # ── Acyclic records ───────────────────────────────────────────────
    def read_record(self, slot:int, subslot:int, index:int, timeout:float=3.0) -> Optional[bytes]:
        if not self._conn.ok: raise RuntimeError("Not connected.")
        payload = _build_read_req(self._conn.ar_uuid,self._conn.sess_key,
                                   slot,subslot,index,self._next_cid())
        hdr = _rpc_header(0,0x02,self._conn.cid,self._conn.ar_uuid,len(payload))
        try:
            s=self._rpc_sock(); s.settimeout(timeout)
            s.sendto(hdr+payload,(self._conn.dev_ip,_RPC_PORT))
            resp,_=s.recvfrom(65536)
            return _parse_read_resp(resp[80:])
        except Exception: return None

    def write_record(self, slot:int, subslot:int, index:int,
                     data:bytes, timeout:float=3.0) -> bool:
        if not self._conn.ok: raise RuntimeError("Not connected.")
        payload = _build_write_req(self._conn.ar_uuid,self._conn.sess_key,
                                    slot,subslot,index,data,self._next_cid())
        hdr = _rpc_header(0,0x03,self._conn.cid,self._conn.ar_uuid,len(payload))
        try:
            s=self._rpc_sock(); s.settimeout(timeout)
            s.sendto(hdr+payload,(self._conn.dev_ip,_RPC_PORT))
            resp,_=s.recvfrom(4096)
            return struct.unpack_from("!H",resp,80)[0]==0x0083 if len(resp)>82 else False
        except Exception: return False

    def read_im0(self) -> Optional[Dict]:
        r=self.read_record(0,1,0xAFF0)
        if not r or len(r)<54: return None
        return {"vendor_id":struct.unpack_from("!H",r,0)[0],
                "order_id":r[2:22].decode("ascii",errors="replace").strip("\x00 "),
                "serial_no":r[22:38].decode("ascii",errors="replace").strip("\x00 "),
                "hw_rev":struct.unpack_from("!H",r,38)[0],
                "sw_rev":r[40:44].decode("ascii",errors="replace").strip(),
                "rev_ctr":struct.unpack_from("!H",r,44)[0],
                "im_supported":struct.unpack_from("!H",r,52)[0]}

    def read_im1(self) -> Optional[Dict]:
        r=self.read_record(0,1,0xAFF1)
        if not r or len(r)<54: return None
        return {"tag_function":r[0:32].decode("ascii",errors="replace").strip("\x00 "),
                "tag_location":r[32:54].decode("ascii",errors="replace").strip("\x00 ")}

    def write_im1(self, tag_fn:str, tag_loc:str) -> bool:
        fn=tag_fn.encode("ascii",errors="replace")[:32].ljust(32,b"\x00")
        lc=tag_loc.encode("ascii",errors="replace")[:22].ljust(22,b"\x00")
        return self.write_record(0,1,0xAFF1,struct.pack("!HHbb",0x0021,52,1,0)+fn+lc)

    def read_im2(self) -> Optional[Dict]:
        r=self.read_record(0,1,0xAFF2)
        if not r or len(r)<16: return None
        return {"installation_date":r[0:16].decode("ascii",errors="replace").strip("\x00 ")}

    def write_im2(self, date:str) -> bool:
        dt=date.encode("ascii",errors="replace")[:16].ljust(16,b"\x00")
        return self.write_record(0,1,0xAFF2,struct.pack("!HHbb",0x0022,16,1,0)+dt)

    def read_im3(self) -> Optional[Dict]:
        r=self.read_record(0,1,0xAFF3)
        return {"descriptor":r[0:54].decode("ascii",errors="replace").strip("\x00 ")} if r and len(r)>=54 else None

    def read_im4(self) -> Optional[Dict]:
        r=self.read_record(0,1,0xAFF4)
        return {"signature":r[0:54].decode("ascii",errors="replace").strip("\x00 ")} if r and len(r)>=54 else None

    # ── DCP Set ───────────────────────────────────────────────────────
    def dcp_set_name(self, dev_mac:str, name:str) -> bool:
        if not _SCAPY_OK: return False
        try:
            _SCAPY.sendp(_SCAPY.Ether(dst=dev_mac,type=_PN_ETYPE)
                         /_SCAPY.Raw(load=_dcp_set_name_frame(name)),
                         iface=self._iface,verbose=False); return True
        except Exception: return False

    def dcp_set_ip(self, dev_mac:str, ip:str, subnet:str, gw:str) -> bool:
        if not _SCAPY_OK: return False
        try:
            _SCAPY.sendp(_SCAPY.Ether(dst=dev_mac,type=_PN_ETYPE)
                         /_SCAPY.Raw(load=_dcp_set_ip_frame(ip,subnet,gw)),
                         iface=self._iface,verbose=False); return True
        except Exception: return False

    # ── Timing / info ─────────────────────────────────────────────────
    def timing_stats(self) -> Dict:
        d=self._stats.snap()
        d.update({"cycle_ms":self._cycle_ms,"sc":self._sc,"rr":self._rr,
                  "iops_valid":self._rtbuf.valid,"operate":self._operate})
        return d

    def device_info(self) -> Dict:
        return {"station":self._station,"module_id":self._mod_id,
                "module_name":self._mod_name,"in_len":self._in_len,
                "out_len":self._out_len,"cycle_ms":self._cycle_ms,
                "device_ip":self._conn.dev_ip,
                "device_mac":":".join(f"{b:02X}" for b in self._conn.dev_mac),
                "controller_ip":self._conn.ctrl_ip,"connected":self._conn.ok,
                "operate_mode":self._operate,"forced":len(self._force),
                "alarms":len(self.alarm_log)}

    def csv_header(self) -> str:
        return "timestamp," + ",".join(s.name for s in MODULES[self._mod_id]["in_sigs"])

    def csv_row(self) -> str:
        try: d=self.read_inputs()
        except RuntimeError: return ""
        ts=time.strftime("%Y-%m-%d %H:%M:%S")
        vals=",".join(str(d.get(s.name,"")) for s in MODULES[self._mod_id]["in_sigs"])
        return f"{ts},{vals}"

    def switch_module(self, new_mod_id: int) -> bool:
        """
        Disconnect the current AR and reconnect with a different module profile.
        This is the only way to change which data group (module) is active –
        PROFINET negotiates the data layout at AR setup time, not at runtime.

        Returns True on success.  The controller is reconnected and live data
        resumes on the new module within ~1 second.
        """
        if new_mod_id not in MODULES:
            raise ValueError(f"Module {new_mod_id} not in 1-13.")
        if new_mod_id == self._mod_id and self._conn.ok:
            return True   # already on this module

        # Clean disconnect
        self.disconnect()
        time.sleep(0.5)   # let device release the AR

        # Reconfigure for new module
        m = MODULES[new_mod_id]
        self._mod_id   = new_mod_id
        self._in_len   = m["in"]
        self._out_len  = m["out"]
        self._mod_name = m["name"]
        self._sm_ident = m["ident"]
        self._outbuf   = bytearray(self._out_len)
        self._dirty    = True

        # Clear runtime state
        self._stats  = _Stats()
        self._rtbuf  = _RTBuf()
        self._force.clear()
        self._watches.clear()

        # Reconnect
        self._conn = _Conn()
        self._stop = threading.Event()
        self._capq = queue.SimpleQueue()
        self._almq = queue.SimpleQueue()
        return self.connect()

    def snapshot_all_groups(self) -> Dict[str, Dict[str, Any]]:
        """
        Read every available data group by switching modules one-by-one.
        Returns a dict of {module_name: {signal: value}}.

        NOTE: each switch requires an AR reconnect (~0.5-1 s per group).
        For live real-time use, stay on Module 13 (EIOS) which contains
        the most comprehensive data in a single AR.
        """
        results: Dict[str, Dict[str, Any]] = {}
        original_mod = self._mod_id

        for mid in sorted(MODULES.keys()):
            m = MODULES[mid]
            try:
                if mid != self._mod_id or not self._conn.ok:
                    self.switch_module(mid)
                if self.wait_valid(timeout=5.0):
                    results[m["name"]] = self.read_inputs()
                else:
                    results[m["name"]] = {"error": "IOPS BAD – no data"}
            except Exception as e:
                results[m["name"]] = {"error": str(e)}

        # Restore original module
        if original_mod != self._mod_id:
            try: self.switch_module(original_mod)
            except Exception: pass

        return results

    # ══════════════════════════════════════════════════════════════════
    # Private
    # ══════════════════════════════════════════════════════════════════
    @staticmethod
    def _clamp(sc,rr):
        if sc not in _VALID_SC: sc=min(_VALID_SC,key=lambda x:abs(x-sc))
        if rr not in _VALID_RR: rr=min(_VALID_RR,key=lambda x:abs(x-rr))
        if sc*rr<_MIN_INTERVAL:
            for c in sorted(_VALID_RR):
                if sc*c>=_MIN_INTERVAL: rr=c; break
        return sc,rr

    def _dcp_discover(self) -> Optional[Dict]:
        if not _SCAPY_OK:
            if self._manual_ip: return {"ip":self._manual_ip,"mac":b"\x00"*6}
            return None
        scapy=_SCAPY
        req=_dcp_identify_request(self._station)
        src=self._mac_for()
        hit=threading.Event(); box:Dict={}

        def _cb(pkt):
            raw=bytes(pkt)
            r=_dcp_parse_response(raw[14:])
            if r and r.get("name","").lower()==self._station.lower():
                r["mac"]=raw[6:12]; box.update(r); hit.set()

        for _ in range(3):
            t=threading.Thread(target=lambda: scapy.sniff(
                iface=self._iface,filter="ether proto 0x8892",
                prn=_cb,timeout=self._timeout/3,store=False,
                stop_filter=lambda _:hit.is_set()),daemon=True)
            t.start(); time.sleep(0.1)
            try:
                scapy.sendp(scapy.Ether(dst="01:0e:cf:00:00:00",
                                        src=":".join(f"{b:02X}" for b in src),
                                        type=_PN_ETYPE)/scapy.Raw(load=req),
                            iface=self._iface,verbose=False)
            except Exception: pass
            hit.wait(timeout=self._timeout/3)
            if box: return box
        return None

    def _rpc_connect(self) -> bool:
        payload=_rpc_connect_payload(
            self._conn.ar_uuid,1,self._conn.ctrl_mac,self._conn.ctrl_ip,
            1,1,self._mod_ident,self._sm_ident,
            self._in_len,self._out_len,self._sc,self._rr)
        hdr=_rpc_header(0,0x00,self._next_cid(),self._conn.ar_uuid,len(payload))
        try:
            s=self._rpc_sock(); s.settimeout(self._timeout)
            s.sendto(hdr+payload,(self._conn.dev_ip,_RPC_PORT))
            resp,_=s.recvfrom(65536)
            if len(resp)>1 and resp[1]==0x02:
                self._conn.sess_key=1; return True
            return False
        except Exception: return False

    def _rpc_release(self):
        if not self._rpc_s or not self._conn.dev_ip: return
        hdr=_rpc_header(0,0x01,self._next_cid(),self._conn.ar_uuid)
        try: self._rpc_s.sendto(hdr,(self._conn.dev_ip,_RPC_PORT)); time.sleep(0.1)
        except Exception: pass

    def _rpc_sock(self) -> socket.socket:
        if not self._rpc_s:
            self._rpc_s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            self._rpc_s.bind(("",0))
        return self._rpc_s

    def _next_cid(self) -> int:
        self._conn.cid=(self._conn.cid+1)&0xFFFFFFFF; return self._conn.cid

    def _open_l2(self):
        if not _SCAPY_OK: return
        bpf="ether proto 0x8892"
        if any(self._conn.dev_mac):
            ms=":".join(f"{b:02x}" for b in self._conn.dev_mac)
            if ms!="00:00:00:00:00:00": bpf+=f" and ether src {ms}"
        self._l2s=_SCAPY.conf.L2socket(iface=self._iface,filter=bpf,promisc=False)

    def _close_l2(self):
        with self._l2lk:
            if self._l2s:
                try: self._l2s.close()
                except Exception: pass
                self._l2s=None

    def _rx_loop(self):
        _thr_high()
        while not self._stop.is_set():
            try:
                pkt=self._l2s.recv(65535)
                if pkt is None: continue
                raw=bytes(pkt)
                if len(raw)>16:
                    fid=struct.unpack_from("!H",raw,14)[0]
                    if _ALARM_LO<=fid<=_ALARM_HI: self._almq.put_nowait(raw)
                    else: self._capq.put_nowait(raw)
            except OSError:
                if not self._stop.is_set(): pass
                break
            except Exception: pass

    def _dec_loop(self):
        _thr_high()
        while not self._stop.is_set():
            try: raw=self._capq.get(timeout=0.05)
            except queue.Empty: continue
            ns=time.time_ns()
            try:
                fr=_parse_rt_frame(raw,self._in_len,ns)
                if fr and fr.frame_id==self._conn.fid_in:
                    sigs=decode_inputs(self._mod_id,fr.payload)
                    self._rtbuf.put(fr,sigs)
                    self._stats.record(ns)
                    self._eval_watches(sigs)
            except Exception: pass

    def _tx_loop(self):
        _thr_high()
        dst=":".join(f"{b:02x}" for b in self._conn.dev_mac)
        src=":".join(f"{b:02x}" for b in self._conn.ctrl_mac)
        cyc=0; nxt=time.perf_counter()+self._cycle_s
        while not self._stop.is_set():
            rem=nxt-time.perf_counter()
            if rem>0.002: time.sleep(rem-0.002)
            while time.perf_counter()<nxt and not self._stop.is_set(): pass
            if self._stop.is_set(): break
            nxt+=self._cycle_s
            if time.perf_counter()-nxt>self._cycle_s: nxt=time.perf_counter()+self._cycle_s
            cyc=(cyc+1)&0xFFFF; self._tx_frame(dst,src,cyc)

    def _tx_frame(self, dst, src, cyc):
        if not _SCAPY_OK: return
        if self._dirty:
            with self._outlk: out=bytearray(self._outbuf)
            with self._flk:
                for n,v in self._force.items():
                    s=next((x for x in MODULES[self._mod_id]["out_sigs"] if x.name==n),None)
                    if s: out=s.encode(v,out)
            self._dirty=False
            db=bytes(int(x,16) for x in dst.split(":"))
            sb=bytes(int(x,16) for x in src.split(":"))
            self._frame_pre=(db+sb+struct.pack("!HH",_PN_ETYPE,self._conn.fid_out)
                             +bytes(out)+bytes([_IOPS_GOOD]))
        ds=_DS_OPERATE if self._operate else _DS_STOP
        raw=self._frame_pre+struct.pack("!H",cyc)+bytes([ds,0x00])
        with self._l2lk:
            if self._l2s and not self._stop.is_set():
                try: self._l2s.send(_SCAPY.Ether(dst=dst,src=src,type=_PN_ETYPE)
                                    /_SCAPY.Raw(load=raw[14:]))
                except Exception: pass

    def _alm_loop(self):
        while not self._stop.is_set():
            try: raw=self._almq.get(timeout=0.1)
            except queue.Empty: continue
            try:
                ev=self._decode_alarm(raw)
                if ev:
                    self.alarm_log.append(ev)
                    for cb in self._alarm_cbs:
                        try: cb(ev)
                        except Exception: pass
            except Exception: pass

    def _decode_alarm(self, raw) -> Optional[AlarmEvent]:
        """
        Parse PROFINET AlarmNotification PDU.
        Layout (IEC 61158-6-10 Table 372, starting after 14-byte ETH header):
          pos 16: AlarmType(2)
          pos 18: API(4)
          pos 22: Slot(2)
          pos 24: Subslot(2)
          pos 26: AlarmSpecifier(2)
          pos 28: UserStructureIdentifier(2)
          pos 30: UserData[0..1] = ErrorType(2)  for ChannelDiag alarms
        """
        try:
            pos = 16
            at   = struct.unpack_from("!H", raw, pos)[0]; pos += 2  # AlarmType
            pos += 4                                                  # API
            slot = struct.unpack_from("!H", raw, pos)[0]; pos += 2  # Slot
            sub  = struct.unpack_from("!H", raw, pos)[0]; pos += 2  # Subslot
            pos += 2                                                  # AlarmSpecifier
            pos += 2                                                  # UserStructureIdentifier
            # ErrorType is first 2 bytes of UserData
            et   = struct.unpack_from("!H", raw, pos)[0] if len(raw) >= pos + 2 else 0
            return AlarmEvent(
                ts=time.time(), alarm_type=at,
                alarm_name=ALARM_NAMES.get(at, f"Alarm0x{at:04X}"),
                slot=slot, subslot=sub, error_type=et,
                text=DIAG_TEXTS.get(et, f"ErrorType 0x{et:04X}"),
                raw=raw,
            )
        except Exception:
            return None

    def _recon_loop(self):
        time.sleep(max(self._rc_dly,3.0))
        while not self._stop.is_set():
            time.sleep(self._rc_dly)
            if self._stop.is_set(): break
            fr=self._rtbuf.frame()
            if fr is None: continue
            age_ms=(time.time_ns()-fr.ts_ns)/1e6
            if age_ms>self._cycle_ms*8:
                self._conn.ok=False
                for _ in range(5):
                    if self._stop.is_set(): return
                    try:
                        self._close_l2()
                        if self._rpc_s:
                            try: self._rpc_s.close()
                            except Exception: pass
                            self._rpc_s=None
                        self._conn.ar_uuid=uuid.uuid4()
                        inf=self._dcp_discover()
                        if inf: self._conn.dev_ip=inf["ip"]; self._conn.dev_mac=inf["mac"]
                        if self._rpc_connect():
                            self._open_l2(); self._conn.ok=True; break
                    except Exception: pass
                    time.sleep(self._rc_dly)

    def _local_addr(self) -> Tuple[str,bytes]:
        try:
            import netifaces  # type: ignore
            for name in netifaces.interfaces():
                if self._iface.lower() in name.lower():
                    a=netifaces.ifaddresses(name)
                    ip4=a.get(netifaces.AF_INET); lnk=a.get(netifaces.AF_LINK)
                    if ip4 and lnk:
                        return (ip4[0]["addr"],
                                bytes.fromhex(lnk[0]["addr"].replace(":","").replace("-","")))
        except ImportError: pass
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close()
        except Exception: ip="127.0.0.1"
        return ip,b"\x00"*6

    def _mac_for(self) -> bytes:
        try:
            import netifaces  # type: ignore
            for name in netifaces.interfaces():
                if self._iface.lower() in name.lower():
                    lnk=netifaces.ifaddresses(name).get(netifaces.AF_LINK)
                    if lnk: return bytes.fromhex(lnk[0]["addr"].replace(":","").replace("-",""))
        except Exception: pass
        return uuid.getnode().to_bytes(6,"big")


# ══════════════════════════════════════════════════════════════════════
# PART 4 — TERMINAL UI
# ══════════════════════════════════════════════════════════════════════

W   = 66
CFG = Path(__file__).parent / "tesys_tera_config.json"
DEF = {"iface":"Ethernet","station":"tesys-tera-pn","module_id":1,
       "sc":32,"rr":16,"timeout":10.0,"device_ip":"","auto_recon":True}

_cfg = {**DEF, **(json.loads(CFG.read_text()) if CFG.exists() else {})}
_g: Optional[Controller] = None   # global controller

def _save(): CFG.write_text(json.dumps(_cfg, indent=2))

# ── Colour helpers ────────────────────────────────────────────────────
_COL = sys.stdout.isatty()
def _c(code,t): return f"\033[{code}m{t}\033[0m" if _COL else t
def G(t):  return _c("32",t)   # green
def R(t):  return _c("31",t)   # red
def Y(t):  return _c("33",t)   # yellow
def C(t):  return _c("36",t)   # cyan
def B(t):  return _c("1", t)   # bold
def D(t):  return _c("2", t)   # dim
def M(t):  return _c("35",t)   # magenta

def clr():
    os.system("cls" if os.name=="nt" else "clear")

def rule(c="─"): print(D(c*W))

def _hdr(title, sub=""):
    print(B(C("╔"+"═"*(W-2)+"╗")))
    def _row(s): print(B(C("║"))+" "+B(s.center(W-4))+" "+B(C("║")))
    _row(title)
    if sub: _row(sub)
    print(B(C("╚"+"═"*(W-2)+"╝")))

def _ask(msg, default=None):
    suf=f" [{default}]" if default is not None else ""
    try:
        v=input(C(f"  → {msg}{suf}: ")).strip()
        return v if v else (str(default) if default is not None else "")
    except (KeyboardInterrupt,EOFError):
        print(); return str(default) if default is not None else ""

def _confirm(msg): return _ask(msg+" (yes/no)","no").lower()=="yes"

def _kv(k,v,u="",w=32):
    print(f"  {C(f'{k:<{w}}')} {v}{D('  '+u) if u else ''}")

def _hexdump(data, cols=16):
    for i in range(0,len(data),cols):
        c=data[i:i+cols]; h=" ".join(f"{b:02X}" for b in c)
        a="".join(chr(b) if 32<=b<127 else "." for b in c)
        print(f"  {D(f'{i:04X}  ')}{h:<{cols*3}}  {D(a)}")


def _get_ctrl() -> Optional[Controller]:
    """Return connected controller or attempt to connect."""
    global _g
    if _g and _g.connected: return _g
    print()
    print(C("  Connecting …"))
    try:
        _g = Controller(
            iface=_cfg["iface"], station=_cfg["station"],
            mod_id=int(_cfg["module_id"]),
            sc=int(_cfg["sc"]), rr=int(_cfg["rr"]),
            timeout=float(_cfg["timeout"]),
            auto_recon=bool(_cfg.get("auto_recon",True)),
        )
        if _cfg.get("device_ip"):
            _g.set_device_ip(_cfg["device_ip"])
        _g.connect()
        print(G("  ✓ Connected") + D(f"  {_g._conn.dev_ip}  "
              f"Cycle {_g.cycle_ms:.0f} ms  "
              f"Module {_g._mod_id}: {_g._mod_name}"))
        return _g
    except Exception as e:
        print(R(f"  ✗ {e}")); _g=None; return None


def _disconnect():
    global _g
    if _g:
        try: _g.disconnect()
        except Exception: pass
        _g=None


def _status_bar():
    global _g
    if _g and _g.connected:
        fr   = _g._rtbuf.frame()
        iops = G("IOPS:GOOD") if (fr and fr.provider_ok) else R("IOPS:BAD ")
        mode = G("OPERATE") if _g.is_operate else Y("STOP   ")
        st   = _g.timing_stats()
        alms = len(_g.alarm_log); ft=len(_g.force_table())
        frms = st.get("total",0)
        extra = (R(f" ⚠{alms}ALM") if alms else "")+(Y(f" ⚡{ft}FRC") if ft else "")
        avg_s = D(f"{frms}fr  {st.get('avg_ms',0):.1f}ms avg")
        print(G("  ● ") + D(f"{_g._conn.dev_ip}") +
              f"  {mode}  {iops}  {avg_s}{extra}")
    else:
        print(D("  ○ Not connected  (auto-connects on first operation)"))


# ══════════════════════════════════════════════════════════════════════
# ALL ACTIONS  (flat – no sub-menus, each function is one screen)
# ══════════════════════════════════════════════════════════════════════

def _dashboard():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    if not ctrl.wait_valid(8.0): print(R("  IOPS BAD")); _ask("Press Enter"); return
    try: ivl=float(_ask("Refresh interval seconds","1.0"))
    except ValueError: ivl=1.0
    try:
        while True:
            clr(); _hdr("Live Dashboard", time.strftime("%H:%M:%S"))
            try: data=ctrl.read_inputs(); fr=ctrl._rtbuf.frame()
            except RuntimeError as e: print(R(f"  {e}")); time.sleep(ivl); continue

            bools=[(k,v) for k,v in sorted(data.items()) if isinstance(v,bool)]
            meas =[(k,v) for k,v in sorted(data.items())
                   if not isinstance(v,bool) and isinstance(v,(int,float))]

            print(); print(B("  STATUS")); rule("·")
            half=len(bools)//2+1
            for (ka,va),(kb,vb) in zip(bools[:half],bools[half:]+[("",None)]):
                sa=G("●ON") if va else D("○off")
                sb=(G("●ON") if vb else D("○off")) if kb else "   "
                print(f"  {sa} {ka:<32}  {sb} {kb}")

            print(); print(B("  MEASUREMENTS")); rule("·")
            smap={s.name:s for s in MODULES[ctrl._mod_id]["in_sigs"]}
            for name,val in meas:
                sig=smap.get(name); unit=sig.unit if sig else ""
                bar=""; 
                if "pct" in name.lower() and 0<=val<=100:
                    f=int(val/5); bar="  ["+G("█"*f)+D("░"*(20-f))+"]"
                print(f"  {C(f'{name:<44}')} {val:>9.3f}  {D(unit)}{bar}")

            if fr:
                st=ctrl.timing_stats()
                iops=G("GOOD") if fr.provider_ok else R("BAD")
                print(); print(D(f"  IOPS={iops}  CC={fr.cycle_counter}  "
                    f"Min={st.get('min_ms','?')}ms  Max={st.get('max_ms','?')}ms  "
                    f"Avg={st.get('avg_ms',0):.1f}ms"))
            alms=len(ctrl.alarm_log)
            if alms: print(R(f"  ⚠  {alms} alarm(s) logged  (option 11)"))
            ft=ctrl.force_table()
            if ft: print(Y(f"  ⚡  Forced: {list(ft.keys())}"))
            print(D("  Ctrl+C to stop"))
            time.sleep(ivl)
    except KeyboardInterrupt:
        print(); print(G("  Dashboard stopped.")); _ask("Press Enter")


def _read_one():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    if not ctrl.wait_valid(8.0): print(R("  IOPS BAD")); _ask("Press Enter"); return
    isigs=MODULES[ctrl._mod_id]["in_sigs"]
    bsigs=[s for s in isigs if s.enc=="BIT"]
    msigs=[s for s in isigs if s.enc!="BIT"]
    all_s=bsigs+msigs
    clr(); _hdr("Read a Signal")
    print(); print(B("  Status bits:"))
    for i,s in enumerate(bsigs,1): print(f"    {D(f'{i:>3}')}  {s.name}")
    print(); print(B("  Measurements:"))
    for i,s in enumerate(msigs,len(bsigs)+1):
        print(f"    {D(f'{i:>3}')}  {s.name:<44} {D(s.unit or '')}")
    print(); rule("·")
    ch=_ask("Signal name or number  (0=cancel)")
    if not ch or ch=="0": return
    name=""
    try:
        idx=int(ch)-1
        if 0<=idx<len(all_s): name=all_s[idx].name
    except ValueError: name=ch
    if not name: print(R("  Not found.")); _ask("Press Enter"); return
    try:
        val=ctrl.read_signal(name)
        sig=next((s for s in isigs if s.name==name),None)
        print(); print(f"  {C(name)}")
        if isinstance(val,bool): print(f"  {G('ON  (True)') if val else D('off (False)')}")
        else: print(f"  {B(f'{val:.4f}')}  {D(sig.unit if sig else '')}")
    except KeyError as e: print(R(f"  {e}"))
    _ask("\n  Press Enter")


def _run_fwd():
    ctrl=_get_ctrl()
    if ctrl: ctrl.cmd_run_fwd(); print(G("  ✓ Run Forward sent."))
    _ask("Press Enter")

def _run_rev():
    ctrl=_get_ctrl()
    if ctrl: ctrl.cmd_run_rev(); print(G("  ✓ Run Reverse sent."))
    _ask("Press Enter")

def _stop_motor():
    ctrl=_get_ctrl()
    if ctrl: ctrl.cmd_stop(); print(G("  ✓ Stop sent."))
    _ask("Press Enter")

def _fault_reset():
    ctrl=_get_ctrl()
    if ctrl: ctrl.cmd_reset(); print(G("  ✓ Fault Reset sent."))
    _ask("Press Enter")

def _estop():
    ctrl=_get_ctrl()
    if ctrl and _confirm("Confirm EMERGENCY STOP"):
        ctrl.cmd_estop(); print(G("  ✓ Emergency Stop sent."))
    _ask("Press Enter")


def _write_output():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    osigs=MODULES[ctrl._mod_id]["out_sigs"]
    clr(); _hdr("Write Output Signal")
    print()
    for i,s in enumerate(osigs,1):
        loc=(f"byte {s.byte_off} bit {s.bit}"if s.enc=="BIT"else f"byte {s.byte_off}")
        print(f"  {D(f'{i:>3}')}  {s.name:<44} {D(loc)}")
    print(); rule("·")
    ch=_ask("Signal name or number  (0=cancel)")
    if not ch or ch=="0": return
    name=""
    try:
        idx=int(ch)-1
        if 0<=idx<len(osigs): name=osigs[idx].name
    except ValueError: name=ch
    sig=next((s for s in osigs if s.name==name),None)
    if not sig: print(R("  Not found.")); _ask("Press Enter"); return
    if sig.enc=="BIT":
        v=_ask(f"Value for {C(name)} (true/false)","true")
        val=v.lower() in ("true","1","yes","on")
    else:
        try: val=float(_ask(f"Value for {C(name)}","0"))
        except ValueError: print(R("  Invalid.")); _ask("Press Enter"); return
    try: ctrl.write(name,val); print(G(f"  ✓ {name} = {val}"))
    except Exception as e: print(R(f"  ✗ {e}"))
    _ask("Press Enter")


def _operate_stop():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    cur=G("OPERATE") if ctrl.is_operate else Y("STOP")
    print(); print(f"  Current mode: {cur}")
    print(f"  {C('1')}  Set OPERATE  (DataStatus RUN=1, device outputs active)")
    print(f"  {C('2')}  Set STOP     (DataStatus RUN=0, device applies failsafe)")
    print(f"  {C('0')}  Cancel")
    ch=_ask("Choose")
    if ch=="1":   ctrl.set_operate(True);  print(G("  ✓ OPERATE mode set."))
    elif ch=="2": ctrl.set_operate(False); print(Y("  ✓ STOP mode set."))
    _ask("Press Enter")


def _force_table():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    ft=ctrl.force_table()
    osigs=MODULES[ctrl._mod_id]["out_sigs"]
    clr(); _hdr(f"IO Force Table  ({len(ft)} active)")
    print()
    if ft:
        print(B("  Active forces:")); rule("·")
        for n,v in sorted(ft.items()):
            print(f"  {Y('⚡')} {C(n):<46} = {B(str(v))}")
        print()
    print(f"  {C('F')}  Force a signal   {C('C')}  Clear one force   "
          f"{C('A')}  Clear all   {C('0')}  Back")
    rule("·"); ch=_ask("Choose").upper()
    if ch=="F":
        print()
        for i,s in enumerate(osigs,1):
            print(f"  {D(f'{i:>3}')}  {s.name}")
        print(); sc=_ask("Signal name or number")
        name=""
        try:
            idx=int(sc)-1
            if 0<=idx<len(osigs): name=osigs[idx].name
        except ValueError: name=sc
        sig=next((s for s in osigs if s.name==name),None)
        if not sig: print(R("  Not found.")); _ask("Press Enter"); return
        if sig.enc=="BIT":
            v=_ask(f"Force {C(name)} to (true/false)","true")
            val=v.lower() in("true","1","yes","on")
        else:
            try: val=float(_ask(f"Force {C(name)} to","0"))
            except ValueError: print(R("  Invalid.")); _ask("Press Enter"); return
        ctrl.force_set(name,val); print(G(f"  ✓ Force SET: {name} = {val}"))
        print(Y("  Active until you clear it!"))
    elif ch=="C":
        names=sorted(ft.keys())
        if not names: print(Y("  No active forces.")); _ask("Press Enter"); return
        for i,n in enumerate(names,1): print(f"  {C(str(i))}  {n}  = {ft[n]}")
        sc=_ask("Signal number or name")
        name=""
        try:
            idx=int(sc)-1
            if 0<=idx<len(names): name=names[idx]
        except ValueError: name=sc
        if name: ctrl.force_clear(name); print(G(f"  ✓ Cleared: {name}"))
    elif ch=="A":
        if _confirm("Clear ALL forces"):
            ctrl.force_clear_all(); print(G("  ✓ All forces cleared."))
    _ask("Press Enter")


def _alarms():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    log=ctrl.alarm_log
    clr(); _hdr(f"Alarm Log  ({len(log)} entries)")
    if not log: print(); print(D("  No alarms logged yet."))
    else:
        print(); rule("·")
        print(f"  {'Time':<12} {'Type':<22} {'Slot':>4} {'ErrCode':>8}  Text")
        rule("·")
        for ev in list(reversed(log))[:40]:
            ts=datetime.fromtimestamp(ev.ts).strftime("%H:%M:%S.%f")[:12]
            col=R if "Trip" in ev.text else Y
            print(f"  {D(ts)}  {col(f'{ev.alarm_name:<22}')}  "
                  f"{ev.slot:>4}  {D(f'0x{ev.error_type:04X}'):>8}  {ev.text}")
    print()
    print(f"  {C('L')} Live watch  {C('E')} Export to alarms.txt  "
          f"{C('X')} Clear log  {C('0')} Back")
    rule("·"); ch=_ask("Choose").upper()
    if ch=="L":
        print(); print(D("  Watching for alarms – Ctrl+C to stop"))
        got=[]
        def _cb(ev):
            ts=datetime.fromtimestamp(ev.ts).strftime("%H:%M:%S")
            col=R if "Trip" in ev.text else Y
            print(f"\n  {D(ts)}  {col(ev.alarm_name)}  "
                  f"slot={ev.slot}  {ev.text}")
            got.append(ev)
        ctrl.alarm_cb_add(_cb)
        try:
            while True: time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        try: ctrl._alarm_cbs.remove(_cb)
        except ValueError: pass
        print(); print(G(f"  {len(got)} alarm(s) received."))
    elif ch=="E":
        path=Path(__file__).parent/"alarms.txt"
        with open(path,"w") as f:
            f.write("Timestamp,AlarmType,AlarmName,Slot,Subslot,ErrorCode,Text\n")
            for ev in log:
                ts=datetime.fromtimestamp(ev.ts).strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{ts},{ev.alarm_type},{ev.alarm_name},{ev.slot},"
                        f"{ev.subslot},0x{ev.error_type:04X},{ev.text}\n")
        print(G(f"  ✓ Exported {len(log)} entries to {path}"))
    elif ch=="X":
        if _confirm("Clear alarm log"): ctrl.alarm_log.clear(); print(G("  ✓ Cleared."))
    _ask("Press Enter")


def _watchlist():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    wl=ctrl.watch_list()
    clr(); _hdr(f"Watch List  ({len(wl)} active)")
    if wl:
        print(); rule("·")
        print(f"  {'Signal':<44} {'Cond':<4} {'Threshold':<12} {'Last':<12} Trig")
        rule("·")
        for w in wl:
            trig=R("YES") if w["triggered"] else G("no")
            lv=f"{w['last']:.3f}" if isinstance(w['last'],(int,float)) else str(w['last'])
            print(f"  {C(w['name']):<44} {w['cond']:<4} "
                  f"{str(w['thr']):<12} {lv:<12} {trig}")
    print()
    print(f"  {C('A')} Add watch  {C('R')} Remove watch  {C('0')} Back")
    rule("·"); ch=_ask("Choose").upper()
    if ch=="A":
        print()
        msigs=[s for s in MODULES[ctrl._mod_id]["in_sigs"] if s.enc!="BIT"]
        for i,s in enumerate(msigs,1):
            print(f"  {D(f'{i:>3}')}  {s.name:<44} {D(s.unit or '')}")
        print(); sc=_ask("Signal name or number")
        name=""
        try:
            idx=int(sc)-1
            if 0<=idx<len(msigs): name=msigs[idx].name
        except ValueError: name=sc
        if not name or not any(s.name==name for s in MODULES[ctrl._mod_id]["in_sigs"]):
            print(R("  Not found.")); _ask("Press Enter"); return
        print(D("  Conditions: gt  lt  ge  le  eq  ne"))
        cond=_ask("Condition","gt")
        try: thr=float(_ask("Threshold","0.0"))
        except ValueError: print(R("  Invalid.")); _ask("Press Enter"); return
        ctrl.watch_add(name,cond,thr); print(G(f"  ✓ Watch added: {name} {cond} {thr}"))
    elif ch=="R":
        wl=ctrl.watch_list()
        if not wl: print(Y("  No watches.")); _ask("Press Enter"); return
        names=[w["name"] for w in wl]
        for i,n in enumerate(names,1): print(f"  {C(str(i))}  {n}")
        sc=_ask("Number or name")
        name=""
        try:
            idx=int(sc)-1
            if 0<=idx<len(names): name=names[idx]
        except ValueError: name=sc
        if name: ctrl.watch_remove(name); print(G(f"  ✓ Removed: {name}"))
    _ask("Press Enter")


def _signal_map():
    clr(); _hdr("Signal Map – All 13 Modules")
    print()
    for mid,m in sorted(MODULES.items()):
        ident_s = D(f"0x{m['ident']:08X}")
        print(f"  {C(str(mid))}  {m['name']:<30} "
              f"IN={m['in']:>3}B  OUT={m['out']:>2}B  "
              f"Ident={ident_s}")
    print()
    ch=_ask("Module number for full signal list (0=back)")
    if not ch or ch=="0": return
    try: mid=int(ch)
    except ValueError: return
    if mid not in MODULES: print(R("  Not found.")); _ask("Press Enter"); return
    m=MODULES[mid]
    clr(); _hdr(f"Module {mid}: {m['name']}")
    sm_id_s = C(f"0x{m['ident']:08X}")
    print(f"\n  SubmoduleIdent = {sm_id_s}  "
          f"IN={m['in']}B  OUT={m['out']}B\n")
    print(B("  INPUTS")); rule("·")
    print(f"  {'Name':<44} {'Enc':<7} {'Location':<22} {'Scale':<7} Unit")
    rule("·")
    for s in m["in_sigs"]:
        loc=(f"byte {s.byte_off} bit {s.bit}" if s.enc=="BIT"
             else f"byte {s.byte_off}")
        sc=str(s.scale) if s.scale!=1.0 else "–"
        print(f"  {s.name:<44} {s.enc:<7} {loc:<22} {sc:<7} {s.unit or '–'}")
    if m["out_sigs"]:
        print(); print(B("  OUTPUTS")); rule("·")
        print(f"  {'Name':<44} {'Enc':<7} Location")
        rule("·")
        for s in m["out_sigs"]:
            loc=(f"byte {s.byte_off} bit {s.bit}" if s.enc=="BIT"
                 else f"byte {s.byte_off}")
            print(f"  {s.name:<44} {s.enc:<7} {loc}")
    print(); _ask("Press Enter")


def _records():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    clr(); _hdr("Acyclic Record Data")
    print()
    records=[
        ("IM0 – Device identity",   0xAFF0,0,1),
        ("IM1 – Tag / Location",    0xAFF1,0,1),
        ("IM2 – Installation date", 0xAFF2,0,1),
        ("IM3 – Descriptor",        0xAFF3,0,1),
        ("IM4 – Signature",         0xAFF4,0,1),
        ("Real identification",     0xF840,0,1),
        ("Custom index",            None,None,None),
    ]
    for i,(lbl,idx,*_) in enumerate(records,1):
        print(f"  {C(str(i))}  {lbl:<30} {D(f'Idx 0x{idx:04X}' if idx else 'enter manually')}")
    print(f"  {C('0')}  Back"); rule("·")
    ch=_ask("Choose")
    if not ch or ch=="0": return
    try: ridx=int(ch)-1
    except ValueError: return
    if not (0<=ridx<len(records)): return
    lbl,index,slot,subslot=records[ridx]
    if index is None:
        try:
            index=int(_ask("Index (hex, e.g. 0xAFF0)"),0)
            slot=int(_ask("Slot","0")); subslot=int(_ask("Subslot","1"))
        except ValueError: _ask("Press Enter"); return
    print(); print(D(f"  Reading {lbl} …"))
    raw=ctrl.read_record(slot,subslot,index)
    if raw is None: print(R("  ✗ Read failed (timeout or device error).")); _ask("Press Enter"); return
    print(G(f"  ✓ {len(raw)} bytes received\n"))

    # Structured decode for known records
    if index==0xAFF0:
        d=ctrl.read_im0()
        if d:
            rule("·")
            _kv("Vendor ID",     f"0x{d['vendor_id']:04X}")
            _kv("Order number",  d["order_id"])
            _kv("Serial number", d["serial_no"])
            _kv("HW revision",   d["hw_rev"])
            _kv("SW revision",   d["sw_rev"])
            _kv("IM supported",  f"0x{d['im_supported']:04X}")
    elif index==0xAFF1:
        d=ctrl.read_im1()
        if d:
            rule("·")
            _kv("Tag function",  d["tag_function"] or "(empty)")
            _kv("Tag location",  d["tag_location"]  or "(empty)")
            print()
            if _confirm("Write new IM1 values?"):
                fn=_ask("Tag function (max 32 chars)","")
                lc=_ask("Tag location (max 22 chars)","")
                if ctrl.write_im1(fn,lc): print(G("  ✓ IM1 written."))
                else: print(R("  ✗ Write failed."))
    elif index==0xAFF2:
        d=ctrl.read_im2()
        if d:
            rule("·")
            _kv("Installation date", d["installation_date"] or "(empty)")
            print()
            if _confirm("Write new installation date?"):
                dt=_ask("Date (e.g. 2025-01-15 08:30)","")
                if ctrl.write_im2(dt): print(G("  ✓ IM2 written."))
                else: print(R("  ✗ Write failed."))
    else:
        # Interactive Hex Editor for Custom Indexes
        edit_buf = bytearray(raw)
        while True:
            clr(); _hdr(f"Custom Index 0x{index:04X}  (Slot {slot}, Subslot {subslot})")
            print(); print(D(f"  Read {len(edit_buf)} bytes successfully."))
            print(B("  Current Data:")); rule("·")
            _hexdump(edit_buf)
            print(); rule("·")
            print(f"  {C('E')}  Edit a byte    {C('W')}  Write back to device    {C('0')}  Back / Cancel")
            
            ch2 = _ask("Choose action").upper()
            if ch2 == "0" or ch2 == "":
                break
            elif ch2 == "E":
                off_str = _ask(f"Byte offset to edit (0 to {len(edit_buf)-1}, e.g. 4 or 0x04)")
                if not off_str: continue
                try:
                    off = int(off_str, 16) if off_str.startswith("0x") else int(off_str)
                    if not (0 <= off < len(edit_buf)):
                        print(R(f"  Offset out of range. Max is {len(edit_buf)-1}.")); time.sleep(1.5); continue
                except ValueError:
                    print(R("  Invalid offset.")); time.sleep(1.5); continue
                
                val_str = _ask(f"New hex value for offset {off} (e.g., FF or 0A)")
                if not val_str: continue
                try:
                    val = int(val_str, 16)
                    if not (0 <= val <= 255):
                        print(R("  Value must be 00 to FF.")); time.sleep(1.5); continue
                    edit_buf[off] = val
                except ValueError:
                    print(R("  Invalid hex value.")); time.sleep(1.5); continue
            elif ch2 == "W":
                print(); print(D(f"  Writing {len(edit_buf)} bytes to 0x{index:04X} ..."))
                success = ctrl.write_record(slot, subslot, index, bytes(edit_buf))
                if success:
                    print(G("  ✓ Write successful!")); _ask("Press Enter")
                    break
                else:
                    print(R("  ✗ Write failed (device rejected it or timeout)."))
                    print(Y("    Note: Many device indexes are read-only or expect exact structures.")); _ask("Press Enter")
        return # Skip the final generic "Press Enter" of the parent function


def _dcp_tools():
    clr(); _hdr("DCP Tools – Device Commissioning")
    print()
    print(f"  {C('1')}  Discover all PROFINET devices on network")
    print(f"  {C('2')}  Set station name  (DCP Set)")
    print(f"  {C('3')}  Set IP address    (DCP Set)")
    print(f"  {C('0')}  Back")
    rule("·"); ch=_ask("Choose")

    if ch=="1":
        print(); print(D("  Scanning for 5 seconds …"))
        if not _SCAPY_OK: print(R("  Scapy/Npcap not available.")); _ask("Press Enter"); return
        from collections import defaultdict
        found: List[Dict]=[]
        lk=threading.Lock()
        def _cb(pkt):
            raw=bytes(pkt)
            r=_dcp_parse_response(raw[14:])
            if r:
                r["mac"]=":".join(f"{b:02X}" for b in raw[6:12])
                with lk:
                    if not any(x.get("mac")==r["mac"] for x in found):
                        found.append(r)
                        print(); print(G(f"  ● {r.get('name','?')}"))
                        print(D(f"    IP={r.get('ip','?')}  MAC={r.get('mac','?')}  "
                              f"VID=0x{r.get('vendor_id',0):04X}  DID=0x{r.get('device_id',0):04X}"))
        req=_dcp_identify_request("",1)
        t=threading.Thread(target=lambda: _SCAPY.sniff(
            iface=_cfg["iface"],filter="ether proto 0x8892",
            prn=_cb,timeout=5.0,store=False),daemon=True)
        t.start(); time.sleep(0.2)
        try:
            _SCAPY.sendp(_SCAPY.Ether(dst="01:0e:cf:00:00:00",type=_PN_ETYPE)
                         /_SCAPY.Raw(load=req),iface=_cfg["iface"],verbose=False)
        except Exception as e: print(R(f"  Send error: {e}"))
        t.join(); print()
        if found: print(G(f"  Found {len(found)} device(s)."))
        else: print(Y("  No devices responded."))

    elif ch in ("2","3"):
        mac=_ask("Target device MAC  (AA:BB:CC:DD:EE:FF)")
        if not mac: _ask("Press Enter"); return
        dummy=Controller(iface=_cfg["iface"])
        if ch=="2":
            name=_ask("New station name")
            if dummy.dcp_set_name(mac,name): print(G(f"  ✓ DCP Set Name → '{name}'"))
            else: print(R("  ✗ Failed."))
        else:
            ip=_ask("New IP","192.168.1.100")
            sn=_ask("Subnet","255.255.255.0")
            gw=_ask("Gateway","192.168.1.1")
            if dummy.dcp_set_ip(mac,ip,sn,gw): print(G(f"  ✓ DCP Set IP → {ip}"))
            else: print(R("  ✗ Failed."))
    _ask("Press Enter")


def _diagnostics():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    if not ctrl.wait_valid(8.0): print(R("  IOPS BAD")); _ask("Press Enter"); return
    print(D("  Collecting 3 s of data …")); time.sleep(3.0)
    clr(); _hdr("RT Diagnostics")
    st=ctrl.timing_stats(); fr=ctrl._rtbuf.frame()
    print(); print(B("  Timing")); rule("·")
    _kv("Target cycle",     f"{st['cycle_ms']:.1f} ms")
    _kv("Min interval",     f"{st.get('min_ms','?')} ms")
    _kv("Max interval",     f"{st.get('max_ms','?')} ms")
    _kv("Rolling avg",      f"{st.get('avg_ms',0):.3f} ms")
    _kv("Total frames",     str(st["total"]))
    _kv("SendClock",        str(st["sc"]))
    _kv("ReductionRatio",   str(st["rr"]))
    mn=st.get("min_ms") or 0; mx=st.get("max_ms") or 0; jit=mx-mn
    print()
    if jit>st["cycle_ms"]*0.5: print(Y(f"  ⚠ Jitter {jit:.1f} ms is >50% of cycle – check CPU load."))
    else: print(G(f"  ✓ Jitter {jit:.1f} ms – acceptable."))
    print(); print(B("  Frame Status")); rule("·")
    if fr:
        ds=fr.data_status
        _kv("IOPS",          f"0x{fr.iops:02X}  {G('GOOD') if fr.provider_ok else R('BAD')}")
        _kv("IOCS",          f"0x{fr.iocs:02X}  {G('GOOD') if fr.consumer_ok else R('BAD')}")
        _kv("DataStatus",    f"0x{ds:02X}")
        print(f"    RUN bit       = {G('1  OPERATE') if ds&0x01 else Y('0  STOP')}")
        print(f"    DataValid     = {G('1') if ds&0x04 else R('0')}")
        print(f"    Problem       = {R('1  FAULT') if ds&0x10 else G('0  OK')}")
        _kv("CycleCounter",  str(fr.cycle_ctr))
    print(); print(B("  Connection")); rule("·")
    inf=ctrl.device_info()
    _kv("Device IP",        inf["device_ip"])
    _kv("Device MAC",       inf["device_mac"])
    _kv("Controller IP",    inf["controller_ip"])
    _kv("Station name",     inf["station"])
    _kv("Module",           f"{inf['module_id']} – {inf['module_name']}")
    _kv("Operate mode",     G("OPERATE") if inf["operate_mode"] else Y("STOP"))
    _kv("Auto-reconnect",   G("ON") if ctrl._auto_rc else D("off"))
    _kv("Active forces",    str(inf["forced"]))
    _kv("Alarms logged",    str(inf["alarms"]))
    print(); _ask("Press Enter")


def _csv_export():
    ctrl=_get_ctrl()
    if not ctrl: _ask("Press Enter"); return
    if not ctrl.wait_valid(8.0): print(R("  IOPS BAD")); _ask("Press Enter"); return
    try: n=int(_ask("Number of samples","10"))
    except ValueError: n=10
    try: ivl=float(_ask("Interval between samples (s)","1.0"))
    except ValueError: ivl=1.0
    path=Path(__file__).parent/"profinet_data.csv"
    print()
    with open(path,"w",newline="") as f:
        f.write(ctrl.csv_header()+"\n")
        for i in range(n):
            row=ctrl.csv_row()
            if row: f.write(row+"\n"); f.flush()
            print(f"  {D(str(i+1).rjust(3))}  {row[:70]}")
            time.sleep(ivl)
    print(); print(G(f"  ✓ {n} rows saved to {path}")); _ask("Press Enter")


def _decode_hex():
    clr(); _hdr("Decode Raw Hex  (offline, no device needed)")
    print(); print(D("  Paste hex bytes from a captured PROFINET frame."))
    print(D("  Example:  03 00 c8 01 a0 00 00 00 ..."))
    print()
    hex_s=_ask("Hex bytes")
    if not hex_s: return
    try: raw=bytes.fromhex(hex_s.replace(" ","").replace(":",""))
    except ValueError as e: print(R(f"  Invalid hex: {e}")); _ask("Press Enter"); return
    print()
    for mid,m in sorted(MODULES.items()):
        print(f"  {C(str(mid))}  {m['name']}  IN={m['in']}B")
    print(); ch=_ask("Module number to decode as","1")
    try: mid=int(ch)
    except ValueError: mid=1
    if mid not in MODULES: mid=1
    m=MODULES[mid]; sigs=decode_inputs(mid,raw)
    clr(); _hdr(f"Decoded: Module {mid}  {m['name']}")
    print(); print(D(f"  {len(raw)} bytes: {raw[:16].hex()}{'…' if len(raw)>16 else ''}\n"))
    if not sigs: print(Y("  No signals (payload too short?)")); _hexdump(raw)
    else:
        bools={k:v for k,v in sigs.items() if isinstance(v,bool)}
        meas ={k:v for k,v in sigs.items() if not isinstance(v,bool)}
        smap ={s.name:s for s in m["in_sigs"]}
        if bools:
            print(B("  Status bits")); rule("·")
            for k in sorted(bools):
                print(f"  {G('●ON') if bools[k] else D('○off')}  {k}")
        if meas:
            print(); print(B("  Measurements")); rule("·")
            for k in sorted(meas):
                v=meas[k]; s=smap.get(k); u=s.unit if s else ""
                print(f"  {C(f'{k:<44}')} {v:>10.4f}  {D(u)}")
    if len(raw)>=m["in"]+2:
        iops=raw[m["in"]]; iocs=raw[m["in"]+1]
        print()
        print(f"  IOPS 0x{iops:02X} {G('GOOD') if iops&0x80 else R('BAD')}   "
              f"IOCS 0x{iocs:02X} {G('GOOD') if iocs&0x80 else R('BAD')}")
    print(); _ask("Press Enter")


def _pick_adapter_interactive():
    r"""
    Show resolved human-readable adapter names and let user pick one.
    Stores the raw \Device\NPF_{GUID} value in _cfg["iface"] for Scapy,
    but displays the friendly name so the user knows what they're choosing.
    """
    print(B("  Network Adapters"))
    rule("·")
    print(f"  {'#':>3}  {'Friendly Name':<38}  Note")
    rule("·")

    adapters = _resolve_adapter_names()

    if not adapters:
        print(Y("  No adapters found (is Npcap/Scapy installed?)"))
        _cfg["iface"] = _ask("Enter adapter name manually", "Ethernet")
        return

    # Print all adapters; dim virtual/skip ones
    for a in adapters:
        num_s = f"{a['index']:>3}"
        if a["skip"]:
            print(D(f"  {num_s}  {a['name']:<38}  {a['hint']}"))
        else:
            print(f"  {C(num_s)}  {a['name']:<38}  {a['hint']}")

    print()

    # Auto-suggest best Ethernet adapter
    best = next((a for a in adapters
                 if not a["skip"] and "ethernet" in a["name"].lower()), None)
    if best is None:
        best = next((a for a in adapters if not a["skip"]), None)
    default_n = str(best["index"]) if best else "1"

    print(D("  Tip: Choose the physical Ethernet adapter connected to the"))
    print(D("       same network switch as the TeSys Tera relay."))
    print(D("       Avoid Virtual, VMware, VirtualBox, Hyper-V, VPN adapters."))
    print()

    ch = _ask("Enter adapter number", default_n)
    chosen = None
    try:
        idx = int(ch) - 1
        if 0 <= idx < len(adapters):
            chosen = adapters[idx]
    except ValueError:
        # User typed a partial name
        ch_l = ch.lower()
        chosen = next((a for a in adapters
                       if ch_l in a["name"].lower()
                       or ch_l in a["raw"].lower()), None)

    if chosen:
        _cfg["iface"] = chosen["raw"]   # raw NPF name for Scapy
        print()
        print(G(f"  ✓ Selected: {chosen['name']}"))
        if chosen.get("skip"):
            print(Y("  ⚠ This looks like a virtual adapter. "
                    "PROFINET may not work on it."))
        print(D(f"    Scapy internal name: {chosen['raw']}"))
    else:
        _cfg["iface"] = ch
        print(G(f"  Selected: {ch}"))


def _settings():
    global _cfg
    _disconnect()
    clr(); _hdr("Settings")
    print()
    cycle=_cfg["sc"]*_cfg["rr"]*_BASE_US/1000
    _kv("1  Network adapter",   _cfg["iface"])
    _kv("2  Station name",      _cfg["station"])
    _kv("3  Device IP",         _cfg.get("device_ip") or "auto-discover")
    _kv("4  Module ID",         f"{_cfg['module_id']}  ({MODULES.get(int(_cfg['module_id']),{}).get('name','')})")
    _kv("5  Cycle time",        f"{cycle:.1f} ms  (SC={_cfg['sc']} RR={_cfg['rr']})")
    _kv("6  Connect timeout",   f"{_cfg['timeout']} s")
    _kv("7  Auto-reconnect",    "ON" if _cfg.get("auto_recon",True) else "OFF")
    print(f"  {C('0')}  Back")
    rule("·"); ch=_ask("Setting number to change")
    if ch=="1":
        _pick_adapter_interactive()
    elif ch=="2": _cfg["station"]=_ask("Station name",_cfg["station"])
    elif ch=="3": _cfg["device_ip"]=_ask("IP (blank=auto)",_cfg.get("device_ip",""))
    elif ch=="4":
        print()
        for mid,m in sorted(MODULES.items()):
            print(f"  {C(str(mid))}  {m['name']}")
        _cfg["module_id"]=int(_ask("Module ID",_cfg["module_id"]))
    elif ch=="5":
        _cfg["sc"]=int(_ask("SendClock {8,16,32,64,128}",_cfg["sc"]))
        _cfg["rr"]=int(_ask("ReductionRatio",_cfg["rr"]))
        new_c=_cfg["sc"]*_cfg["rr"]*_BASE_US/1000
        if new_c<_MIN_CYCLE_MS: print(Y(f"  ⚠  {new_c:.1f} ms < 16 ms minimum, will be auto-corrected."))
        else: print(G(f"  ✓  Cycle time = {new_c:.1f} ms"))
    elif ch=="6": _cfg["timeout"]=float(_ask("Timeout (s)",_cfg["timeout"]))
    elif ch=="7": _cfg["auto_recon"]=_confirm("Enable auto-reconnect?")
    _save(); print(G("  ✓ Saved.")); _ask("Press Enter")


# ══════════════════════════════════════════════════════════════════════
# MAIN SCREEN
# ══════════════════════════════════════════════════════════════════════

def _data_groups():
    """
    Explains cyclic data groups and lets the user live-switch between them.
    """
    clr(); _hdr("Cyclic Data Groups — How It Works")
    print()
    print(B("  How PROFINET cyclic data groups work on TeSys Tera"))
    print()
    rule("·")
    print("""
  The TeSys Tera has ONE physical slot (Slot 1) with ONE submodule.
  You choose which data PROFILE (group) that submodule uses when the
  Application Relation (AR) is established during connect().

  Think of it like a USB device with multiple firmware modes — you
  pick the mode at connection time and the device streams that exact
  format of bytes to you every 16 ms.

  ┌─────────────────────────────────────────────────────────────┐
  │  AR SETUP (RPC Connect)                                     │
  │   → you say: "I want SubmoduleIdentNumber = 0x10400003"    │
  │   → device confirms                                         │
  │   → cyclic exchange starts at exactly that byte layout      │
  └─────────────────────────────────────────────────────────────┘

  To switch groups you MUST disconnect and reconnect with the new
  SubmoduleIdentNumber. This takes ~0.5–1 second per switch.

  For LIVE continuous data with the MOST signals, use Module 13
  (EIOS, 128 bytes) — it contains every measurement in one frame.""")
    print()
    rule("·")
    print()
    print(B(f"  {'Module':<3}  {'Name':<33} {'IN':>3}B  {'Bits':>4}  {'Meas':>4}  {'What it gives you'}"))
    rule("·")
    summaries = {
        1:  "Standard: 3-phase V+I, Hz, thermal, unbalance, earth fault",
        2:  "Overload only: trip/warn/reset status bits",
        3:  "Overload only (extended): same as M2",
        4:  "Basic motor starter: run/stop/K1 bits",
        5:  "Contractor: run/stop/K1 bits (extended)",
        6:  "Reversing starter: Fwd/Rev/K1/K2 bits",
        7:  "Reversing starter 2: same as M6",
        8:  "LTMT + digital I/O: DI1-4, DO1-2, avg current, thermal",
        9:  "PKW only: parameter channel for reading device registers",
        10: "PKW + extended starter: parameter + run/stop",
        11: "PKW + full LTMT: most complete fast profile (16B)",
        12: "E_Fast: compact V+I+thermal in 12B (lowest overhead)",
        13: "EIOS: EVERYTHING — V, I, P, Q, S, PF, Hz, thermal, unbalance (128B)",
    }
    for mid,m in sorted(MODULES.items()):
        isigs=m["in_sigs"]
        bits=len([s for s in isigs if s.enc=="BIT"])
        meas=len([s for s in isigs if s.enc!="BIT"])
        active = G(" ← ACTIVE") if _g and _g._mod_id==mid else ""
        desc = summaries.get(mid,"")
        print(f"  {C(f'{mid:>3}')}  {m['name']:<33} {m['in']:>3}B  {bits:>4}  {meas:>4}  {D(desc)}{active}")
    print()
    rule("·")
    print()
    print(f"  {C('S')}  Switch to a different module (live reconnect)")
    print(f"  {C('0')}  Back")
    rule("·"); ch=_ask("Choose").upper()
    if ch=="S": _switch_module_screen()


def _switch_module_screen():
    """Switch the active cyclic data group (disconnects and reconnects AR)."""
    global _g
    clr(); _hdr("Switch Data Group / Module")
    print()
    print(B("  Choose which module profile to connect with."))
    print(D("  This will disconnect and reconnect (~1 second)."))
    print()
    for mid,m in sorted(MODULES.items()):
        active = G("  ← current") if _g and _g._mod_id==mid else ""
        print(f"  {C(str(mid))}  {m['name']:<33} IN={m['in']:>3}B  OUT={m['out']:>2}B{active}")
    print(f"  {C('0')}  Cancel")
    print()
    rule("·"); ch=_ask("Module number")
    if not ch or ch=="0": return
    try: mid=int(ch)
    except ValueError: mid=-1
    if mid not in MODULES:
        print(R("  Invalid module number.")); _ask("Press Enter"); return

    # Save settings
    _cfg["module_id"] = mid; _save()

    ctrl=_get_ctrl()
    if ctrl is None:
        # Not yet connected – just update config and it will connect fresh next use
        print(G(f"  Module {mid} ({MODULES[mid]['name']}) selected. Will use on next connect."))
        _ask("Press Enter"); return

    print()
    print(D(f"  Switching to Module {mid}: {MODULES[mid]['name']} …"))
    try:
        ok_flag = ctrl.switch_module(mid)
        if ok_flag:
            print(G(f"  ✓ Switched to Module {mid}: {MODULES[mid]['name']}"))
            print(D(f"    IN={MODULES[mid]['in']}B  OUT={MODULES[mid]['out']}B  "
                    f"Cycle={ctrl.cycle_ms:.0f}ms"))
            if ctrl.wait_valid(timeout=6.0):
                d=ctrl.read_inputs()
                print(G(f"  ✓ Live data valid — {len(d)} signals flowing"))
            else:
                print(Y("  ⚠ Connected but IOPS not yet GOOD (give it 2–3 seconds)"))
        else:
            print(R("  ✗ Switch failed — check device is powered and on network"))
            _disconnect()
    except Exception as e:
        print(R(f"  ✗ {e}")); _disconnect()
    _ask("Press Enter")


def _capture_info():
    """Show which capture backends are available and explain the architecture."""
    clr(); _hdr("Capture Backend & Npcap Architecture")
    print()
    backends = _detect_capture_backends()

    print(B("  Detected backends:"))
    rule("·")
    mark = lambda ok: G("  ✓  installed") if ok else R("  ✗  not found")
    print(f"  Scapy (Python)     {mark(backends.get('scapy',False))}")
    print(f"  Npcap DLL          {mark(backends.get('npcap_dll',True))}"
          if platform.system()=="Windows" else "")
    print(f"  TShark binary      {mark(backends.get('tshark',False))}")
    print(f"  pyshark (Python)   {mark(backends.get('pyshark',False))}")
    print()
    rule("·")
    print("""
  ┌───────────────────────────────────────────────────────────────┐
  │  HOW LAYER 2 CAPTURE WORKS ON WINDOWS                        │
  │                                                               │
  │  ┌──────────┐   ┌──────────┐   ┌──────────────────────────┐ │
  │  │  Scapy   │   │ TShark / │   │     pyshark              │ │
  │  │ (Python) │   │Wireshark │   │  (Python wrapper for     │ │
  │  └────┬─────┘   └────┬─────┘   │   TShark subprocess)     │ │
  │       │              │          └────────────┬─────────────┘ │
  │       └──────────────┴──────────────────────┘               │
  │                            │                                 │
  │                    ┌───────▼───────┐                         │
  │                    │   Npcap DLL   │  ← THE kernel driver    │
  │                    │  (wpcap.dll)  │    ALL tools use this   │
  │                    └───────┬───────┘                         │
  │                            │                                 │
  │                    ┌───────▼───────┐                         │
  │                    │  NPF.sys      │  ← Windows kernel mode  │
  │                    │  (kernel drv) │    NIC ring buffer       │
  │                    └───────────────┘                         │
  └───────────────────────────────────────────────────────────────┘

  KEY POINT:  TShark IS Npcap.  They are the same kernel driver.
  If TShark/Wireshark is installed on your PC, Npcap IS installed.
  Scapy will work. You do NOT need a separate Npcap install.

  WHY THIS TOOL USES SCAPY (not TShark):
  ────────────────────────────────────────
  ✓  Scapy can SEND (inject) raw Ethernet frames    ← needed for TX
  ✓  Scapy can RECEIVE (capture) raw frames         ← needed for RX
  ✗  TShark can ONLY receive — it cannot inject frames
  ✗  pyshark is a Python wrapper for TShark — also receive-only

  TShark would be enough for a PASSIVE sniffer/analyser.
  To be an IO CONTROLLER (commander) you MUST inject frames,
  so Scapy+Npcap is the correct and only option on Windows.

  FALLBACK:
  If scapy fails to import but tshark is present, this tool
  can use tshark for the RX path (reading device inputs).
  However the TX path (writing outputs / sending commands)
  will NOT work without Scapy. Install scapy to fix TX.""")
    print()
    rule("·")
    print()
    print(B("  Install / fix commands:"))
    print(f"    pip install scapy netifaces")
    print(f"    pip install pyshark          (optional fallback)")
    print(f"    Npcap: https://npcap.com     (if not already installed)")
    print()
    print(B("  If Wireshark/TShark is already installed on this PC:"))
    print(D("    → Npcap is already there. Just run: pip install scapy"))
    print()

    # Offer to try tshark fallback test
    if backends.get("tshark") and not backends.get("scapy"):
        print(Y("  TShark is available but Scapy is not."))
        print(Y("  RX (reading device inputs) will work via TShark fallback."))
        print(Y("  TX (writing outputs/commands) requires Scapy — install it."))
    elif backends.get("scapy"):
        print(G("  ✓ Full TX+RX capability available via Scapy+Npcap."))

    print()
    print(B("  Your adapters (resolved friendly names):"))
    rule("·")
    print(f"  {'#':>3}  {'Friendly Name':<38}  Note")
    rule("·")
    adapters = _resolve_adapter_names()
    if adapters:
        for a in adapters:
            if a["skip"]:
                print(D(f"  {a['index']:>3}  {a['name']:<38}  {a['hint']}"))
            else:
                print(f"  {C(str(a['index'])):>3}  {a['name']:<38}  {a['hint']}")
    else:
        print(D("  (Could not resolve — install Scapy/Npcap first)"))
    print()
    print(D(f"  Currently configured: {_cfg.get('iface','')}"))

    print(); _ask("Press Enter")


def _main_screen():
    while True:
        clr()
        _hdr("PROFINET Commander  ·  TeSys Tera",
             f"VID=0x{_VENDOR_ID:04X}  DID=0x{_DEVICE_ID:04X}  "
             f"Module {_cfg['module_id']}: {MODULES.get(int(_cfg['module_id']),{}).get('name','')}")
        print(); _status_bar(); print()

        print(f"  {B(C('──── MONITOR ────────────────────────────────────────────'))} ")
        print(f"  {C(' 1')}  Live dashboard           Auto-refresh all signals")
        print(f"  {C(' 2')}  Read one signal          Any input by name or number")
        print(f"  {C('20')}  Data groups / switch     View all groups, switch live module")
        print()
        print(f"  {B(C('──── COMMANDS ───────────────────────────────────────────'))} ")
        print(f"  {C(' 3')}  Run Forward              Start motor K1")
        print(f"  {C(' 4')}  Run Reverse              Start motor K2")
        print(f"  {C(' 5')}  Stop                     De-energise")
        print(f"  {C(' 6')}  Fault Reset              Clear trip – 200 ms pulse")
        print(f"  {C(' 7')}  Emergency Stop           Immediate de-energise")
        print(f"  {C(' 8')}  Write any output         Any output bit / value")
        print(f"  {C(' 9')}  Operate / Stop mode      DataStatus RUN bit toggle")
        print(f"  {C('10')}  IO Force table           Override outputs for FAT/commissioning")
        print()
        print(f"  {B(C('──── DIAGNOSTICS & RECORDS ──────────────────────────────'))} ")
        print(f"  {C('11')}  Alarm monitor            Real-time alarm receive & log")
        print(f"  {C('12')}  Watch list               Signal threshold alerts")
        print(f"  {C('13')}  Signal map               Byte/bit layout all 13 modules")
        print(f"  {C('14')}  Acyclic records          IM0–4 read/write + custom index")
        print(f"  {C('15')}  RT diagnostics           Timing, IOPS, DataStatus")
        print(f"  {C('16')}  CSV export               Log readings to file")
        print(f"  {C('17')}  Decode hex offline       Paste captured frame bytes")
        print()
        print(f"  {B(C('──── SETUP ──────────────────────────────────────────────'))} ")
        print(f"  {C('18')}  DCP tools                Discover / set name or IP")
        print(f"  {C('19')}  Settings                 Adapter, station, cycle, reconnect")
        print(f"  {C('21')}  Capture backend info     Npcap / TShark / Scapy explained")
        print(f"  {C(' 0')}  Disconnect & Exit")
        print()
        rule()
        ch=_ask("Choose action")

        actions = {
            "1":_dashboard,   "2":_read_one,
            "3":_run_fwd,     "4":_run_rev,    "5":_stop_motor,
            "6":_fault_reset, "7":_estop,      "8":_write_output,
            "9":_operate_stop,"10":_force_table,
            "11":_alarms,     "12":_watchlist,  "13":_signal_map,
            "14":_records,    "15":_diagnostics,"16":_csv_export,
            "17":_decode_hex, "18":_dcp_tools,  "19":_settings,
            "20":_data_groups,"21":_capture_info,
        }
        if ch in ("0","q","exit","quit"):
            _disconnect(); clr()
            print(); print(G("  Disconnected. Goodbye!")); print(); sys.exit(0)
        fn=actions.get(ch)
        if fn: fn()
        else: print(R("  Invalid choice – enter a number 0-21.")); time.sleep(0.8)


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    # Enable ANSI colours on Windows
    if os.name=="nt":
        try: ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11),7)
        except Exception: pass

    # Dependency check
    backends = _detect_capture_backends()
    missing=[]
    try: import netifaces  # type: ignore
    except ImportError: missing.append("netifaces")

    if missing:
        clr(); _hdr("Missing Dependencies")
        print(); print(R("  Run these first:"))
        for m in missing: print(f"      pip install {m}")
        print(); sys.exit(1)

    if not backends.get("scapy"):
        clr(); _hdr("Scapy Not Found")
        print()
        if backends.get("tshark"):
            print(Y("  TShark is installed (Npcap is present) but Scapy is not."))
            print(Y("  RX (reading device inputs) will work in fallback mode."))
            print(Y("  TX (writing outputs/commands) requires Scapy."))
            print()
            print(R("  Run:   pip install scapy"))
            print(D("  Then restart this tool for full TX+RX capability."))
            print()
            print(D("  Continuing in RX-only mode …"))
            time.sleep(2)
        else:
            print(R("  Scapy is not installed and TShark is not found."))
            print()
            print(R("  Run:   pip install scapy"))
            print(R("  And:   Install Npcap from https://npcap.com"))
            print(Y("  (If Wireshark is already installed, Npcap is already there.)"))
            print(Y("  (Just run: pip install scapy)"))
            print(); sys.exit(1)

    # First run: no config or no adapter set
    if not CFG.exists():
        clr(); _hdr("First-Time Setup")
        print(); print(D("  No configuration found. Let's set this up (takes 30 seconds)."))
        print(); _ask("Press Enter to begin")
        # Adapter
        print()
        _pick_adapter_interactive()
        # Station name
        print()
        _cfg["station"]=_ask("PROFINET Name of Station","tesys-tera-pn")
        # Device IP
        print()
        print(D("  Leave IP blank for automatic DCP discovery (recommended)."))
        _cfg["device_ip"]=_ask("Device IP (blank = auto-discover)","")
        # Module
        print()
        print(B("  Module:"))
        for mid,m in sorted(MODULES.items()):
            flag=" ← recommended" if mid==1 else ""
            print(f"    {C(str(mid))}  {m['name']:<32} IN={m['in']}B  OUT={m['out']}B{flag}")
        _cfg["module_id"]=int(_ask("Module ID","1"))
        _save()
        print(); print(G("  ✓ Configuration saved.")); _ask("Press Enter")

    _main_screen()


if __name__ == "__main__":
    main()