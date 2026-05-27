# PROFINET IO Controller — TeSys Tera: Complete Technical Briefing
## Full session findings for LLM handoff

---

## 1. HARDWARE & NETWORK TOPOLOGY

| Parameter | Value |
|-----------|-------|
| Device (IO Device) | Schneider Electric TeSys Tera Motor Management Relay |
| Device IP | 192.168.0.61 |
| Device MAC | 88:01:f9:35:d9:a2 |
| Device Station Name | `tesys-tera-pn` |
| Device Vendor ID | 0x1559 |
| Device ID | 0x1503 |
| Controller (PC) IP | 192.168.0.100 |
| Controller MAC | 18:3d:2d:61:f9:70 |
| OS | Windows (tested with Python 3.12) |
| Module 1 | 40 bytes Input (device→controller), 4 bytes Output (controller→device) |
| Protocol | PROFINET IO RT Class 1 (Software RT, ~32ms cycle) |
| DCE/RPC variant | **Version 4 connectionless (CL-PDU) over UDP** — NOT v5 TCP |

---

## 2. PROTOCOL STACK SUMMARY

```
┌─────────────────────────────────────────────────────────────┐
│ LAYER        │ TECHNOLOGY                                    │
├─────────────────────────────────────────────────────────────┤
│ Discovery    │ DCP (PROFINET Discovery & Config Protocol)    │
│              │  — Ethernet multicast, EtherType 0x8892      │
├─────────────────────────────────────────────────────────────┤
│ CM Acyclic   │ DCE/RPC v4 Connectionless (CL-PDU)           │
│              │  — UDP port 34964 (both src AND dst)          │
│              │  — 80-byte fixed header                       │
│              │  — Object UUID identifies device endpoint     │
│              │  — Transport: Scapy raw Ethernet              │
│              │    (NOT Python UDP socket — Windows firewall  │
│              │     silently drops inbound responses)         │
├─────────────────────────────────────────────────────────────┤
│ Cyclic IO    │ PROFINET RT frames                            │
│              │  — EtherType 0x8892                           │
│              │  — VLAN tag prio=6, VID=0 (802.1Q)           │
│              │  — FrameID 0x8000 = input  (device→ctrl)     │
│              │  — FrameID 0x8001 = output (ctrl→device)     │
│              │  — Transport: Scapy sendp/AsyncSniffer        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. CRITICAL UUID REFERENCE

| UUID | Value | Purpose |
|------|-------|---------|
| `PNIO_CM_OBJ_UUID` | `dea00000-6c97-11d1-8271-006428ce90d2` | **Device's endpoint Object UUID** — goes in DCE/RPC CL-PDU `object` field (bytes 8–23 of header). This is the Anybus/HMS well-known UUID used by TeSys Tera. Device returns `nca_unk_if` (0x1c010003) if this is wrong. |
| `PNIO_CM_IF_UUID` | `dea00001-6c97-11d1-8271-00a02442df7d` | **Interface UUID** — fixed by PROFINET standard (IEC 61158-6-10). Goes in `if_uuid` field (bytes 24–39) of CL-PDU header. |
| `PNIO_CTRL_OBJ_UUID` | `dea00002-6c97-11d1-8271-00a02442df7d` | **Controller's own Object UUID** — placed in `ARBlock.CMInitiatorObjectUUID`. Tells the device which UUID to use for callbacks to the controller. |

### UUID Wire Encoding (DCE/RPC mixed-endian)
```python
# Python uuid.UUID.bytes_le gives the correct DCE/RPC wire encoding:
# Fields 1-3 (time_low, time_mid, time_hi): Little-Endian
# Fields 4-5 (clock_seq, node): Big-Endian
def _u(u: uuid.UUID) -> bytes:
    return u.bytes_le   # 16 bytes, correct wire format
```

---

## 4. DCE/RPC v4 CL-PDU HEADER — EXACT LAYOUT (80 bytes)

```
Offset  Size  Field           Value / Notes
──────  ────  ─────────────   ──────────────────────────────────────────────
  0       1   rpc_vers        = 4   (NOT 5 — PROFINET uses v4)
  1       1   pkt_type        = 0x00 (Request), 0x02 (Response), 0x03 (Fault)
              *** BYTE 1 is pkt_type — NOT byte 2 as in v5 TCP ***
  2       1   flags1          = 0x83 = FIRST_FRAG|LAST_FRAG|OBJECT_UUID
  3       1   flags2          = 0x00
  4       3   drep[3]         = 0x10, 0x00, 0x00  (LE integers, IEEE float)
  7       1   serial_hi       = 0
  8      16   object_uuid     ← device Object UUID (bytes_le encoded)
 24      16   if_uuid         ← interface UUID (bytes_le encoded)
 40      16   act_uuid        ← activity UUID (unique per AR session)
 56       4   server_boot     = 0
 60       4   if_version      = 0x00010000  (v1.0, little-endian!)
              *** Common bug: packing as struct.pack("<I",1) gives 0x00000001 ***
 64       4   seq_num         = 0 for Connect, +1 for each subsequent call
              *** MUST be 0 for first packet (AR Connect) — no BIND ***
 68       2   opnum           = 0/2/3/4 (see below)
 70       2   ihint           = 0xFFFF
 72       2   ahint           = 0xFFFF
 74       2   frag_len        (little-endian, = 80 + len(stub))
 76       2   frag_num        = 0
 78       1   auth_proto      = 0
 79       1   serial_lo       = 0
─────────────────────────────────────────────────────────────────────────────
 80+     var  stub data       (PROFINET blocks, no NDR length prefix)
```

### PROFINET CM Opnums (IEC 61158-6-10 §6.3)
| Opnum | Operation | Notes |
|-------|-----------|-------|
| 0 | IODConnectReq | AR Connect — MUST be seq=0 |
| 1 | IODReleaseReq | AR Release |
| 2 | IODControlReq | PrmEnd AND ApplicationReady both use opnum 2 |
| 3 | IODReadReq | Acyclic read |
| 4 | IODWriteReq | Acyclic write |

---

## 5. AR ESTABLISHMENT SEQUENCE (CORRECT ORDER)

```
Controller (PC)                          TeSys Tera Device
      │                                          │
      │── seq=0  IODConnectReq (opnum 0) ──────►│
      │          Contains: ARBlock, IOCRBlock×2, │
      │          ExpectedSubmoduleBlock,          │
      │          AlarmCRBlock                     │
      │◄──────────────── ConnectRes (ptype=0x02) ─│
      │                                          │
      │── seq=1  IODControlReq (opnum 2) ───────►│
      │          ControlCommand = 0x0008 (PrmEnd)│
      │◄──────────── ControlRes (ptype=0x02) ────│
      │                                          │
      │── seq=2  IODControlReq (opnum 2) ───────►│
      │    ControlCommand = 0x0010 (AppReady)    │
      │◄──────────── ControlRes (ptype=0x02) ────│
      │                                          │
      │  ◄══ Cyclic RT frames begin ═══════════► │
      │  FrameID=0x8001 (output, ctrl→device)    │
      │  FrameID=0x8000 (input,  device→ctrl)    │
      │                                          │
      │── seq=3+  IODReadReq (opnum 3) ─────────►│  (acyclic, any time)
      │── seq=3+  IODWriteReq (opnum 4) ─────────►│
```

**CRITICAL: NO BIND STEP.** DCE/RPC v4 CL does not use BIND. Any packet sent before AR Connect steals seq=0, causing `nca_wrong_boot_time` (0x1c00000e) ghost AR lock.

---

## 6. COMPLETE BUG LIST (18 bugs found and fixed)

### Layer 1 — DCE/RPC Connection

| ID | Location | Bug | Fix | Impact |
|----|----------|-----|-----|--------|
| A | `if_version` field | `struct.pack("<I", 1)` = `0x00000001` | `struct.pack("<I", 0x00010000)` | Interface version 0.0.0.1 instead of 1.0 |
| B | UDP bind | `bind((ip, 0))` ephemeral port | `bind((ip, 34964))` | Device silently drops all packets → timeout |
| C | `ARProperties` | `0x00000001` (PullModule flag) | `0x00000000` | Pull-module mode on a standard AR → rejected |
| D | `CMInitiatorActivityTimeoutFactor` | `0x8892` (PROFINET ethertype!) | `0x0064` (10s) | 3496-second watchdog → malformed/rejected |
| E | `CMInitiatorObjectUUID` | `PNIO_CM_IF_UUID` = `dea00001...` | `PNIO_CTRL_OBJ_UUID` = `dea00002...` | Device can't send RPC callbacks to controller |
| F | IOCR `LT` field | `struct.pack(">I", 0)` — 4 bytes | `struct.pack(">H", 0x8892)` — 2 bytes | Shifts DataLength, FrameID, all subsequent IOCR fields by +2 bytes → entire IOCR garbage |
| G | PrmEnd opnum | `opnum=4` (IODWriteReq) | `opnum=2` (IODControlReq) | Wrong RPC operation |
| H | PrmEnd `ControlCommand` | `0x0001` | `0x0008` (bit 3 = PrmEnd, Table 566) | Device never signals end-of-parameterisation |
| I | Control block padding | Missing 2 padding bytes after BlockVersion, before ARUUID | Added `struct.pack(">H", 0)` | ARUUID shifted by 2 bytes → PrmEnd and AppReady rejected |
| J | AppReady opnum | `opnum=4` | `opnum=2` | Wrong RPC operation |
| K | AppReady `ControlCommand` | `0x0002` | `0x0010` (bit 4 = AppReady) | Device never enters active IO state |
| O | Sequence number trap | `step_bind()` consumes seq=0 before AR Connect | Remove BIND entirely | AR Connect at seq=1 → `nca_wrong_boot_time` ghost lock |
| P | Transport | Python UDP socket | Scapy raw Ethernet (Ether/IP/UDP) | Windows Firewall/stack silently drops inbound UDP 34964 responses → timeout |

### Layer 2 — Cyclic RT Frames

| ID | Bug | Fix |
|----|-----|-----|
| L | TX `frame_id = 0x8002` | `FRAME_ID_OUT = 0x8001` |
| M | TX had 30-byte phantom padding | Exact: data + IOPS(1B) + CycleCounter(2B) + DataStatus(1B) + TransferStatus(1B) |
| N | RX filter `fid == 0x8001` (output direction) | `fid == 0x8000` (input from device) |

### Layer 3 — PROFINET Blocks

| ID | Bug | Fix |
|----|-----|-----|
| NEW-1 | `SubmoduleProperties = 0x0000` (NO_IO) | `0x0003` (INPUT_OUTPUT) |
| NEW-2 | OUTPUT `DataDescription` block missing from `ExpectedSubmoduleBlock` | Added OUTPUT DataDescription (type=0x0002, length=output_len) |

---

## 7. PROFINET BLOCK STRUCTURES (WIRE FORMAT)

All multi-byte integers in PROFINET blocks are **Big-Endian** unless noted.
UUIDs inside PROFINET blocks use the DCE/RPC mixed-endian format (`uuid.bytes_le`).

### Block Envelope (all blocks)
```
BlockType    (2B, BE)
BlockLength  (2B, BE)  = 2 + len(body)   [counts version bytes, NOT type/length]
VersionHigh  (1B)      = 1
VersionLow   (1B)      = 0
body         (variable)
```

### ARBlockReq (0x0101)
```
ARType                     (2B): 0x0001 = IOCAR_SINGLE
ARUUID                    (16B): uuid.bytes_le (fresh per connection)
SessionKey                 (2B): 0x0001
CMInitiatorMACAdd          (6B): controller MAC
CMInitiatorObjectUUID     (16B): PNIO_CTRL_OBJ_UUID = dea00002... (controller's own UUID)
ARProperties               (4B): 0x00000000 (standard AR, no special flags)
CMInitiatorActivityTimeoutFactor (2B): 0x0064 (100 × 100ms = 10s)
CMInitiatorUDPRTPort       (2B): 34964 = 0x8894
StationNameLength          (2B): len(name)
CMInitiatorStationName     (nB): ASCII, no null terminator, pad to even length
```

### IOCRBlockReq (0x0102) — one block per direction
```
IOCRType        (2B): 0x0001=Input, 0x0002=Output
IOCRReference   (2B): 1=input, 2=output
LT              (2B): 0x8892 (PROFINET EtherType)  ← MUST be 2 bytes not 4
IOCRProperties  (4B): 0x00000000
DataLength      (2B): process_data_bytes + 1 (IOPS)
FrameID         (2B): 0x8000=input, 0x8001=output
SendClockFactor (2B): 32 (32 × 31.25µs = 1ms base)
ReductionRatio  (2B): 32 (32ms actual cycle)
Phase           (2B): 1  (1-indexed, NOT 0)
Sequence        (2B): 0
FrameSendOffset (4B): 0xFFFFFFFF (best effort)
WatchdogFactor  (2B): 5
DataHoldFactor  (2B): 5
IOCRTagHeader   (2B): 0xC000 (VLAN priority=6, VID=0)
IOCRMulticastMACAdd (6B): 0x000000000000 (unicast)
NumberOfAPIs    (2B): 1
  API           (4B): 0
  NumberOfIODataObjects (2B): 1
    SlotNumber  (2B): 1
    SubslotNumber (2B): 0x0001
    FrameOffset (2B): 0
  NumberOfIOCS  (2B): 0
```

### ExpectedSubmoduleBlockReq (0x0104)
```
NumberOfAPIs        (2B): 1
  API               (4B): 0
  NumberOfModules   (2B): 1
    SlotNumber      (2B): 1
    ModuleIdentNumber (4B): 0x00001503  (TeSys Tera Device ID)
    ModuleProperties  (2B): 0x0000
    NumberOfSubmodules (2B): 1
      SubslotNumber     (2B): 0x0001
      SubmoduleIdentNumber (4B): 0x00000001
      SubmoduleProperties  (2B): 0x0003  ← INPUT_OUTPUT (was 0x0000 = NO_IO bug)
      SubmoduleDataDescription INPUT:
        DataDirection   (2B): 0x0001
        DataLength      (2B): 40 (INPUT_LEN)
        LengthIOCS      (1B): 1
        LengthIOPS      (1B): 1
      SubmoduleDataDescription OUTPUT:     ← was missing entirely (bug NEW-2)
        DataDirection   (2B): 0x0002
        DataLength      (2B): 4 (OUTPUT_LEN)
        LengthIOCS      (1B): 1
        LengthIOPS      (1B): 1
```

### IODControlReq (0x0110) — PrmEnd and ApplicationReady
```
BlockType   (2B): 0x0110
BlockLength (2B): 26
Version     (2B): 1.0
Padding     (2B): 0x0000  ← was MISSING (bug I), shifts ARUUID by 2 bytes
ARUUID     (16B): uuid.bytes_le
SessionKey  (2B): 0x0001
Padding     (2B): 0x0000
ControlCommand (2B): 0x0008=PrmEnd  OR  0x0010=ApplicationReady
ControlBlockProperties (2B): 0x0000

opnum for BOTH = 2 (not 3 or 4)
```

### AlarmCRBlockReq (0x0103)
```
AlarmCRType         (2B): 0x0001
LT                  (2B): 0x8892
AlarmCRProperties   (4B): 0x00000000
RTATimeoutFactor    (2B): 200
RTARetries          (2B): 3
LocalAlarmReference (2B): 1
MaxAlarmDataLength  (2B): 200
AlarmCRTagHeaderHigh (2B): 0x0000
AlarmCRTagHeaderLow  (2B): 0x0000
```

---

## 8. CYCLIC RT FRAME WIRE STRUCTURE

### Output Frame (controller → device)
```
Ethernet header:
  dst = TARGET_MAC
  src = CONTROLLER_MAC
802.1Q VLAN tag:
  prio=6, DEI=0, VID=0
  EtherType = 0x8892
PROFINET payload:
  FrameID        (2B, BE): 0x8001
  OutputData     (4B):     actual output values
  IOPS           (1B):     0x80 = GOOD
  CycleCounter   (2B, BE): incrementing 0..65535
  DataStatus     (1B):     0x35 (Run|Primary|DataValid)
  TransferStatus (1B):     0x00
Total payload after VLAN tag: 11 bytes
```

### Input Frame (device → controller)
```
Same Ethernet/VLAN header (src=device MAC)
PROFINET payload:
  FrameID     (2B, BE): 0x8000  ← listen for THIS, NOT 0x8001
  InputData  (40B):     process measurements
  IOPS        (1B):     device provider status
  CycleCounter (2B, BE)
  DataStatus   (1B)
  TransferStatus (1B)
```

---

## 9. WINDOWS-SPECIFIC ISSUES AND FIXES

### Issue 1: Silent Timeout on UDP Socket (Root Cause of Final Timeout)
- **Symptom**: Packet is sent, perfectly formed, 33/33 self-tests pass, device never responds.
- **Cause**: Windows Firewall / NDIS silently drops inbound UDP 34964 responses even with `SO_REUSEADDR`. The Python UDP socket `recvfrom()` never fires.
- **Fix**: Use **Scapy `sendp` + `AsyncSniffer`** for ALL DCE/RPC traffic (acyclic and cyclic). Scapy uses Npcap/WinPcap raw Ethernet access, completely bypassing the Windows network stack.
- **Code pattern**:
```python
from scapy.all import AsyncSniffer, Ether, IP, UDP, Raw, sendp

# Start sniffer BEFORE sending (avoid race condition)
sniffer = AsyncSniffer(
    iface=SCAPY_IFACE,
    filter=f"udp src host {device_ip} and src port 34964",
    prn=lambda pkt: resp_q.put(bytes(pkt[Raw])),
    store=False,
)
sniffer.start()
time.sleep(0.05)

frame = (Ether(dst=device_mac, src=ctrl_mac) /
         IP(src=ctrl_ip, dst=device_ip) /
         UDP(sport=34964, dport=34964) /
         Raw(load=dcerpc_payload))
sendp(frame, iface=SCAPY_IFACE, verbose=False)

resp = resp_q.get(timeout=3.0)
sniffer.stop()
```

### Issue 2: Wrong UDP Source Port
- **Symptom**: PROFINET device silently drops connect requests, no response.
- **Cause**: Binding UDP socket to ephemeral port 0 instead of 34964.
- **Fix**: `sock.bind((controller_ip, 34964))`. IEC 61784-2 §8.3 mandates port 34964 as both source and destination for CM traffic.

### Issue 3: Ghost AR Lock (`nca_wrong_boot_time`, code 0x1c00000e)
- **Symptom**: Device returns fault 0x1c00000e immediately.
- **Cause**: Previous connection attempts left an active AR in device memory. Device refuses new connects from same IP/MAC until old AR times out.
- **Fix**: Power-cycle TeSys Tera (10 seconds off). Device clears all ARs on boot.
- **Prevention**: Never send a BIND packet before AR Connect — BIND consumes seq=0, AR Connect arrives at seq=1, device treats it as ghost retry.

### Issue 4: SCAPY_IFACE Configuration
- Must be set to NPF GUID, e.g. `r"\Device\NPF_{5F0A0BED-FF5A-49AF-BF8A-3EA3896BD971}"`
- Find your GUID: `python -c "from scapy.all import get_if_list; print(get_if_list())"`
- Script must run as **Administrator** for Npcap raw socket access.

---

## 10. DCE/RPC FAULT CODE REFERENCE

| Code | Name | Meaning / Action |
|------|------|-----------------|
| `0x1c010003` | `nca_unk_if` | Wrong Object UUID. Device endpoint not found. Check `PNIO_CM_OBJ_UUID`. |
| `0x1c010002` | `nca_op_rng_error` | Opnum not registered. Check opnum values (0/2/3/4). |
| `0x1c000009` | `nca_s_fault_ill_inst` | Malformed stub. Block structure/padding error. |
| `0x1c000008` | `nca_s_fault_cancel` | Operation cancelled. |
| `0x1c010001` | `nca_s_unsupported_type` | Transfer syntax mismatch. |
| `0x1c00000e` | `nca_wrong_boot_time` | **Ghost AR lock.** Power-cycle device. |

---

## 11. FINAL WORKING SCRIPT ARCHITECTURE

```
tesys_pn_v4.py
│
├── UUID helpers
│     _u(uuid) → bytes_le wire encoding
│     _pu(bytes, offset) → UUID
│
├── DCE/RPC v4 CL-PDU builder
│     build_request(seq_num, opnum, obj_uuid, if_uuid, act_uuid, stub)
│       → 80-byte header + stub
│
├── PROFINET block builders (all Big-Endian)
│     _block(type, body) → block envelope wrapper
│     build_ar_block(ar_uuid, ctrl_mac, station_name)
│     build_iocr_block(IOCRSpec)
│     build_expected_submodule_block(in_len, out_len)
│     build_alarm_cr_block()
│     build_connect_stub(...)  → all blocks concatenated
│     build_control_stub(ar_uuid, CTRL_PRM_END | CTRL_APP_READY)
│     build_read_stub(ar_uuid, slot, subslot, index, max_len)
│     build_write_stub(ar_uuid, slot, subslot, index, data)
│
├── Cyclic RT frame helpers
│     build_output_rt_frame(out_data, cycle, src_mac, dst_mac)
│     parse_input_rt_frame(raw_bytes, in_len) → Optional[bytes]
│     decode_tesys_input(40_bytes) → dict of measurements
│
├── ScapyTransport class
│     send_recv(payload, label, timeout)
│       → starts AsyncSniffer, sends via sendp, waits for response
│       → bypasses Windows firewall/stack entirely
│
├── PNIOController class
│     step_ar_connect()      seq=0, opnum=0
│     step_prm_end()         seq=1, opnum=2, cmd=0x0008
│     step_application_ready() seq=2, opnum=2, cmd=0x0010
│     acyclic_read(slot, subslot, index)  opnum=3
│     acyclic_write(data, slot, subslot, index)  opnum=4
│     set_output(bytes)      thread-safe output update
│     _tx_loop(stop_event)   background 32ms cyclic TX
│     read_cyclic_data(duration_s)  sniff + decode input frames
│     run()                  full sequence: Connect→Prm→AppRdy→Cyclic
│
├── run_self_tests()          33 assertions, no hardware needed
│
└── main()                    tests → connect → cyclic
```

---

## 12. IMPORTANT I&M RECORD INDICES (ACYCLIC READ)

| Index | Name | Content |
|-------|------|---------|
| `0xF830` | I&M 0 | Manufacturer ID, Order ID, Serial number, HW/SW revision |
| `0xF831` | I&M 1 | Installation tag (location/date) |
| `0xF832` | I&M 2 | Installation date |
| `0xF833` | I&M 3 | Descriptor |
| `0x8028` | PDPortDataReal | Port status/link state |
| `0xB081` | DiagnosisData | Current alarms and diagnostics |
| `0x0000` | SubmoduleRealIdent | Real submodule identification |

---

## 13. TeSys TERA INPUT DATA MAP (40 bytes, Big-Endian)

| Byte Offset | Type | Field | Scale |
|-------------|------|-------|-------|
| 0–1 | UINT16 | Status Word 1 (control state bits) | — |
| 2–3 | UINT16 | Status Word 2 (alarm/warning bits) | — |
| 4–7 | UINT32 | Current as % of FLC | × 0.1 → % |
| 8–9 | UINT16 | Thermal State | — |
| 10 | UINT8 | Last Trip Cause code | — |
| 11 | UINT8 | Motor State | — |
| 12–23 | — | Reserved | — |
| 24–27 | UINT32 | Voltage | × 0.1 → V |
| 28–31 | UINT32 | Active Power | × 0.001 → kW |
| 32–39 | — | Reserved / extended | — |

*Offsets approximate — verify against Schneider Electric PROFINET mapping document for exact firmware version.*

---

## 14. ENVIRONMENT & DEPENDENCIES

```
Python  ≥ 3.10  (uses match/case syntax optional, dataclasses required)
scapy   ≥ 2.5   pip install scapy
Npcap   latest  https://npcap.com  (Windows; WinPcap deprecated)
Run as  Administrator  (required for raw socket / Npcap access)
```

---

## 15. PRE-FLIGHT CHECKLIST

Before every run:
1. Power-cycle TeSys Tera (10 s off) → clears ghost AR locks
2. `ipconfig` confirms `192.168.0.100` on correct NIC
3. `ping 192.168.0.61` succeeds (basic layer-3 reachability)
4. Update `SCAPY_IFACE` constant to match NPF GUID
5. Running as Administrator
6. No other PROFINET controller on same subnet (port 34964 conflict)
7. `python tesys_pn_v4.py` → 33 self-tests should all PASS before attempting connection

---

## 16. FAILURE DECISION TREE

```
python tesys_pn_v4.py
         │
         ├─ Self-test FAIL → Fix the indicated bug (structural issue)
         │
         ├─ TIMEOUT on Connect
         │       ├─ Did you power-cycle the device? → NO → Power-cycle, retry
         │       ├─ ping 192.168.0.61 fails? → Fix network/VLAN routing
         │       ├─ Wrong SCAPY_IFACE? → Run get_if_list(), update constant
         │       └─ Not running as Admin? → Re-run as Administrator
         │
         ├─ FAULT 0x1c010003 nca_unk_if
         │       └─ Object UUID mismatch → Verify PNIO_CM_OBJ_UUID
         │          For TeSys Tera (Anybus stack): dea00000-6c97-11d1-8271-006428ce90d2
         │
         ├─ FAULT 0x1c00000e nca_wrong_boot_time
         │       └─ Ghost AR lock → Power-cycle device, wait 10 s, retry
         │
         ├─ FAULT 0x1c000009 nca_s_fault_ill_inst
         │       └─ Block structure error → Check PROFINET block padding/lengths
         │
         ├─ Connect OK, PrmEnd TIMEOUT
         │       └─ Seq number wrong → Verify seq=1 for PrmEnd
         │
         ├─ Connect + PrmEnd OK, AppReady TIMEOUT
         │       └─ Seq=2, opnum=2, ControlCommand=0x0010 → Verify
         │
         └─ AR established, zero cyclic frames received
                 ├─ Check FRAME_ID_IN = 0x8000 in sniffer filter
                 ├─ Check SCAPY_IFACE — sniff on different interface than send?
                 └─ Run Wireshark: filter "eth.addr == 88:01:f9:35:d9:a2"
                    Look for frames with EtherType 0x8892 from the device
```

---

*End of briefing. Total bugs found and fixed: 18. All 33 self-tests pass without hardware.*
