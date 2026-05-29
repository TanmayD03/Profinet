import unittest
from tesys_tera_profinet import Controller, _rpc_header
import uuid

from tesys_tera_profinet import _rpc_connect_payload, _build_read_req, _build_write_req

class TestProfinetController(unittest.TestCase):
    def test_rpc_header_uuid(self):
        act_uuid = uuid.uuid4()
        header = _rpc_header(0, 1, 12345, act_uuid, 40)

        # Verify length of generated header
        self.assertEqual(len(header), 80, "RPC header must be exactly 80 bytes long")

        # Verify the well known UUIDs exist in the header (The apology fix)
        # We use dea00001 twice (for Object UUID and Interface UUID)
        well_known_uuid = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le

        # Verify header structure flags matches updated 0x23 logic
        self.assertEqual(header[2], 0x23)
        self.assertEqual(header.count(well_known_uuid), 2)
        self.assertIn(act_uuid.bytes_le, header)

    def test_controller_init(self):
        ctrl = Controller(iface="lo", station="test-station")
        self.assertEqual(ctrl._station, "test-station")

    def test_rpc_connect_payload(self):
        ar_uuid = uuid.uuid4()
        ctrl_mac = bytes.fromhex("001122334455")

        payload = _rpc_connect_payload(
            ar_uuid=ar_uuid, session_key=1, ctrl_mac=ctrl_mac,
            ctrl_ip="192.168.0.100", slot=1, subslot=1,
            mod_ident=0x01, sm_ident=0x01, in_len=40, out_len=4,
            sc=32, rr=16
        )

        # Verify the basic block type (ARBlockReq = 0x0101)
        self.assertEqual(payload[0:2], b'\x01\x01')
        self.assertIn(ar_uuid.bytes_le, payload)
        self.assertIn(ctrl_mac, payload)

        # CMInitiatorObjectUUID should be at byte 32 of the ARBlock
        # Which is bytes[36:52] inside payload (after 4 byte block header)
        cm_uuid = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le
        self.assertIn(cm_uuid, payload)

    def test_build_read_req(self):
        ar_uuid = uuid.uuid4()
        payload = _build_read_req(ar_uuid, 1, 0, 1, 0xAFF0, 2)

        # BlockType 0x0081 (RecordReadReq)
        self.assertEqual(payload[0:2], b'\x00\x81')
        self.assertIn(ar_uuid.bytes_le, payload)

    def test_build_write_req(self):
        ar_uuid = uuid.uuid4()
        data = b'\x00\x01\x02\x03'
        payload = _build_write_req(ar_uuid, 1, 0, 1, 0xAFF0, data, 2)

        # BlockType 0x0082 (RecordWriteReq)
        self.assertEqual(payload[0:2], b'\x00\x82')
        self.assertIn(ar_uuid.bytes_le, payload)
        self.assertIn(data, payload)

if __name__ == '__main__':
    unittest.main()
