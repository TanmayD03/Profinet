import unittest
from tesys_tera_profinet import Controller, _rpc_header
import uuid

class TestProfinetController(unittest.TestCase):
    def test_rpc_header_uuid(self):
        act_uuid = uuid.uuid4()
        header = _rpc_header(0, 1, 12345, act_uuid, 40)

        # Verify length of generated header
        self.assertEqual(len(header), 80, "RPC header must be exactly 80 bytes long")

        # Verify the well known UUIDs exist in the header (The apology fix)
        well_known_uuid1 = uuid.UUID("dea00000-6c97-11d1-8271-006428ce90d2").bytes_le
        well_known_uuid2 = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le

        self.assertIn(well_known_uuid1, header)
        self.assertIn(well_known_uuid2, header)
        self.assertIn(act_uuid.bytes_le, header)

    def test_controller_init(self):
        ctrl = Controller(iface="lo", station="test-station")
        self.assertEqual(ctrl._station, "test-station")

if __name__ == '__main__':
    unittest.main()
