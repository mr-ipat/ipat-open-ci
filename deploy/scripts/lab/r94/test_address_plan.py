import unittest
from check_address_plan import evaluate


class OfflineAddressPlanTests(unittest.TestCase):
    def test_private_separate_site_vlan_is_plan_only(self):
        actual = evaluate("10.253.77.0/30", "192.168.77.10",
                          ["192.168.77.0/24", "10.40.0.0/16"])
        self.assertEqual(actual["result"], "PLAN_ONLY")
        self.assertFalse(actual["eligible_for_live_deployment"])

    def test_rejects_existing_network_overlap(self):
        with self.assertRaisesRegex(ValueError, "overlaps"):
            evaluate("10.40.1.0/30", "192.168.77.10", ["10.40.0.0/16"])

    def test_rejects_public_telnet_endpoint(self):
        with self.assertRaisesRegex(ValueError, "private"):
            evaluate("10.253.77.0/30", "198.51.100.109", [])

    def test_rejects_tunnel_contains_olt(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            evaluate("10.253.77.0/30", "10.253.77.2", [])

    def test_rejects_bad_address(self):
        with self.assertRaises(ValueError):
            evaluate("not-a-subnet", "192.168.77.10", [])


if __name__ == "__main__":
    unittest.main()
