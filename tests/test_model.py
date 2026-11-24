import unittest

from portchecker import model
from tests import fixtures as fx


class ModelTest(unittest.TestCase):
    def setUp(self):
        self.s = fx.snap()

    def v(self, port):
        return self.s.row(port)["verdict"]

    def test_six_verdicts(self):
        self.assertEqual(self.v(6789), model.IN_USE)
        self.assertEqual(self.v(8793), model.RETIRED)
        self.assertEqual(self.v(8080), model.RESERVED)
        self.assertEqual(self.v(50010), model.EXCLUDED)
        self.assertEqual(self.v(9333), model.TRANSIENT)
        self.assertEqual(self.v(6790), model.FREE, "a '(next free)' row does not take the port")
        self.assertEqual(self.v(7000), model.FREE)
        down = fx.snap(netstat=fx.NETSTAT.replace("127.0.0.1:8791 ", "127.0.0.1:9999 ").replace("[::1]:8791", "[::1]:9998"))
        self.assertEqual(down.row(8791)["verdict"], model.DOWN)

    def test_owner_through_process_tree(self):
        r = self.s.row(6789)
        self.assertEqual((r["pm2"], r["process"], r["exposure"]), ("phasedoc-a", "python.exe", "loopback"))
        self.assertEqual(self.s.row(8792)["exposure"], "all")
        self.assertEqual(self.s.app_ports(), {"phasedoc-a": [6789], "app-a": [8791], "app-b": [8792], "robodoc-hub": [7801]})

    def test_rows_skip_dynamic_range(self):
        ports = [r["port"] for r in self.s.rows()]
        self.assertIn(13469, ports)  # below 49152: listed
        self.assertIn(1521, ports)   # registered, not listening: listed
        self.assertNotIn(49664, ports)

    def test_next_is_above_highest_and_always_free(self):
        self.assertEqual(self.s.pool_next("phasedoc"), 6790)
        self.assertEqual(self.s.pool_next("robodoc"), 7802)
        self.assertEqual(self.s.pool_next("app"), 8794, "8793 is retired: never reused")
        busy = fx.snap(netstat=fx.NETSTAT + "  TCP    127.0.0.1:8794         0.0.0.0:0              LISTENING       777\n")
        self.assertEqual(busy.pool_next("app"), 8795, "an unregistered listener is skipped too")
        for name in fx.CFG["pools"]:
            n = self.s.pool_next(name)
            self.assertEqual(self.s.row(n)["verdict"], model.FREE)


if __name__ == "__main__":
    unittest.main()
