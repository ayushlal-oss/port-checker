import json
import unittest

from portchecker import pm, scan
from tests import fixtures as fx


class ScanTest(unittest.TestCase):
    def test_netstat_listening_v4_v6_udp(self):
        rows = scan.parse_netstat(fx.NETSTAT)
        tcp = [(r["addr"], r["port"]) for r in rows if r["proto"] == "tcp"]
        self.assertIn(("127.0.0.1", 6789), tcp)
        self.assertIn(("::", 135), tcp)
        self.assertIn(("::1", 8791), tcp)
        self.assertEqual(sum(1 for r in rows if r["proto"] == "tcp" and r["port"] == 6789), 1, "ESTABLISHED skipped")
        self.assertEqual(sorted(r["family"] for r in rows if r["proto"] == "udp"), ["v4", "v6"])

    def test_exposure(self):
        self.assertEqual(scan.exposure("127.0.0.1"), "loopback")
        self.assertEqual(scan.exposure("::"), "all")
        self.assertEqual(scan.exposure("192.168.0.156"), "lan")

    def test_processes_and_chain(self):
        procs = scan.parse_processes(json.dumps([{"ProcessId": 5, "ParentProcessId": 4, "Name": "a"},
                                                 {"ProcessId": 4, "ParentProcessId": 5, "Name": "b"}]))
        self.assertEqual(scan.chain(5, procs), [5, 4], "cycle from pid reuse stops")
        self.assertEqual(scan.chain(848, fx.PROCS), [848, 100, 1])
        self.assertEqual(scan.parse_processes(json.dumps({"ProcessId": 9, "ParentProcessId": 0, "Name": "x"})),
                         {9: {"name": "x", "ppid": 0}}, "single object, not a list")

    def test_excluded(self):
        self.assertEqual(scan.parse_excluded(fx.NETSH), [(50000, 50059)])


class Pm2Test(unittest.TestCase):
    JLIST = ("[PM2] noise line\n" + json.dumps([{
        "name": "app-a", "pid": 900,
        "pm2_env": {"status": "online", "pm_cwd": "C:/x", "PHASEDOC_PORT": "6789",
                    "env": {"OPENAI_API_KEY": "sk-secret", "PORT": "8791"}}}]))

    def test_jlist_keeps_only_safe_fields(self):
        apps = pm.parse_jlist(self.JLIST)
        self.assertEqual(apps[0]["name"], "app-a")
        self.assertEqual(apps[0]["status"], "online")
        self.assertNotIn("sk-secret", json.dumps(apps), "pm2 env (API keys) must never leave pm.py")
        self.assertIn(apps[0]["port_hint"], (8791, 6789))

    def test_unsaved(self):
        new, gone = pm.unsaved([{"name": "a"}, {"name": "b"}], [{"name": "b"}, {"name": "c"}])
        self.assertEqual((new, gone), (["a"], ["c"]))

    def test_from_dump_stale_pid_is_not_online(self):
        apps = pm.from_dump([{"name": "x", "pid_path": "Z:/nope.pid", "cwd": "", "env": {}}], fx.PROCS)
        self.assertEqual(apps[0]["status"], "stopped?")


if __name__ == "__main__":
    unittest.main()
