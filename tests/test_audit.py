import unittest

from portchecker import audit, cli
from tests import fixtures as fx

CLEAN_NETSTAT = fx.NETSTAT.replace("0.0.0.0:8792 ", "127.0.0.1:8792 ").replace(
    "  TCP    127.0.0.1:5555         0.0.0.0:0              LISTENING       777\n", "")


def kinds(snap):
    return {(f["kind"], f["name"]) for f in audit.run(snap)}


class AuditTest(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(audit.run(fx.snap(netstat=CLEAN_NETSTAT)), [])

    def test_unregistered_listener_respects_ignore_list(self):
        k = kinds(fx.snap())
        self.assertIn(("unregistered-listener", "mystery.exe"), k)
        self.assertNotIn(("unregistered-listener", "StudioMCP.exe"), k)
        self.assertFalse(any(n == "svchost.exe" for _, n in k))

    def test_exposed(self):
        self.assertIn(("exposed", "app-b"), kinds(fx.snap()))

    def test_registered_down(self):
        s = fx.snap(netstat=CLEAN_NETSTAT.replace("127.0.0.1:7801 ", "127.0.0.1:9999 "))
        self.assertIn(("registered-down", "robodoc-hub"), kinds(s))

    def test_pm2_kinds(self):
        apps = [dict(a) for a in fx.APPS] + [{"name": "stray", "pid": 777, "status": "online", "cwd": "", "port_hint": None}]
        apps[1]["status"] = "errored"
        apps = [a for a in apps if a["name"] != "robodoc-hub"]
        k = kinds(fx.snap(netstat=CLEAN_NETSTAT, apps=apps))
        self.assertIn(("pm2-unregistered", "stray"), k)
        self.assertIn(("pm2-not-online", "app-a"), k)
        self.assertIn(("pm2-missing", "robodoc-hub"), k)
        self.assertNotIn(("pm2-missing", "app-old"), k, "retired rows are not expected in pm2")

    def test_port_mismatch(self):
        s = fx.snap(netstat=CLEAN_NETSTAT.replace("127.0.0.1:8791 ", "127.0.0.1:8899 ").replace("[::1]:8791", "[::1]:8899"))
        self.assertIn(("port-mismatch", "app-a"), kinds(s))

    def test_unsaved_only_with_live_pm2(self):
        saved = [{"name": a["name"]} for a in fx.APPS[:-1]] + [{"name": "ghost"}]
        k = kinds(fx.snap(netstat=CLEAN_NETSTAT, saved=saved))
        self.assertIn(("unsaved", "robodoc-hub"), k)
        self.assertIn(("unsaved", "ghost"), k)
        self.assertNotIn("unsaved", {x for x, _ in kinds(fx.snap(netstat=CLEAN_NETSTAT, saved=saved, live=False))})

    def test_next_free_stale(self):
        md = fx.PORTS_MD.replace("| 6790 | (next free) |", "| 6795 | (next free) |")
        self.assertIn(("next-free-stale", "phasedoc"), kinds(fx.snap(md=md, netstat=CLEAN_NETSTAT)))

    def test_exit_code(self):
        import contextlib, io
        import portchecker.model as m
        orig = m.collect
        with contextlib.redirect_stdout(io.StringIO()):
            self._exit_codes(m)
        m.collect = orig

    def _exit_codes(self, m):
        orig = m.collect
        try:
            m.collect = lambda **kw: fx.snap(netstat=CLEAN_NETSTAT)
            self.assertEqual(cli.main(["audit", "--json"]), 0)
            m.collect = lambda **kw: fx.snap()
            self.assertEqual(cli.main(["audit", "--json"]), 1)
        finally:
            m.collect = orig


if __name__ == "__main__":
    unittest.main()
