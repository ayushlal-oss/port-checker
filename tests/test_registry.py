import unittest

from portchecker import registry
from tests import fixtures as fx


class RegistryTest(unittest.TestCase):
    def setUp(self):
        self.rows = registry.parse(fx.PORTS_MD)

    def test_every_section(self):
        self.assertEqual({r["section"] for r in self.rows},
                         {"registered", "phasedoc", "robodoc", "transient", "reserved"})

    def test_lists_and_open_ranges(self):
        win = next(r for r in self.rows if r["label"] == "Windows")
        self.assertEqual(win["ports"], [(135, 135), (445, 445), (5040, 5040), (7680, 7680), (49664, 65535)])
        self.assertEqual(registry.single_ports(win), [135, 445, 5040, 7680], "open ranges are not expanded")
        ora = next(r for r in self.rows if r["label"].startswith("Oracle"))
        self.assertEqual(registry.single_ports(ora), [1521, 8080])

    def test_next_free_rows_and_names(self):
        nf = [(r["section"], registry.single_ports(r)) for r in self.rows if r["next_free"]]
        self.assertEqual(nf, [("phasedoc", [6790]), ("robodoc", [7802])])
        reg = [r for r in self.rows if r["section"] == "registered"]
        self.assertEqual([r["name"] for r in reg], ["phasedoc-a", "app-a", "app-b", "app-old"])
        self.assertEqual(reg[0]["project"], "A cockpit", "wiki links stripped")
        self.assertEqual(reg[3]["status"], "retired")

    def test_crlf_and_dataview_ignored(self):
        self.assertIn("\r\n", fx.PORTS_MD)
        self.assertFalse(any("TABLE" in r["label"] for r in self.rows))

    def test_defaults_overlaid_by_user_config(self):
        import json, os, tempfile
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.json")
        cfg = registry.load_config(p)  # no user file: packaged defaults only
        self.assertEqual(list(cfg["pools"]), ["app"])
        with open(p, "w", encoding="utf-8") as f:
            json.dump({"pools": {"web": {"start": 3000, "end": 3999, "section": "registered"}},
                       "ignore": [{"process": "x.exe"}], "_help": "skip me"}, f)
        cfg = registry.load_config(p)
        self.assertEqual(list(cfg["pools"]), ["web"], "user pools replace defaults")
        self.assertIn({"process": "x.exe"}, cfg["ignore"])
        self.assertIn("svchost.exe", {i["process"] for i in cfg["ignore"]}, "ignore lists add up")
        self.assertNotIn("_help", {k for k in cfg if k == "_help" and cfg[k] == "skip me"})

if __name__ == "__main__":
    unittest.main()
