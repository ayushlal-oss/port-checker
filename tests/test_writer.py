import os
import tempfile
import unittest

from portchecker import registry, writer
from tests import fixtures as fx


class WriterTest(unittest.TestCase):
    def setUp(self):
        self.s = fx.snap()
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "Ports.md")
        with open(self.path, "w", encoding="utf-8", newline="") as f:
            f.write(fx.PORTS_MD)
        writer.BACKUPS = os.path.join(self.tmp, "backups")

    def test_claim_phasedoc_adds_both_rows_and_moves_next_free(self):
        new = writer.plan_claim(fx.PORTS_MD, self.s, 6790, "phasedoc", "phasedoc-b", "B", "pm2 start b")
        rows = registry.parse(new)
        sec = {(r["section"], r["name"]) for r in rows if 6790 in registry.single_ports(r) and not r["next_free"]}
        self.assertEqual(sec, {("registered", "phasedoc-b"), ("phasedoc", "phasedoc-b")})
        nf = [registry.single_ports(r) for r in rows if r["next_free"] and r["section"] == "phasedoc"]
        self.assertEqual(nf, [[6791]])
        phasedoc_rows = [r for r in rows if r["section"] == "phasedoc"]
        self.assertTrue(phasedoc_rows[-1]["next_free"], "new row goes above the (next free) row")
        self.assertIn("\r\n", new)
        self.assertNotIn("\n\n\n", new.replace("\r\n", "\n"))

    def test_claim_app_and_robodoc(self):
        new = writer.plan_claim(fx.PORTS_MD, self.s, 8794, "app", "tool", "Tool", "pm2 start t")
        self.assertIn("| 8794 | tool | [[Tool]] | `pm2 start t` | online |", new)
        new = writer.plan_claim(fx.PORTS_MD, self.s, 7802, "robodoc", "robodoc-x", "X", kind="project")
        nf = [registry.single_ports(r) for r in registry.parse(new) if r["next_free"] and r["section"] == "robodoc"]
        self.assertEqual(nf, [[7803]])

    def test_claim_taken_or_wrong_pool_refused(self):
        for port, pool, code in ((6789, "phasedoc", 2), (8793, "app", 2), (8080, "app", 2), (7000, "app", 4)):
            with self.assertRaises(writer.Refused) as e:
                writer.plan_claim(fx.PORTS_MD, self.s, port, pool, "n", "P")
            self.assertEqual(e.exception.code, code, port)

    def test_retire(self):
        new = writer.plan_retire(fx.PORTS_MD, 8791)
        row = next(r for r in registry.parse(new) if r["name"] == "app-a")
        self.assertEqual(row["status"], "retired")
        s = fx.snap(md=new, netstat=fx.NETSTAT.replace("127.0.0.1:8791 ", "127.0.0.1:9999 ").replace("[::1]:8791", "[::1]:9998"))
        self.assertEqual(s.row(8791)["verdict"], "retired")
        self.assertNotEqual(s.pool_next("app"), 8791)

    def test_commit_backup_and_changed_guard(self):
        new = writer.plan_retire(fx.PORTS_MD, 8791)
        bak = writer.commit(self.path, fx.PORTS_MD, new)
        self.assertTrue(os.path.exists(bak))
        with open(self.path, encoding="utf-8", newline="") as f:
            self.assertEqual(f.read(), new)
        with self.assertRaises(writer.Refused) as e:  # file now differs from what the caller read
            writer.commit(self.path, fx.PORTS_MD, new)
        self.assertEqual(e.exception.code, 3)
        with open(self.path, encoding="utf-8", newline="") as f:
            self.assertEqual(f.read(), new, "refused write leaves the file untouched")

    def test_cli_claim_dry_run_and_write(self):
        import contextlib, io
        import portchecker.model as m
        from portchecker import cli
        orig, env = m.collect, os.environ.get("PORTS_MD")
        os.environ["PORTS_MD"] = self.path
        m.collect = lambda **kw: fx.snap()
        try:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli.main(["claim", "8794", "--pool", "app", "--name", "tool", "--project", "Tool", "--cmd", "pm2 start t"])
            self.assertEqual(code, 0)
            self.assertIn("+| 8794 | tool |", buf.getvalue())
            with open(self.path, encoding="utf-8", newline="") as f:
                self.assertEqual(f.read(), fx.PORTS_MD, "dry run writes nothing")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["claim", "8794", "--pool", "app", "--name", "tool", "--project", "Tool", "--write"]), 0)
            with open(self.path, encoding="utf-8", newline="") as f:
                self.assertIn("| 8794 | tool |", f.read())
        finally:
            m.collect = orig
            if env is None:
                os.environ.pop("PORTS_MD", None)
            else:
                os.environ["PORTS_MD"] = env


if __name__ == "__main__":
    unittest.main()
