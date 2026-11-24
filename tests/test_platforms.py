"""Parsers for the Linux (/proc) and macOS (lsof/ps) backends, and non-English Windows netstat."""
import unittest

from portchecker import scan

PROC_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1FBB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41234 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999 1 0000000000000000 100 0 0 10 0
   2: 0100007F:1FBB 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 41299 1 0000000000000000 20 4 30 10 -1
"""
PROC_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5555 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 5556 1 0000000000000000 100 0 0 10 0
"""
LSOF = """p501
n127.0.0.1:3000
n[::1]:3000
p88
n*:5000
p77
n127.0.0.1:5432->127.0.0.1:60000
"""
PS = """    1     0 /sbin/launchd
  501     1 /usr/local/bin/node
   88     1 /System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter
"""
NETSTAT_DE = """
Aktive Verbindungen

  Proto  Lokale Adresse         Remoteadresse          Status           PID
  TCP    127.0.0.1:8080         0.0.0.0:0              ABHÖREN          4321
  TCP    127.0.0.1:8080         127.0.0.1:55000        HERGESTELLT      4321
  TCP    [::]:443               [::]:0                 ABHÖREN          4
"""


class LinuxTest(unittest.TestCase):
    def test_hex_addresses(self):
        self.assertEqual(scan.hex_addr("0100007F"), "127.0.0.1")
        self.assertEqual(scan.hex_addr("00000000000000000000000001000000"), "::1")
        self.assertEqual(scan.hex_addr("0000000000000000FFFF00000100007F"), "127.0.0.1", "v4-mapped v6")

    def test_proc_net(self):
        rows = scan.parse_proc_net(PROC_TCP, "tcp", {"41234": 1200})
        self.assertEqual([(r["addr"], r["port"], r["pid"]) for r in rows], [("127.0.0.1", 8123, 1200), ("0.0.0.0", 22, 0)])
        rows6 = scan.parse_proc_net(PROC_TCP6, "tcp", {})
        self.assertEqual([(r["addr"], r["port"]) for r in rows6], [("::1", 3000), ("::", 80)])

    def test_proc_stat_name_with_spaces(self):
        self.assertEqual(scan.parse_proc_stat("4242 (Web Content) S 4100 4242 4242 0 -1"), ("Web Content", 4100))


class MacTest(unittest.TestCase):
    def test_lsof(self):
        rows = scan.parse_lsof(LSOF, "tcp")
        self.assertEqual([(r["addr"], r["port"], r["pid"]) for r in rows],
                         [("127.0.0.1", 3000, 501), ("::1", 3000, 501), ("0.0.0.0", 5000, 88)])

    def test_ps(self):
        p = scan.parse_ps(PS)
        self.assertEqual(p[501], {"name": "node", "ppid": 1})
        self.assertEqual(p[88]["name"], "ControlCenter")


class WindowsLocaleTest(unittest.TestCase):
    def test_german_netstat(self):
        rows = scan.parse_netstat(NETSTAT_DE)
        self.assertEqual([(r["addr"], r["port"], r["pid"]) for r in rows], [("127.0.0.1", 8080, 4321), ("::", 443, 4)])


if __name__ == "__main__":
    unittest.main()
