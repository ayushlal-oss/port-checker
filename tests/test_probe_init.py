"""Web-page detection, and first run on a machine with nothing set up."""
import contextlib
import io
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from portchecker import cli, probe, registry


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><head><title>My &amp; App</title></head><body>hi</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProbeTest(unittest.TestCase):
    def test_http_server_found_with_title(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            res = probe.probe(port, ["127.0.0.1"])
            self.assertEqual(res["url"], f"http://127.0.0.1:{port}/")
            self.assertEqual(res["title"], "My & App")
        finally:
            srv.shutdown()
            srv.server_close()

    def test_silent_tcp_socket_gets_no_url(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        try:
            self.assertIsNone(probe.probe(s.getsockname()[1], ["127.0.0.1"]))
        finally:
            s.close()

    def test_host_choice(self):
        self.assertEqual(probe.host_for(["0.0.0.0", "::"]), "127.0.0.1")
        self.assertEqual(probe.host_for(["::1"]), "::1")
        self.assertEqual(probe.host_for(["192.168.1.5"]), "192.168.1.5")


class InitTest(unittest.TestCase):
    def test_init_then_use_in_empty_home(self):
        d = tempfile.mkdtemp()
        old = {k: os.environ.get(k) for k in ("PORTS_HOME", "PORTS_CONFIG", "PORTS_MD")}
        os.environ["PORTS_HOME"] = d
        for k in ("PORTS_CONFIG", "PORTS_MD"):
            os.environ.pop(k, None)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["init"]), 0)
                self.assertEqual(cli.main(["init"]), 0, "second run leaves files alone")
            self.assertTrue(os.path.exists(os.path.join(d, "config.json")))
            cfg = registry.load_config()
            _, text = registry.read(None, cfg)
            self.assertEqual({r["section"] for r in registry.parse(text + "| 1 | x | | | | |\n")} >= {"reserved"}, True)
            self.assertIn("## Registered", text)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
