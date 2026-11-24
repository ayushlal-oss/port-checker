"""pm2 entry point: python serve.py [port]."""
import sys

from portchecker import web

web.serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8801)
