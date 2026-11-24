"""Entry for the ~/bin/ports shims: python ports.py <verb> ..."""
import sys

from portchecker.cli import main

sys.exit(main())
