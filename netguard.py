#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from netguard.cli import CLI
CLI().run(sys.argv[1:])
