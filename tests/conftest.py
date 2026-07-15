import os
import sys

# Put the package root on sys.path so `import anchor_auth` resolves under a bare
# `pytest tests/` invocation (the pytest console script doesn't add cwd).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
