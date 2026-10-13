#!/usr/bin/env python3
"""Entry point for the SnowSCSI external test suite (pure stdlib).

Usage:
    python3 tools/ext-test/run.py               # discover + run all tests
    python3 tools/ext-test/run.py TestISO       # filter by name

Environment:
    SNOWSCSI_BIN   path to the snowscsi binary (default: target/{debug,release})
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)


def main():
    loader = unittest.TestLoader()
    suite = loader.discover(_HERE, pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
