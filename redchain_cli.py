#!/usr/bin/env python3
"""
RedChain CLI entry point — allows running as `redchain scan -t target.com`
after `pip install .` or `pip install -e .`
"""
import os
import sys

# Ensure the project root is in sys.path so all modules can be found
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from cli import app

def main():
    app()

if __name__ == "__main__":
    main()
