#!/usr/bin/env python3
"""
Entry point for running the standalone CLI from the function-app directory.
Usage: python -m standalone [args]
"""

from .cli import main

if __name__ == "__main__":
    main()