from __future__ import annotations

import argparse
import json
from pathlib import Path

from .parser import EmailParser


def main() -> None:
    parser = argparse.ArgumentParser(description="Email parsing utility")
    parser.add_argument("file", type=Path, help="Input email file (.eml or .msg)")
    args = parser.parse_args()

    ep = EmailParser()
    data = args.file.read_bytes()
    result = ep.parse(data, args.file.name)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":  # pragma: no cover
    main()
