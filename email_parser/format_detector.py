from __future__ import annotations

import logging
import os
from typing import Optional, Tuple


class EmailFormatDetector:
    """Detect email format using simple heuristics and magic bytes."""

    MAGIC_SIGNATURES = {
        "msg": [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
        "eml": [b"Return-Path:", b"From:"] ,
    }

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def detect_by_magic_bytes(self, data: bytes) -> Optional[str]:
        if len(data) < 4:
            return None
        header = data[:512]
        for fmt, sigs in self.MAGIC_SIGNATURES.items():
            for sig in sigs:
                if header.startswith(sig):
                    return fmt
        return None

    def detect_format(self, data: bytes, filename: str | None = None) -> Tuple[str, float]:
        fmt = self.detect_by_magic_bytes(data)
        if not fmt and filename:
            lower = filename.lower()
            if lower.endswith(".msg"):
                fmt = "msg"
            elif lower.endswith(".eml"):
                fmt = "eml"
        if not fmt:
            fmt = "eml"  # default
        confidence = 0.9 if fmt != "eml" else 0.5
        return fmt, confidence
