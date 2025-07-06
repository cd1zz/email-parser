from __future__ import annotations

import hashlib
import logging
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass
class FileAnalysis:
    filename: Optional[str]
    declared_mime_type: Optional[str]
    size: int
    detected_type: str
    confidence: float
    mime_type: str
    file_extension: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)
    hashes: Dict[str, str] = field(default_factory=dict)
    encoding_info: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class ContentAnalyzer:
    """Basic content analysis for file type detection and metadata extraction."""

    MAGIC_SIGNATURES: Dict[str, list[tuple]] = {
        "png": [(b"\x89PNG\r\n\x1a\n", 0)],
        "jpeg": [(b"\xff\xd8\xff", 0)],
        "gif": [(b"GIF87a", 0), (b"GIF89a", 0)],
        "bmp": [(b"BM", 0)],
        "tiff": [(b"II*\x00", 0), (b"MM\x00*", 0)],
        "ico": [(b"\x00\x00\x01\x00", 0)],
        "webp": [(b"RIFF", 0, b"WEBP", 8)],
        "pdf": [(b"%PDF-", 0)],
        "msg": [(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0)],
        "eml": [(b"Return-Path:", 0), (b"From:", 0)],
    }

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def analyze_content(
        self, data: bytes, filename: str | None = None, declared_mime: str | None = None
    ) -> FileAnalysis:
        if not data:
            return FileAnalysis(
                filename=filename,
                declared_mime_type=declared_mime,
                size=0,
                detected_type="unknown",
                confidence=0.0,
                mime_type="application/octet-stream",
                file_extension=None,
                error="No data provided",
            )

        detected_type, confidence = self._detect_by_magic_bytes(data)
        analysis = FileAnalysis(
            filename=filename,
            declared_mime_type=declared_mime,
            size=len(data),
            detected_type=detected_type,
            confidence=confidence,
            mime_type=self._get_mime_type(detected_type),
            file_extension=os.path.splitext(filename)[1].lstrip(".") if filename else None,
        )
        analysis.hashes = self._generate_hashes(data)
        analysis.metadata = self._extract_metadata(data, detected_type)
        analysis.encoding_info = self._analyze_encoding(data)
        return analysis

    def _detect_by_magic_bytes(self, data: bytes) -> Tuple[str, float]:
        if len(data) < 16:
            return "unknown", 0.0
        for ftype, sigs in self.MAGIC_SIGNATURES.items():
            for sig in sigs:
                if len(sig) == 2:
                    signature, offset = sig
                    if data[offset : offset + len(signature)] == signature:
                        return ftype, 0.9
                elif len(sig) == 4:
                    sig1, off1, sig2, off2 = sig
                    if (
                        data[off1 : off1 + len(sig1)] == sig1
                        and data[off2 : off2 + len(sig2)] == sig2
                    ):
                        return ftype, 0.95
        return "unknown", 0.0

    def _get_mime_type(self, detected_type: str) -> str:
        mime_map = {
            "png": "image/png",
            "jpeg": "image/jpeg",
            "gif": "image/gif",
            "bmp": "image/bmp",
            "tiff": "image/tiff",
            "webp": "image/webp",
            "pdf": "application/pdf",
            "msg": "application/vnd.ms-outlook",
            "eml": "message/rfc822",
        }
        return mime_map.get(detected_type, "application/octet-stream")

    def _generate_hashes(self, data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def _extract_metadata(self, data: bytes, file_type: str) -> Dict[str, Any]:
        metadata: Dict[str, Any] = {}
        if file_type == "pdf" and data.startswith(b"%PDF-"):
            match = re.search(rb"%PDF-(\d+\.\d+)", data[:10])
            if match:
                metadata["pdf_version"] = match.group(1).decode()
        return metadata

    def _analyze_encoding(self, data: bytes) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        ascii_ratio = sum(1 for b in data[:1024] if 32 <= b <= 126) / min(len(data), 1024)
        info["ascii_ratio"] = round(ascii_ratio, 3)
        info["entropy"] = round(self._calculate_entropy(data[:4096]), 3)
        return info

    def _calculate_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / length
                entropy -= p * (p.bit_length() - 1)  # approximate log2
        return entropy
