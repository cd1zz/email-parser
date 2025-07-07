# ============================================================================
# email_parser/content_analyzer.py
# ============================================================================

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
    """Enhanced content analysis for file type detection and metadata extraction."""

    MAGIC_SIGNATURES: Dict[str, list[tuple]] = {
        # Images
        "png": [(b"\x89PNG\r\n\x1a\n", 0)],
        "jpeg": [(b"\xff\xd8\xff", 0)],
        "gif": [(b"GIF87a", 0), (b"GIF89a", 0)],
        "bmp": [(b"BM", 0)],
        "tiff": [(b"II*\x00", 0), (b"MM\x00*", 0)],
        "ico": [(b"\x00\x00\x01\x00", 0)],
        "webp": [(b"RIFF", 0, b"WEBP", 8)],
        
        # Documents
        "pdf": [(b"%PDF-", 0)],
        "docx": [(b"PK\x03\x04", 0)],
        "doc": [(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0)],
        "xlsx": [(b"PK\x03\x04", 0)],
        "xls": [(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0)],
        "rtf": [(b"{\\rtf1", 0)],
        
        # Archives
        "zip": [(b"PK\x03\x04", 0), (b"PK\x05\x06", 0), (b"PK\x07\x08", 0)],
        "rar": [(b"Rar!\x1a\x07\x00", 0), (b"Rar!\x1a\x07\x01\x00", 0)],
        "7z": [(b"7z\xbc\xaf\x27\x1c", 0)],
        "gzip": [(b"\x1f\x8b", 0)],
        
        # Executables
        "exe": [(b"MZ", 0)],
        "dll": [(b"MZ", 0)],
        "elf": [(b"\x7fELF", 0)],
        
        # Email formats
        "msg": [(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0)],
        "eml": [(b"Return-Path:", 0), (b"From:", 0), (b"Received:", 0)],
        "mbox": [(b"From ", 0)],
        
        # Other
        "sqlite": [(b"SQLite format 3\x00", 0)],
        "xml": [(b"<?xml", 0), (b"\xef\xbb\xbf<?xml", 0)],
        "html": [(b"<!DOCTYPE html", 0), (b"<html", 0), (b"<HTML", 0)],
        "json": [(b"{", 0), (b"[", 0)],
    }

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger

    def analyze_content(
        self, data: bytes, filename: str = None, declared_mime: str = None
    ) -> FileAnalysis:
        """Comprehensive content analysis for type detection and metadata."""
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

        analysis = FileAnalysis(
            filename=filename,
            declared_mime_type=declared_mime,
            size=len(data),
            detected_type="unknown",
            confidence=0.0,
            mime_type="application/octet-stream",
            file_extension=os.path.splitext(filename)[1].lstrip(".") if filename else None,
        )

        try:
            # Generate hashes
            analysis.hashes = self._generate_hashes(data)
            
            # Detect file type by magic bytes
            detected_type, confidence = self._detect_by_magic_bytes(data)
            analysis.detected_type = detected_type
            analysis.confidence = confidence
            
            # Enhanced detection for Office documents
            if detected_type in ["docx", "xlsx", "pptx"] or (detected_type == "zip" and filename):
                office_type = self._detect_office_type(data, filename)
                if office_type:
                    analysis.detected_type = office_type
                    analysis.confidence = min(confidence + 0.2, 1.0)
            
            # Set MIME type
            analysis.mime_type = self._get_mime_type(analysis.detected_type)
            
            # Content-specific analysis
            if analysis.detected_type != "unknown":
                analysis.metadata = self._extract_metadata(data, analysis.detected_type)
            
            # Encoding analysis
            analysis.encoding_info = self._analyze_encoding(data)
            
            self.logger.debug(f"Content analysis complete: {analysis.detected_type} (confidence: {analysis.confidence:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error in content analysis: {e}")
            analysis.error = str(e)

        return analysis

    def _detect_by_magic_bytes(self, data: bytes) -> Tuple[str, float]:
        """Detect file type using magic byte signatures."""
        if len(data) < 16:
            return "unknown", 0.0

        for file_type, signatures in self.MAGIC_SIGNATURES.items():
            for sig_data in signatures:
                if len(sig_data) == 2:  # (signature, offset)
                    signature, offset = sig_data
                    if len(data) > offset + len(signature):
                        if data[offset:offset + len(signature)] == signature:
                            return file_type, 0.9
                elif len(sig_data) == 4:  # (signature1, offset1, signature2, offset2)
                    sig1, off1, sig2, off2 = sig_data
                    if (len(data) > off1 + len(sig1) and len(data) > off2 + len(sig2)):
                        if (data[off1:off1 + len(sig1)] == sig1 and 
                            data[off2:off2 + len(sig2)] == sig2):
                            return file_type, 0.95

        return "unknown", 0.0

    def _detect_office_type(self, data: bytes, filename: str) -> Optional[str]:
        """Enhanced detection for Office documents."""
        if not filename:
            return None

        filename_lower = filename.lower()
        
        if filename_lower.endswith(('.docx', '.docm')):
            if self._is_office_document(data, 'word'):
                return 'docx'
        elif filename_lower.endswith(('.xlsx', '.xlsm')):
            if self._is_office_document(data, 'excel'):
                return 'xlsx'
        elif filename_lower.endswith(('.pptx', '.pptm')):
            if self._is_office_document(data, 'powerpoint'):
                return 'pptx'

        return None

    def _is_office_document(self, data: bytes, office_type: str) -> bool:
        """Check if ZIP data contains Office document structure."""
        try:
            content_str = data[:2048].decode('latin-1', errors='ignore')
            
            office_indicators = {
                'word': ['word/', 'document.xml'],
                'excel': ['xl/', 'workbook.xml'],
                'powerpoint': ['ppt/', 'presentation.xml']
            }
            
            indicators = office_indicators.get(office_type, [])
            return any(indicator in content_str for indicator in indicators)
            
        except Exception:
            return False

    def _get_mime_type(self, detected_type: str) -> str:
        """Get MIME type for detected file type."""
        mime_map = {
            "png": "image/png",
            "jpeg": "image/jpeg",
            "gif": "image/gif",
            "bmp": "image/bmp",
            "tiff": "image/tiff",
            "webp": "image/webp",
            "pdf": "application/pdf",
            "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "doc": "application/msword",
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "xls": "application/vnd.ms-excel",
            "zip": "application/zip",
            "rar": "application/x-rar-compressed",
            "7z": "application/x-7z-compressed",
            "exe": "application/x-msdownload",
            "dll": "application/x-msdownload",
            "html": "text/html",
            "xml": "text/xml",
            "json": "application/json",
            "msg": "application/vnd.ms-outlook",
            "eml": "message/rfc822",
            "mbox": "application/mbox",
        }
        return mime_map.get(detected_type, "application/octet-stream")

    def _generate_hashes(self, data: bytes) -> Dict[str, str]:
        """Generate cryptographic hashes for the content."""
        hashes = {}
        try:
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            self.logger.debug(f"Error generating hashes: {e}")
        return hashes

    def _extract_metadata(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Extract basic metadata based on file type."""
        metadata = {}

        try:
            if file_type == "pdf":
                metadata.update(self._extract_pdf_metadata(data))
            elif file_type in ["png", "jpeg", "gif", "bmp", "tiff"]:
                metadata.update(self._extract_image_metadata(data, file_type))
            elif file_type in ["docx", "xlsx", "pptx"]:
                metadata.update(self._extract_office_metadata(data))
            elif file_type == "exe":
                metadata.update(self._extract_pe_metadata(data))
        except Exception as e:
            self.logger.debug(f"Error extracting {file_type} metadata: {e}")
            metadata["extraction_error"] = str(e)

        return metadata

    def _extract_pdf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic PDF metadata."""
        metadata = {}
        try:
            content = data[:4096].decode("latin-1", errors="ignore")

            if content.startswith("%PDF-"):
                version_match = re.search(r"%PDF-(\d+\.\d+)", content)
                if version_match:
                    metadata["pdf_version"] = version_match.group(1)

            if "/JavaScript" in content or "/JS" in content:
                metadata["contains_javascript"] = True
            if "/EmbeddedFile" in content:
                metadata["has_embedded_files"] = True

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _extract_image_metadata(self, data: bytes, image_type: str) -> Dict[str, Any]:
        """Extract basic image metadata."""
        metadata = {"image_type": image_type}

        try:
            if image_type == "png" and len(data) >= 24:
                if data[12:16] == b"IHDR":
                    width = struct.unpack(">I", data[16:20])[0]
                    height = struct.unpack(">I", data[20:24])[0]
                    metadata["dimensions"] = f"{width}x{height}"

            elif image_type == "jpeg":
                if b"\xff\xe1" in data[:100]:
                    metadata["has_exif"] = True

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _extract_office_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic Office document metadata."""
        metadata = {}

        try:
            content_str = data[:8192].decode("latin-1", errors="ignore")

            if any(macro_ind in content_str.lower() for macro_ind in ["vbaproject", "macro", "vba"]):
                metadata["contains_macros"] = True

            if any(link_ind in content_str.lower() for link_ind in ["http://", "https://", "ftp://"]):
                metadata["contains_external_links"] = True

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic PE (executable) metadata."""
        metadata = {}

        try:
            if len(data) >= 64:
                pe_offset = struct.unpack("<I", data[60:64])[0]

                if len(data) >= pe_offset + 24:
                    pe_sig = data[pe_offset:pe_offset + 4]
                    if pe_sig == b"PE\x00\x00":
                        metadata["pe_format"] = True

                        machine = struct.unpack("<H", data[pe_offset + 4:pe_offset + 6])[0]
                        arch_map = {0x014c: "i386", 0x8664: "x64", 0x01c0: "ARM", 0xaa64: "ARM64"}
                        metadata["architecture"] = arch_map.get(machine, f"unknown({machine:04x})")

        except Exception as e:
            metadata["error"] = str(e)

        return metadata

    def _analyze_encoding(self, data: bytes) -> Dict[str, Any]:
        """Analyze content encoding."""
        encoding_info = {}

        try:
            ascii_ratio = sum(1 for b in data[:1024] if 32 <= b <= 126) / min(len(data), 1024)
            encoding_info["ascii_ratio"] = round(ascii_ratio, 3)

            entropy = self._calculate_entropy(data[:4096])
            encoding_info["entropy"] = round(entropy, 3)

        except Exception as e:
            encoding_info["error"] = str(e)

        return encoding_info

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                import math
                entropy -= p * math.log2(p)

        return entropy
