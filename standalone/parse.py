#!/usr/bin/env python3
"""
Email Parser with Robust Format Detection and Recursive Structure Analysis
Handles nested emails, attachments, various input formats (.eml, .msg, raw) with detailed logging.
Focused purely on parsing without any security analysis or risk assessment.
"""

import email
import email.parser
import email.policy
import json
import logging
import base64
import quopri
import os
import sys
from typing import Dict, List, Any, Optional, Union, Tuple
from email.message import EmailMessage, Message
import mimetypes
import chardet
import re
import hashlib
import struct

# Try to import extract_msg for MSG file support
try:
    import extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False

class ContentAnalyzer:
    """Basic content analysis for file type detection and metadata extraction."""
    
    # Magic byte signatures for file type detection
    MAGIC_SIGNATURES = {
        # Images
        'png': [(b'\x89PNG\r\n\x1a\n', 0)],
        'jpeg': [(b'\xff\xd8\xff', 0)],
        'gif': [(b'GIF87a', 0), (b'GIF89a', 0)],
        'bmp': [(b'BM', 0)],
        'tiff': [(b'II*\x00', 0), (b'MM\x00*', 0)],
        'ico': [(b'\x00\x00\x01\x00', 0)],
        'webp': [(b'RIFF', 0, b'WEBP', 8)],
        
        # Documents
        'pdf': [(b'%PDF-', 0)],
        'docx': [(b'PK\x03\x04', 0)],  # Will need additional validation
        'doc': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0)],  # OLE format
        'xlsx': [(b'PK\x03\x04', 0)],  # Will need additional validation
        'xls': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0)],  # OLE format
        'pptx': [(b'PK\x03\x04', 0)],  # Will need additional validation
        'ppt': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0)],  # OLE format
        'rtf': [(b'{\\rtf1', 0)],
        'odt': [(b'PK\x03\x04', 0)],  # Will need additional validation
        
        # Archives
        'zip': [(b'PK\x03\x04', 0), (b'PK\x05\x06', 0), (b'PK\x07\x08', 0)],
        'rar': [(b'Rar!\x1a\x07\x00', 0), (b'Rar!\x1a\x07\x01\x00', 0)],
        '7z': [(b'7z\xbc\xaf\x27\x1c', 0)],
        'tar': [(b'ustar\x00', 257), (b'ustar  \x00', 257)],
        'gzip': [(b'\x1f\x8b', 0)],
        'bzip2': [(b'BZ', 0)],
        'xz': [(b'\xfd7zXZ\x00', 0)],
        
        # Executables
        'exe': [(b'MZ', 0)],  # PE format
        'dll': [(b'MZ', 0)],  # PE format
        'elf': [(b'\x7fELF', 0)],  # Linux executables
        'macho': [(b'\xfe\xed\xfa\xce', 0), (b'\xfe\xed\xfa\xcf', 0)],  # macOS executables
        'dex': [(b'dex\n', 0)],  # Android DEX
        'apk': [(b'PK\x03\x04', 0)],  # Android APK (ZIP-based)
        
        # Media
        'mp3': [(b'ID3', 0), (b'\xff\xfb', 0)],
        'mp4': [(b'ftyp', 4)],
        'avi': [(b'RIFF', 0, b'AVI ', 8)],
        'wav': [(b'RIFF', 0, b'WAVE', 8)],
        'mkv': [(b'\x1a\x45\xdf\xa3', 0)],
        
        # Email formats
        'msg': [(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0)],  # OLE/MSG
        'eml': [(b'Return-Path:', 0), (b'Received:', 0), (b'From:', 0)],
        'mbox': [(b'From ', 0)],
        'pst': [(b'!BDN', 0)],
        
        # Other
        'sqlite': [(b'SQLite format 3\x00', 0)],
        'xml': [(b'<?xml', 0), (b'\xef\xbb\xbf<?xml', 0)],
        'html': [(b'<!DOCTYPE html', 0), (b'<html', 0), (b'<HTML', 0)],
        'csv': [],  # Content-based detection
        'json': [(b'{', 0), (b'[', 0)],
    }
    
    def __init__(self, logger):
        self.logger = logger
    
    def analyze_content(self, data: bytes, filename: str = None, declared_mime: str = None) -> Dict[str, Any]:
        """Basic content analysis for type detection and metadata."""
        if not data:
            return {'error': 'No data provided'}
        
        analysis = {
            'filename': filename,
            'declared_mime_type': declared_mime,
            'size': len(data),
            'detected_type': None,
            'confidence': 0.0,
            'mime_type': None,
            'file_extension': None,
            'metadata': {},
            'hashes': {},
            'encoding_info': {}
        }
        
        try:
            # Generate hashes
            analysis['hashes'] = self._generate_hashes(data)
            
            # Detect file type by magic bytes
            detected_type, confidence = self._detect_by_magic_bytes(data)
            analysis['detected_type'] = detected_type
            analysis['confidence'] = confidence
            
            # Enhanced detection for Office documents
            if detected_type in ['docx', 'xlsx', 'pptx'] or (detected_type == 'zip' and filename):
                office_type = self._detect_office_type(data, filename)
                if office_type:
                    analysis['detected_type'] = office_type
                    analysis['confidence'] = min(confidence + 0.2, 1.0)
            
            # Set MIME type
            analysis['mime_type'] = self._get_mime_type(analysis['detected_type'])
            
            # Extract filename extension
            if filename:
                analysis['file_extension'] = os.path.splitext(filename.lower())[1].lstrip('.')
            
            # Content-specific analysis
            if analysis['detected_type']:
                analysis['metadata'] = self._extract_metadata(data, analysis['detected_type'])
            
            # Encoding analysis
            analysis['encoding_info'] = self._analyze_encoding(data)
            
            self.logger.debug(f"Content analysis complete: {analysis['detected_type']} (confidence: {analysis['confidence']:.2f})")
            
        except Exception as e:
            self.logger.error(f"Error in content analysis: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _detect_by_magic_bytes(self, data: bytes) -> Tuple[str, float]:
        """Detect file type using magic byte signatures."""
        if len(data) < 16:
            return 'unknown', 0.0
        
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
        
        return 'unknown', 0.0
    
    def _detect_office_type(self, data: bytes, filename: str) -> Optional[str]:
        """Enhanced detection for Office documents."""
        if not filename:
            return None
        
        filename_lower = filename.lower()
        
        # Check for Office file extensions
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
            # Look for Office-specific files in ZIP structure
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
            'png': 'image/png',
            'jpeg': 'image/jpeg',
            'gif': 'image/gif',
            'bmp': 'image/bmp',
            'tiff': 'image/tiff',
            'webp': 'image/webp',
            'pdf': 'application/pdf',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'doc': 'application/msword',
            'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'xls': 'application/vnd.ms-excel',
            'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'ppt': 'application/vnd.ms-powerpoint',
            'zip': 'application/zip',
            'rar': 'application/x-rar-compressed',
            '7z': 'application/x-7z-compressed',
            'exe': 'application/x-msdownload',
            'dll': 'application/x-msdownload',
            'html': 'text/html',
            'xml': 'text/xml',
            'json': 'application/json',
            'csv': 'text/csv',
            'msg': 'application/vnd.ms-outlook',
            'eml': 'message/rfc822',
        }
        return mime_map.get(detected_type, 'application/octet-stream')
    
    def _generate_hashes(self, data: bytes) -> Dict[str, str]:
        """Generate cryptographic hashes for the content."""
        hashes = {}
        try:
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            self.logger.debug(f"Error generating hashes: {e}")
        return hashes
    
    def _extract_metadata(self, data: bytes, file_type: str) -> Dict[str, Any]:
        """Extract basic metadata based on file type."""
        metadata = {}
        
        try:
            if file_type == 'pdf':
                metadata.update(self._extract_pdf_metadata(data))
            elif file_type in ['png', 'jpeg', 'gif', 'bmp', 'tiff']:
                metadata.update(self._extract_image_metadata(data, file_type))
            elif file_type in ['docx', 'xlsx', 'pptx']:
                metadata.update(self._extract_office_metadata(data))
            elif file_type == 'exe':
                metadata.update(self._extract_pe_metadata(data))
        except Exception as e:
            self.logger.debug(f"Error extracting {file_type} metadata: {e}")
            metadata['extraction_error'] = str(e)
        
        return metadata
    
    def _extract_pdf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic PDF metadata."""
        metadata = {}
        try:
            content = data[:4096].decode('latin-1', errors='ignore')
            
            # Extract PDF version
            if content.startswith('%PDF-'):
                version_match = re.search(r'%PDF-(\d+\.\d+)', content)
                if version_match:
                    metadata['pdf_version'] = version_match.group(1)
            
            # Look for basic features
            if '/JavaScript' in content or '/JS' in content:
                metadata['contains_javascript'] = True
            if '/EmbeddedFile' in content:
                metadata['has_embedded_files'] = True
                
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_image_metadata(self, data: bytes, image_type: str) -> Dict[str, Any]:
        """Extract basic image metadata."""
        metadata = {'image_type': image_type}
        
        try:
            if image_type == 'png' and len(data) >= 24:
                # PNG dimensions from IHDR chunk
                if data[12:16] == b'IHDR':
                    width = struct.unpack('>I', data[16:20])[0]
                    height = struct.unpack('>I', data[20:24])[0]
                    metadata['dimensions'] = f"{width}x{height}"
            
            elif image_type == 'jpeg':
                # Look for EXIF data
                if b'\xff\xe1' in data[:100]:
                    metadata['has_exif'] = True
                
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_office_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic Office document metadata."""
        metadata = {}
        
        try:
            content_str = data[:8192].decode('latin-1', errors='ignore')
            
            # Look for macro indicators
            if any(macro_ind in content_str.lower() for macro_ind in ['vbaproject', 'macro', 'vba']):
                metadata['contains_macros'] = True
            
            # Look for external links
            if any(link_ind in content_str.lower() for link_ind in ['http://', 'https://', 'ftp://']):
                metadata['contains_external_links'] = True
                
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract basic PE (executable) metadata."""
        metadata = {}
        
        try:
            if len(data) >= 64:
                # Read PE header location
                pe_offset = struct.unpack('<I', data[60:64])[0]
                
                if len(data) >= pe_offset + 24:
                    # Read PE signature
                    pe_sig = data[pe_offset:pe_offset + 4]
                    if pe_sig == b'PE\x00\x00':
                        metadata['pe_format'] = True
                        
                        # Read machine type
                        machine = struct.unpack('<H', data[pe_offset + 4:pe_offset + 6])[0]
                        arch_map = {0x014c: 'i386', 0x8664: 'x64', 0x01c0: 'ARM', 0xaa64: 'ARM64'}
                        metadata['architecture'] = arch_map.get(machine, f'unknown({machine:04x})')
                        
        except Exception as e:
            metadata['error'] = str(e)
        
        return metadata
    
    def _analyze_encoding(self, data: bytes) -> Dict[str, Any]:
        """Analyze content encoding."""
        encoding_info = {}
        
        try:
            # Check if content is primarily ASCII
            ascii_ratio = sum(1 for b in data[:1024] if 32 <= b <= 126) / min(len(data), 1024)
            encoding_info['ascii_ratio'] = round(ascii_ratio, 3)
            
            # Entropy analysis (simplified)
            entropy = self._calculate_entropy(data[:4096])
            encoding_info['entropy'] = round(entropy, 3)
            
        except Exception as e:
            encoding_info['error'] = str(e)
        
        return encoding_info
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                # Use natural logarithm for Shannon entropy
                import math
                entropy -= p * math.log2(p)
        
        return entropy

class EmailFormatDetector:
    """Handles robust email format detection using magic bytes and content analysis."""
    
    # Magic byte signatures for different email formats
    MAGIC_SIGNATURES = {
        'msg': [
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',  # OLE/Compound Document (MSG files)
            b'\x0e\x11\xfc\x0d\xd0\xcf\x11\xe0',  # Alternative OLE signature
        ],
        'eml': [
            b'Return-Path:',
            b'Received:',
            b'From:',
            b'Message-ID:',
            b'Date:',
        ],
        'mbox': [
            b'From ',  # mbox format starts with "From "
        ],
        'pst': [
            b'!BDN',  # PST file signature
        ]
    }
    
    def __init__(self, logger):
        self.logger = logger
    
    def detect_by_magic_bytes(self, data: bytes) -> Optional[str]:
        """Detect format using magic byte signatures."""
        if len(data) < 8:
            return None
            
        # Check first 512 bytes for signatures
        header = data[:512]
        
        for format_type, signatures in self.MAGIC_SIGNATURES.items():
            for signature in signatures:
                if signature in header:
                    self.logger.info(f"Detected {format_type} format by magic bytes: {signature.hex()}")
                    return format_type
        
        return None
    
    def detect_by_content_analysis(self, data: bytes) -> Optional[str]:
        """Detect format by analyzing content structure."""
        try:
            # Try to decode as text for analysis
            if isinstance(data, bytes):
                try:
                    text_data = data.decode('utf-8', errors='ignore')
                except:
                    text_data = data.decode('latin-1', errors='ignore')
            else:
                text_data = str(data)
            
            # Look for email header patterns in first 2KB
            header_section = text_data[:2048]
            
            # Count email headers
            email_headers = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'Received:', 'Return-Path:']
            header_count = sum(1 for header in email_headers if header in header_section)
            
            if header_count >= 2:
                self.logger.info(f"Detected EML format by header analysis ({header_count} headers found)")
                return 'eml'
            
            # Check for mbox format
            if text_data.startswith('From ') and '\n\n' in text_data[:1000]:
                self.logger.info("Detected MBOX format by content structure")
                return 'mbox'
                
        except Exception as e:
            self.logger.debug(f"Content analysis failed: {e}")
        
        return None
    
    def detect_by_filename(self, filename: str) -> Optional[str]:
        """Detect format by file extension."""
        if not filename:
            return None
            
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.msg'):
            return 'msg'
        elif filename_lower.endswith(('.eml', '.email')):
            return 'eml'
        elif filename_lower.endswith('.mbox'):
            return 'mbox'
        elif filename_lower.endswith('.pst'):
            return 'pst'
        
        return None
    
    def detect_format(self, data: bytes, filename: str = None) -> Tuple[str, float]:
        """
        Comprehensive format detection with confidence scoring.
        Returns (format, confidence) where confidence is 0.0-1.0
        """
        self.logger.info("Starting comprehensive format detection...")
        
        detections = {}
        
        # Magic byte detection (highest confidence)
        magic_format = self.detect_by_magic_bytes(data)
        if magic_format:
            detections[magic_format] = detections.get(magic_format, 0) + 0.8
        
        # Content analysis (medium confidence)
        content_format = self.detect_by_content_analysis(data)
        if content_format:
            detections[content_format] = detections.get(content_format, 0) + 0.6
        
        # Filename detection (low confidence)
        if filename:
            filename_format = self.detect_by_filename(filename)
            if filename_format:
                detections[filename_format] = detections.get(filename_format, 0) + 0.3
        
        if not detections:
            self.logger.warning("Could not detect email format")
            return 'unknown', 0.0
        
        # Return format with highest confidence
        best_format = max(detections.items(), key=lambda x: x[1])
        self.logger.info(f"Detected format: {best_format[0]} (confidence: {best_format[1]:.2f})")
        
        return best_format[0], min(best_format[1], 1.0)

class EmailParser:
    def __init__(self, log_level=logging.INFO):
        """Initialize the email parser with logging configuration."""
        self.setup_logging(log_level)
        self.parser = email.parser.Parser(policy=email.policy.default)
        self.bytes_parser = email.parser.BytesParser(policy=email.policy.default)
        self.format_detector = EmailFormatDetector(self.logger)
        self.content_analyzer = ContentAnalyzer(self.logger)
        
    def setup_logging(self, log_level):
        """Setup detailed logging configuration."""
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler('email_parser.log')
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def parse_msg_file(self, data: bytes) -> Optional[Message]:
        """Parse Microsoft Outlook MSG file format."""
        if not MSG_SUPPORT:
            self.logger.error("MSG file support not available. Install extract_msg: pip install extract-msg")
            return None
        
        tmp_file_path = None
        try:
            self.logger.info("Parsing MSG file using extract_msg")
            
            # Write to temporary file for extract_msg
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                tmp_file_path = tmp_file.name
            
            # Extract MSG content (file is now closed)
            msg = extract_msg.Message(tmp_file_path)
            
            # Convert MSG to email-like structure
            email_content = self.convert_msg_to_email_format(msg)
            
            # Explicitly close the MSG object to release file handles
            if hasattr(msg, 'close'):
                msg.close()
            elif hasattr(msg, '__exit__'):
                msg.__exit__(None, None, None)
            
            # Parse the converted content before cleanup
            parsed_message = None
            if email_content:
                parsed_message = self.parser.parsestr(email_content)
            
            return parsed_message
                
        except Exception as e:
            self.logger.error(f"Failed to parse MSG file: {e}")
            return None
        finally:
            # Clean up temp file with retry logic
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.unlink(tmp_file_path)
                    self.logger.debug(f"Cleaned up temporary file: {tmp_file_path}")
                except Exception as cleanup_error:
                    self.logger.warning(f"Could not clean up temporary file {tmp_file_path}: {cleanup_error}")
                    # Try again after a short delay
                    import time
                    time.sleep(0.1)
                    try:
                        os.unlink(tmp_file_path)
                        self.logger.debug(f"Cleaned up temporary file on retry: {tmp_file_path}")
                    except:
                        self.logger.warning(f"Temporary file cleanup failed, file may need manual deletion: {tmp_file_path}")
    
    def extract_msg_attachment_data(self, attachment):
        """Extract raw data from MSG attachment for proper content type detection."""
        try:
            # Try to get the raw attachment data
            if hasattr(attachment, 'data') and attachment.data:
                data = attachment.data
                if isinstance(data, bytes):
                    return data
                else:
                    self.logger.debug(f"Attachment data is not bytes, type: {type(data)}")
                    return None
            elif hasattr(attachment, 'save'):
                # Some versions require saving to get data
                import io
                buffer = io.BytesIO()
                attachment.save(buffer)
                return buffer.getvalue()
            else:
                self.logger.warning("Could not extract attachment data from MSG")
                return None
        except Exception as e:
            self.logger.warning(f"Error extracting MSG attachment data: {e}")
            return None


    def _add_single_body_content(self, lines: List[str], msg) -> None:
        """Add single body content (either plain or HTML)."""
        try:
            # Try plain text first
            if hasattr(msg, 'body') and msg.body:
                plain_content = self._normalize_msg_content(msg.body)
                if plain_content and plain_content.strip():
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append(plain_content)
                    self.logger.debug(f"Added plain text body ({len(plain_content)} chars)")
                    return
            
            # Fall back to HTML
            if hasattr(msg, 'htmlBody') and msg.htmlBody:
                html_content = self._normalize_msg_content(msg.htmlBody)
                if html_content and html_content.strip():
                    lines.append("Content-Type: text/html; charset=utf-8")
                    lines.append("")
                    lines.append(html_content)
                    self.logger.debug(f"Added HTML body ({len(html_content)} chars)")
                    return
            
            # No body content found
            lines.append("Content-Type: text/plain; charset=utf-8")
            lines.append("")
            lines.append("[No body content found]")
            self.logger.debug("No body content found")
            
        except Exception as e:
            self.logger.error(f"Error adding single body content: {e}")
            lines.append("Content-Type: text/plain; charset=utf-8")
            lines.append("")
            lines.append("[Error reading body content]")

    def _add_multipart_body_content(self, lines: List[str], msg, boundary: str) -> None:
        """Add multipart body content with both plain and HTML versions."""
        try:
            # Add plain text part
            lines.append(f"--{boundary}")
            plain_content = None
            if hasattr(msg, 'body') and msg.body:
                plain_content = self._normalize_msg_content(msg.body)
                
            if plain_content and plain_content.strip():
                lines.append("Content-Type: text/plain; charset=utf-8")
                lines.append("")
                lines.append(plain_content)
                self.logger.debug(f"Added plain text part ({len(plain_content)} chars)")
            else:
                # Generate plain text from HTML if no plain text available
                html_content = None
                if hasattr(msg, 'htmlBody') and msg.htmlBody:
                    html_content = self._normalize_msg_content(msg.htmlBody)
                    
                if html_content:
                    self.logger.info(f"Converting HTML body to plain text ({len(html_content)} chars)")
                    plain_from_html = self.convert_html_to_text(html_content)
                    if plain_from_html and plain_from_html.strip():
                        lines.append("Content-Type: text/plain; charset=utf-8")
                        lines.append("")
                        lines.append(plain_from_html)
                        self.logger.info(f"Successfully converted HTML to plain text ({len(plain_from_html)} chars)")
                    else:
                        lines.append("Content-Type: text/plain; charset=utf-8")
                        lines.append("")
                        lines.append("[HTML body detected but conversion failed]")
                        self.logger.warning("HTML to text conversion failed")
                else:
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append("[No plain text content available]")
            
            # Add HTML part
            lines.append(f"\n--{boundary}")
            html_content = None
            if hasattr(msg, 'htmlBody') and msg.htmlBody:
                html_content = self._normalize_msg_content(msg.htmlBody)
                
            if html_content and html_content.strip():
                lines.append("Content-Type: text/html; charset=utf-8")
                lines.append("")
                lines.append(html_content)
                self.logger.debug(f"Added HTML part ({len(html_content)} chars)")
            else:
                lines.append("Content-Type: text/html; charset=utf-8")
                lines.append("")
                lines.append("<html><body>[No HTML content available]</body></html>")
            
            # Close the multipart/alternative
            lines.append(f"\n--{boundary}--")
            
        except Exception as e:
            self.logger.error(f"Error adding multipart body content: {e}")
            lines.append(f"--{boundary}")
            lines.append("Content-Type: text/plain; charset=utf-8")
            lines.append("")
            lines.append("[Error reading body content]")
            lines.append(f"\n--{boundary}--")

    def _normalize_msg_content(self, content) -> Optional[str]:
        """Normalize MSG content to proper string format."""
        if content is None:
            return None
        
        try:
            # If it's already a string, return it
            if isinstance(content, str):
                return content
            
            # If it's bytes, decode it properly
            elif isinstance(content, bytes):
                # Try different encodings
                for encoding in ['utf-8', 'utf-16', 'windows-1252', 'latin-1']:
                    try:
                        return content.decode(encoding)
                    except (UnicodeDecodeError, UnicodeError):
                        continue
                
                # Last resort - decode with errors='replace'
                return content.decode('utf-8', errors='replace')
            
            # For any other type, convert to string
            else:
                content_str = str(content)
                # Check if it looks like a bytes representation string
                if content_str.startswith("b'") and content_str.endswith("'"):
                    # This is a string representation of bytes - try to parse it
                    try:
                        # Remove the b' prefix and ' suffix, then handle escape sequences
                        inner_content = content_str[2:-1]
                        # Handle common escape sequences
                        inner_content = inner_content.replace('\\r\\n', '\r\n')
                        inner_content = inner_content.replace('\\n', '\n')
                        inner_content = inner_content.replace('\\r', '\r')
                        inner_content = inner_content.replace('\\t', '\t')
                        inner_content = inner_content.replace("\\'", "'")
                        inner_content = inner_content.replace('\\"', '"')
                        inner_content = inner_content.replace('\\\\', '\\')
                        return inner_content
                    except Exception as e:
                        self.logger.debug(f"Failed to parse bytes string representation: {e}")
                        return content_str
                else:
                    return content_str
                    
        except Exception as e:
            self.logger.error(f"Error normalizing MSG content: {e}")
            return str(content) if content is not None else None
    def _normalize_msg_content(self, content) -> Optional[str]:
        """Normalize MSG content to proper string format."""
        if content is None:
            return None
        
        try:
            # If it's already a string, return it
            if isinstance(content, str):
                return content
            
            # If it's bytes, decode it properly
            elif isinstance(content, bytes):
                # Try different encodings
                for encoding in ['utf-8', 'utf-16', 'windows-1252', 'latin-1']:
                    try:
                        return content.decode(encoding)
                    except (UnicodeDecodeError, UnicodeError):
                        continue
                
                # Last resort - decode with errors='replace'
                return content.decode('utf-8', errors='replace')
            
            # For any other type, convert to string
            else:
                content_str = str(content)
                # Check if it looks like a bytes representation string
                if content_str.startswith("b'") and content_str.endswith("'"):
                    # This is a string representation of bytes - try to parse it
                    try:
                        # Remove the b' prefix and ' suffix, then handle escape sequences
                        inner_content = content_str[2:-1]
                        # Handle common escape sequences
                        inner_content = inner_content.replace('\\r\\n', '\r\n')
                        inner_content = inner_content.replace('\\n', '\n')
                        inner_content = inner_content.replace('\\r', '\r')
                        inner_content = inner_content.replace('\\t', '\t')
                        inner_content = inner_content.replace("\\'", "'")
                        inner_content = inner_content.replace('\\"', '"')
                        inner_content = inner_content.replace('\\\\', '\\')
                        return inner_content
                    except Exception as e:
                        self.logger.debug(f"Failed to parse bytes string representation: {e}")
                        return content_str
                else:
                    return content_str
                    
        except Exception as e:
            self.logger.error(f"Error normalizing MSG content: {e}")
            return str(content) if content is not None else None
    
    def parse_email_from_input(self, input_data: Union[str, bytes], filename: str = None) -> Optional[Message]:
        """Parse email from various input formats with robust detection."""
        
        # Ensure we have bytes for format detection
        if isinstance(input_data, str):
            data_bytes = input_data.encode('utf-8')
        else:
            data_bytes = input_data
        
        # Detect format
        detected_format, confidence = self.format_detector.detect_format(data_bytes, filename)
        
        self.logger.info(f"Attempting to parse as {detected_format} format (confidence: {confidence:.2f})")
        
        try:
            if detected_format == 'msg':
                if not MSG_SUPPORT:
                    self.logger.error("MSG format detected but extract_msg not available")
                    return None
                return self.parse_msg_file(data_bytes)
            
            elif detected_format == 'eml':
                # Standard email format
                if isinstance(input_data, bytes):
                    return self.bytes_parser.parsebytes(input_data)
                else:
                    return self.parser.parsestr(input_data)
            
            elif detected_format == 'mbox':
                # MBOX format - extract first message
                if isinstance(input_data, str):
                    content = input_data
                else:
                    content = input_data.decode('utf-8', errors='replace')
                
                # Find first message in mbox
                if content.startswith('From '):
                    # Find end of first message
                    next_from = content.find('\nFrom ', 1)
                    if next_from > 0:
                        first_message = content[content.find('\n', 1):next_from]
                    else:
                        first_message = content[content.find('\n', 1):]
                    
                    return self.parser.parsestr(first_message)
            
            elif detected_format == 'pst':
                self.logger.error("PST format detected but not supported (use libpst or similar tools)")
                return None
            
            else:
                # Unknown format - try both parsers as fallback
                self.logger.warning(f"Unknown format, trying fallback parsing...")
                
                try:
                    if isinstance(input_data, bytes):
                        return self.bytes_parser.parsebytes(input_data)
                    else:
                        return self.parser.parsestr(input_data)
                except:
                    self.logger.error("Fallback parsing failed")
                    return None
                    
        except Exception as e:
            self.logger.error(f"Failed to parse email in {detected_format} format: {e}")
            return None
    
    def extract_email_body(self, message: Message) -> Dict[str, Any]:
        """Extract email body content, converting HTML to plain text when needed."""
        self.logger.debug("Extracting email body content...")
        
        body_info = {
            'plain_text': None,
            'html_content': None,
            'body_type': 'none',
            'truncated': False,
            'char_count': 0
        }
        
        try:
            if message.is_multipart():
                self.logger.debug("Processing multipart message for body extraction")
                
                # Look for text parts in multipart message
                for part in message.walk():
                    content_type = part.get_content_type()
                    
                    if content_type == 'text/plain' and not body_info['plain_text']:
                        try:
                            text_content = self._extract_text_content(part)
                            if text_content and text_content.strip():
                                body_info['plain_text'] = text_content.strip()
                                body_info['body_type'] = 'plain'
                                body_info['char_count'] = len(body_info['plain_text'])
                                self.logger.debug(f"Found plain text body ({body_info['char_count']} chars)")
                            
                        except Exception as e:
                            self.logger.debug(f"Error extracting plain text: {e}")
                    
                    elif content_type == 'text/html' and not body_info['html_content']:
                        try:
                            html_content = self._extract_text_content(part)
                            if html_content and html_content.strip():
                                body_info['html_content'] = html_content.strip()
                                self.logger.debug(f"Found HTML body ({len(body_info['html_content'])} chars)")
                                
                                # Convert HTML to plain text if no plain text version exists
                                if not body_info['plain_text']:
                                    plain_from_html = self.convert_html_to_text(body_info['html_content'])
                                    if plain_from_html and plain_from_html.strip():
                                        body_info['plain_text'] = plain_from_html.strip()
                                        body_info['body_type'] = 'html_converted'
                                        body_info['char_count'] = len(body_info['plain_text'])
                                        self.logger.debug(f"Converted HTML to text ({body_info['char_count']} chars)")
                            
                        except Exception as e:
                            self.logger.debug(f"Error extracting HTML: {e}")
            else:
                # Single part message
                content_type = message.get_content_type()
                self.logger.debug(f"Processing single-part message: {content_type}")
                
                try:
                    content = self._extract_text_content(message)
                    if content:
                        content = content.strip()
                        
                        if content_type == 'text/plain':
                            body_info['plain_text'] = content
                            body_info['body_type'] = 'plain'
                            body_info['char_count'] = len(content)
                            self.logger.debug(f"Single-part plain text body ({body_info['char_count']} chars)")
                            
                        elif content_type == 'text/html':
                            body_info['html_content'] = content
                            plain_from_html = self.convert_html_to_text(content)
                            if plain_from_html and plain_from_html.strip():
                                body_info['plain_text'] = plain_from_html.strip()
                                body_info['body_type'] = 'html_converted'
                                body_info['char_count'] = len(body_info['plain_text'])
                                self.logger.debug(f"Single-part HTML converted to text ({body_info['char_count']} chars)")
                        else:
                            # Try to extract as text anyway
                            body_info['plain_text'] = content
                            body_info['body_type'] = 'unknown'
                            body_info['char_count'] = len(content)
                            self.logger.debug(f"Single-part unknown content type extracted as text ({body_info['char_count']} chars)")
                            
                except Exception as e:
                    self.logger.debug(f"Error extracting single-part content: {e}")
            
            # Truncate body if too long (keep first 1000 chars for preview)
            if body_info['plain_text'] and len(body_info['plain_text']) > 1000:
                body_info['plain_text'] = body_info['plain_text'][:1000] + "... [TRUNCATED]"
                body_info['truncated'] = True
                self.logger.debug("Body content truncated for output")
            
            # Add HTML detection info without full content
            if body_info['html_content']:
                html_preview = body_info['html_content'][:200] + "... [HTML CONTENT DETECTED - TRUNCATED]" if len(body_info['html_content']) > 200 else body_info['html_content'] + " [HTML CONTENT DETECTED]"
                body_info['html_preview'] = html_preview
                # Don't include full HTML content in output
                del body_info['html_content']
            
            self.logger.info(f"Body extraction complete: type={body_info['body_type']}, chars={body_info['char_count']}, truncated={body_info['truncated']}")
            
        except Exception as e:
            self.logger.error(f"Error extracting email body: {e}")
            body_info['error'] = str(e)
        
        return body_info

    def _extract_text_content(self, part: Message) -> str:
        """Helper method to properly extract and decode text content from a message part."""
        try:
            # Get the raw payload
            payload = part.get_payload(decode=True)
            
            if payload is None:
                # Try without decoding
                payload = part.get_payload(decode=False)
                if isinstance(payload, list):
                    return None
            
            # Handle different payload types
            if isinstance(payload, bytes):
                # Determine charset
                charset = part.get_content_charset() or 'utf-8'
                
                # Check for additional encoding (like quoted-printable or base64)
                encoding = part.get('Content-Transfer-Encoding', '').lower()
                
                if encoding == 'quoted-printable':
                    # Manually decode quoted-printable if needed
                    try:
                        payload = quopri.decodestring(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual quoted-printable decode failed: {e}")
                elif encoding == 'base64':
                    # Manually decode base64 if needed
                    try:
                        payload = base64.b64decode(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual base64 decode failed: {e}")
                
                # Decode to string
                try:
                    content = payload.decode(charset, errors='ignore')
                except (UnicodeDecodeError, LookupError):
                    # Fallback charsets
                    for fallback_charset in ['utf-8', 'latin1', 'cp1252']:
                        try:
                            content = payload.decode(fallback_charset, errors='ignore')
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        # Last resort - decode with errors='replace'
                        content = payload.decode('utf-8', errors='replace')
                        
            elif isinstance(payload, str):
                content = payload
            else:
                # Unexpected payload type
                content = str(payload)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error extracting text content: {e}")
            return None

    def convert_msg_to_email_format(self, msg) -> Optional[str]:
        """Convert MSG object to email-like format for standard parsing."""
        try:
            lines = []
            
            self.logger.info("Starting MSG to email conversion...")
            self.logger.debug(f"MSG object type: {type(msg)}")
            
            # Add headers with proper error handling
            try:
                if hasattr(msg, 'sender') and msg.sender:
                    lines.append(f"From: {msg.sender}")
                    self.logger.debug(f"Added From: {msg.sender}")
            except Exception as e:
                self.logger.debug(f"Error getting sender: {e}")
                
            try:
                if hasattr(msg, 'to') and msg.to:
                    lines.append(f"To: {msg.to}")
                    self.logger.debug(f"Added To: {msg.to}")
            except Exception as e:
                self.logger.debug(f"Error getting to: {e}")
                
            try:
                if hasattr(msg, 'cc') and msg.cc:
                    lines.append(f"Cc: {msg.cc}")
                    self.logger.debug(f"Added Cc: {msg.cc}")
            except Exception as e:
                self.logger.debug(f"Error getting cc: {e}")
                
            try:
                if hasattr(msg, 'subject') and msg.subject:
                    lines.append(f"Subject: {msg.subject}")
                    self.logger.debug(f"Added Subject: {msg.subject}")
            except Exception as e:
                self.logger.debug(f"Error getting subject: {e}")
                
            try:
                if hasattr(msg, 'date') and msg.date:
                    lines.append(f"Date: {msg.date}")
                    self.logger.debug(f"Added Date: {msg.date}")
            except Exception as e:
                self.logger.debug(f"Error getting date: {e}")
                
            try:
                if hasattr(msg, 'messageId') and msg.messageId:
                    lines.append(f"Message-ID: {msg.messageId}")
                    self.logger.debug(f"Added Message-ID: {msg.messageId}")
            except Exception as e:
                self.logger.debug(f"Error getting messageId: {e}")
            
            # Add MIME headers
            lines.append("MIME-Version: 1.0")
            
            # Check for attachments
            has_attachments = False
            attachment_count = 0
            try:
                if hasattr(msg, 'attachments') and msg.attachments:
                    attachment_count = len(msg.attachments)
                    has_attachments = True
                    self.logger.info(f"Found {attachment_count} attachments in MSG file")
            except Exception as e:
                self.logger.error(f"Error checking MSG attachments: {e}")
            
            # Try to extract plain text using getSaveBody method
            plain_text_content = None
            try:
                if hasattr(msg, 'getSaveBody'):
                    save_body_bytes = msg.getSaveBody()
                    if save_body_bytes and len(save_body_bytes) > 50:  # Must be substantial content
                        # This might contain plain text version
                        plain_text_content = save_body_bytes.decode('utf-8', errors='ignore')
                        self.logger.info(f"Extracted plain text from getSaveBody: {len(plain_text_content)} chars")
            except Exception as e:
                self.logger.debug(f"Could not extract from getSaveBody: {e}")
            
            # Extract and properly decode HTML content
            html_content = None
            try:
                if hasattr(msg, 'htmlBody') and msg.htmlBody:
                    # Use the correct encoding found by diagnostics
                    for encoding in ['windows-1252', 'latin-1', 'utf-8']:
                        try:
                            html_content = msg.htmlBody.decode(encoding)
                            self.logger.info(f"Successfully decoded HTML body using {encoding}")
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        # Fallback
                        html_content = msg.htmlBody.decode('utf-8', errors='replace')
                        self.logger.warning("Used fallback HTML decoding")
            except Exception as e:
                self.logger.error(f"Error extracting HTML body: {e}")
            
            # Determine structure based on what we have
            has_plain = plain_text_content and plain_text_content.strip()
            has_html = html_content and html_content.strip()
            
            if has_attachments:
                # Multipart/mixed for attachments
                main_boundary = "----=_NextPart_EmailParser_MSG"
                lines.append(f"Content-Type: multipart/mixed; boundary=\"{main_boundary}\"")
                lines.append("")
                lines.append(f"--{main_boundary}")
                
                if has_plain and has_html:
                    # Both plain and HTML - create multipart/alternative
                    alt_boundary = "----=_NextPart_EmailParser_MSG_Alt"
                    lines.append(f"Content-Type: multipart/alternative; boundary=\"{alt_boundary}\"")
                    lines.append("")
                    
                    # Add plain text part
                    lines.append(f"--{alt_boundary}")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append(plain_text_content)
                    
                    # Add HTML part
                    lines.append(f"\n--{alt_boundary}")
                    lines.append("Content-Type: text/html; charset=utf-8")
                    lines.append("")
                    lines.append(html_content)
                    lines.append(f"\n--{alt_boundary}--")
                    
                elif has_plain:
                    # Only plain text
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append(plain_text_content)
                    
                elif has_html:
                    # Only HTML - convert to plain text
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    converted_text = self.convert_html_to_text(html_content)
                    lines.append(converted_text if converted_text else "[HTML conversion failed]")
                    
                else:
                    # No body content
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append("[No body content found]")
                    
            else:
                # No attachments
                if has_plain and has_html:
                    # Both plain and HTML - create multipart/alternative
                    alt_boundary = "----=_NextPart_EmailParser_MSG_Alt"
                    lines.append(f"Content-Type: multipart/alternative; boundary=\"{alt_boundary}\"")
                    lines.append("")
                    
                    # Add plain text part
                    lines.append(f"--{alt_boundary}")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append(plain_text_content)
                    
                    # Add HTML part
                    lines.append(f"\n--{alt_boundary}")
                    lines.append("Content-Type: text/html; charset=utf-8")
                    lines.append("")
                    lines.append(html_content)
                    lines.append(f"\n--{alt_boundary}--")
                    
                elif has_plain:
                    # Only plain text
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append(plain_text_content)
                    
                elif has_html:
                    # Only HTML - convert to plain text
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    converted_text = self.convert_html_to_text(html_content)
                    lines.append(converted_text if converted_text else "[HTML conversion failed]")
                    
                else:
                    # No body content
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                    lines.append("[No body content found]")
            
            # Process attachments
            if has_attachments:
                try:
                    main_boundary = "----=_NextPart_EmailParser_MSG"
                    for i, attachment in enumerate(msg.attachments):
                        self.logger.info(f"Processing MSG attachment {i}...")
                        lines.append(f"\n--{main_boundary}")
                        
                        try:
                            filename = getattr(attachment, 'longFilename', None) or getattr(attachment, 'shortFilename', f'attachment_{i}')
                            self.logger.debug(f"Attachment filename: {filename}")
                            
                            # Try to get attachment data for better content type detection
                            attachment_data = self.extract_msg_attachment_data(attachment)
                            
                            if attachment_data and filename and filename.lower().endswith('.eml'):
                                # This might be a nested email - include the actual data
                                self.logger.info(f"Detected potential nested email attachment: {filename}")
                                lines.append(f"Content-Type: message/rfc822")
                                lines.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
                                lines.append("Content-Transfer-Encoding: base64")
                                lines.append("")
                                
                                # Encode the attachment data
                                import base64
                                encoded_data = base64.b64encode(attachment_data).decode('ascii')
                                # Split into 76-character lines (standard for base64 in email)
                                for j in range(0, len(encoded_data), 76):
                                    lines.append(encoded_data[j:j+76])
                                    
                            else:
                                # Regular attachment
                                lines.append(f"Content-Type: application/octet-stream")
                                lines.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
                                if attachment_data:
                                    lines.append("Content-Transfer-Encoding: base64")
                                    lines.append("")
                                    
                                    # Include actual data for better processing
                                    import base64
                                    encoded_data = base64.b64encode(attachment_data).decode('ascii')
                                    # Split into 76-character lines (standard for base64 in email)
                                    for j in range(0, len(encoded_data), 76):
                                        lines.append(encoded_data[j:j+76])
                                else:
                                    lines.append("")
                                    lines.append(f"[MSG Attachment: {filename}]")
                                    
                        except Exception as e:
                            self.logger.error(f"Error processing attachment {i}: {e}")
                            lines.append(f"Content-Type: application/octet-stream")
                            lines.append(f"Content-Disposition: attachment; filename=\"attachment_{i}\"")
                            lines.append("")
                            lines.append(f"[MSG Attachment {i} - Error: {e}]")
                    
                    lines.append(f"\n--{main_boundary}--")
                    
                except Exception as e:
                    self.logger.error(f"Error processing MSG attachments: {e}")
            
            result = "\n".join(str(line) for line in lines)
            self.logger.info(f"Converted MSG to email format with {len(lines)} lines, {attachment_count} attachments")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error converting MSG to email format: {e}")
            return None

    def convert_html_to_text(self, html_content: str) -> str:
        """Convert HTML content to plain text with better handling."""
        try:
            if not html_content:
                return ""
            
            # Try to import html2text for better conversion
            try:
                import html2text
                h = html2text.HTML2Text()
                h.ignore_links = True
                h.ignore_images = True
                h.body_width = 0  # No line wrapping
                h.unicode_snob = True  # Better Unicode handling
                result = h.handle(html_content).strip()
                self.logger.debug(f"html2text conversion successful, result length: {len(result)}")
                return result
            except ImportError:
                self.logger.debug("html2text not available, using fallback conversion")
                # Fallback to basic HTML tag removal
                import re
                import html
                
                # Remove script and style content
                text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML tags
                text = re.sub(r'<[^>]+>', '', text)
                
                # Convert HTML entities
                text = html.unescape(text)
                
                # Clean up whitespace
                text = re.sub(r'\s+', ' ', text).strip()
                
                self.logger.debug(f"Fallback conversion successful, result length: {len(text)}")
                return text
                
        except Exception as e:
            self.logger.error(f"Error converting HTML to text: {e}")
            return f"[HTML conversion failed: {e}]"

    def _normalize_msg_content(self, content) -> Optional[str]:
        """Normalize MSG content to proper string format with enhanced Unicode handling."""
        if content is None:
            return None
        
        try:
            self.logger.debug(f"Normalizing MSG content, type: {type(content)}")
            
            # If it's already a string, check for Unicode issues
            if isinstance(content, str):
                # Check if it looks like improperly decoded Unicode
                if len(content) > 10:
                    # Sample first few characters to see if they look like garbled Unicode
                    sample = content[:20]
                    if any(ord(c) > 127 and ord(c) < 65536 for c in sample if len(sample) > 5):
                        self.logger.debug("String content appears to contain improperly decoded Unicode")
                        # Try to re-encode as latin-1 and decode as UTF-16
                        try:
                            # Convert back to bytes using latin-1 (preserves byte values)
                            byte_content = content.encode('latin-1')
                            # Try UTF-16 decoding
                            if len(byte_content) % 2 == 0:  # UTF-16 requires even number of bytes
                                decoded = byte_content.decode('utf-16le', errors='ignore')
                                if self._is_reasonable_text(decoded):
                                    self.logger.info("Successfully re-decoded as UTF-16LE")
                                    return decoded
                        except Exception as e:
                            self.logger.debug(f"UTF-16 re-decoding failed: {e}")
                
                return content
            
            # If it's bytes, decode it properly with enhanced logic
            elif isinstance(content, bytes):
                self.logger.debug(f"Content is bytes, length: {len(content)}")
                
                # First, try to detect if it's UTF-16 by looking for patterns
                if len(content) >= 4:
                    # Check for UTF-16 BOM or patterns
                    if content[:2] == b'\xff\xfe' or content[:2] == b'\xfe\xff':
                        self.logger.debug("Detected UTF-16 BOM")
                        try:
                            return content.decode('utf-16')
                        except UnicodeDecodeError:
                            pass
                    
                    # Check for UTF-16LE pattern (common in Windows/Outlook)
                    # Look for alternating null bytes which is common in UTF-16LE ASCII
                    if len(content) >= 20:
                        null_pattern = sum(1 for i in range(1, min(20, len(content)), 2) if content[i] == 0)
                        if null_pattern > 5:  # Many null bytes in odd positions
                            self.logger.debug("Detected likely UTF-16LE encoding pattern")
                            try:
                                decoded = content.decode('utf-16le', errors='ignore')
                                if self._is_reasonable_text(decoded):
                                    self.logger.info("Successfully decoded as UTF-16LE")
                                    return decoded
                            except UnicodeDecodeError:
                                pass
                
                # Standard encoding attempts
                for encoding in ['utf-8', 'utf-16', 'windows-1252', 'latin-1']:
                    try:
                        result = content.decode(encoding)
                        if self._is_reasonable_text(result):
                            self.logger.debug(f"Successfully decoded using {encoding}")
                            return result
                    except (UnicodeDecodeError, UnicodeError):
                        continue
                
                # Last resort - decode with errors='replace'
                result = content.decode('utf-8', errors='replace')
                self.logger.warning("Used fallback decoding with errors='replace'")
                return result
            
            # For any other type, convert to string
            else:
                content_str = str(content)
                self.logger.debug(f"Converted {type(content)} to string")
                
                # Check if it looks like a bytes representation string
                if content_str.startswith("b'") and content_str.endswith("'"):
                    try:
                        # Remove the b' prefix and ' suffix, then handle escape sequences
                        inner_content = content_str[2:-1]
                        # Handle common escape sequences
                        inner_content = inner_content.replace('\\r\\n', '\r\n')
                        inner_content = inner_content.replace('\\n', '\n')
                        inner_content = inner_content.replace('\\r', '\r')
                        inner_content = inner_content.replace('\\t', '\t')
                        inner_content = inner_content.replace("\\'", "'")
                        inner_content = inner_content.replace('\\"', '"')
                        inner_content = inner_content.replace('\\\\', '\\')
                        self.logger.debug("Successfully parsed bytes string representation")
                        return inner_content
                    except Exception as e:
                        self.logger.debug(f"Failed to parse bytes string representation: {e}")
                
                return content_str
                    
        except Exception as e:
            self.logger.error(f"Error normalizing MSG content: {e}")
            return str(content) if content is not None else None

    def _is_reasonable_text(self, text: str) -> bool:
        """Check if decoded text looks reasonable (not garbage)."""
        if not text or len(text) < 10:
            return False
        
        # Check for reasonable ratio of printable characters
        printable_chars = sum(1 for c in text[:200] if c.isprintable() or c.isspace())
        ratio = printable_chars / min(len(text), 200)
        
        # Check for common HTML/text patterns
        has_html_tags = '<' in text and '>' in text
        has_common_words = any(word in text.lower() for word in ['the', 'and', 'html', 'body', 'div', 'span'])
        
        # Consider it reasonable if:
        # 1. High ratio of printable characters, OR
        # 2. Contains HTML tags and some common words
        return ratio > 0.7 or (has_html_tags and has_common_words)

    def convert_html_to_text(self, html_content: str) -> str:
        """Convert HTML content to plain text with better Unicode handling."""
        try:
            self.logger.debug(f"Converting HTML to text, input length: {len(html_content) if html_content else 0}")
            
            if not html_content:
                return ""
            
            # Log a safe preview (first 100 chars, ASCII only)
            safe_preview = ''.join(c if ord(c) < 128 else '?' for c in html_content[:100])
            self.logger.debug(f"HTML content preview (ASCII-safe): {safe_preview}")
            
            # Try to import html2text for better conversion
            try:
                import html2text
                h = html2text.HTML2Text()
                h.ignore_links = True
                h.ignore_images = True
                h.body_width = 0  # No line wrapping
                h.unicode_snob = True  # Better Unicode handling
                result = h.handle(html_content).strip()
                self.logger.debug(f"html2text conversion successful, result length: {len(result)}")
                
                # Log a safe preview of the result
                safe_result_preview = ''.join(c if ord(c) < 128 else '?' for c in result[:200])
                self.logger.debug(f"Conversion result preview: {safe_result_preview}")
                
                return result
            except ImportError:
                self.logger.debug("html2text not available, using fallback conversion")
                # Fallback to basic HTML tag removal
                import re
                import html
                
                # Remove script and style content
                text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
                
                # Remove HTML tags
                text = re.sub(r'<[^>]+>', '', text)
                
                # Convert HTML entities
                text = html.unescape(text)
                
                # Clean up whitespace
                text = re.sub(r'\s+', ' ', text).strip()
                
                self.logger.debug(f"Fallback conversion successful, result length: {len(text)}")
                return text
                
        except Exception as e:
            self.logger.error(f"Error converting HTML to text: {e}")
            return f"[HTML conversion failed: {e}]"


    def extract_headers(self, message: Message) -> Dict[str, Any]:
        """Extract and analyze email headers."""
        self.logger.debug("Extracting headers...")
        headers = {}
        
        try:
            # Standard headers
            standard_headers = ['From', 'To', 'Cc', 'Bcc', 'Subject', 'Date', 
                              'Message-ID', 'Content-Type', 'Content-Transfer-Encoding']
            
            for header in standard_headers:
                value = message.get(header)
                if value:
                    headers[header.lower().replace('-', '_')] = str(value)
                    self.logger.debug(f"Found header {header}: {value}")
            
            # All headers for completeness
            all_headers = {}
            for key, value in message.items():
                all_headers[key.lower().replace('-', '_')] = str(value)
            
            headers['all_headers'] = all_headers
            headers['header_count'] = len(all_headers)
            
            self.logger.info(f"Extracted {len(all_headers)} headers")
            
        except Exception as e:
            self.logger.error(f"Error extracting headers: {e}")
            headers['error'] = f"Header extraction failed: {e}"
            
        return headers
    
    def analyze_content_type(self, message: Message) -> Dict[str, Any]:
        """Analyze content type and encoding information."""
        self.logger.debug("Analyzing content type...")
        
        content_info = {
            'content_type': 'unknown',
            'main_type': 'unknown',
            'sub_type': 'unknown',
            'charset': None,
            'boundary': None,
            'encoding': None,
            'is_multipart': False
        }
        
        try:
            content_type = message.get_content_type()
            content_info['content_type'] = content_type
            content_info['main_type'] = message.get_content_maintype()
            content_info['sub_type'] = message.get_content_subtype()
            content_info['is_multipart'] = message.is_multipart()
            
            # Get charset
            charset = message.get_content_charset()
            if charset:
                content_info['charset'] = charset
            
            # Get boundary for multipart messages
            if content_info['is_multipart']:
                boundary = message.get_boundary()
                if boundary:
                    content_info['boundary'] = boundary
            
            # Get encoding
            encoding = message.get('Content-Transfer-Encoding')
            if encoding:
                content_info['encoding'] = encoding
                
            self.logger.debug(f"Content type analysis: {content_info}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing content type: {e}")
            content_info['error'] = f"Content type analysis failed: {e}"
            
        return content_info
    
    def detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email."""
        content_type = part.get_content_type()
        filename = part.get_filename()
        
        self.logger.debug(f"Checking for nested email - Content-Type: {content_type}, Filename: {filename}")
        
        # Check content type
        if content_type in ['message/rfc822', 'message/partial', 'message/external-body']:
            self.logger.info(f"Detected nested email by content type: {content_type}")
            return True
        
        # Check if attachment has email-like extensions
        if filename:
            email_extensions = ['.eml', '.msg', '.email']
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(f"Detected nested email by filename: {filename}")
                    return True
        
        # Check content for email headers pattern
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                except:
                    payload_str = payload.decode('latin-1', errors='ignore')
            else:
                payload_str = str(payload)
            
            self.logger.debug(f"Analyzing payload for email patterns (first 200 chars): {payload_str[:200]}")
            
            # Look for email header patterns
            email_indicators = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'Received:', 'Return-Path:']
            header_matches = {}
            
            for indicator in email_indicators:
                if indicator in payload_str[:2000]:  # Check first 2KB
                    header_matches[indicator] = payload_str.find(indicator)
                    
            header_count = len(header_matches)
            self.logger.debug(f"Found email headers: {list(header_matches.keys())} (count: {header_count})")
            
            if header_count >= 3:
                self.logger.info(f"Detected nested email by header pattern analysis ({header_count} headers found)")
                return True
                
        except Exception as e:
            self.logger.debug(f"Error in nested email detection: {e}")
        
        self.logger.debug("No nested email detected")
        return False
    
    def parse_attachment(self, part: Message, depth: int = 0) -> Dict[str, Any]:
        """Parse individual attachment with basic content analysis."""
        self.logger.info(f"Parsing attachment at depth {depth}")
        
        attachment_info = {
            'type': 'attachment',
            'depth': depth,
            'content_type': part.get_content_type(),
            'filename': part.get_filename(),
            'size': None,
            'encoding': part.get('Content-Transfer-Encoding'),
            'is_nested_email': False,
            'nested_email': None,
            'content_disposition': part.get('Content-Disposition'),
            'content_analysis': {}
        }
        
        try:
            # Get payload and perform content analysis
            payload = part.get_payload(decode=True)
            if payload:
                attachment_info['size'] = len(payload)
                
                # Basic content analysis
                self.logger.debug(f"Performing content analysis for attachment: {attachment_info['filename']}")
                content_analysis = self.content_analyzer.analyze_content(
                    payload, 
                    attachment_info['filename'], 
                    attachment_info['content_type']
                )
                
                attachment_info['content_analysis'] = content_analysis
                
                # Update content type if analysis detected something different
                if content_analysis.get('detected_type') and content_analysis.get('confidence', 0) > 0.7:
                    detected_mime = content_analysis.get('mime_type')
                    if detected_mime and detected_mime != attachment_info['content_type']:
                        self.logger.info(f"Content analysis override: {attachment_info['content_type']} -> {detected_mime}")
                        attachment_info['fingerprinted_content_type'] = detected_mime
            
            # Check if this attachment is a nested email
            if self.detect_nested_email(part):
                attachment_info['is_nested_email'] = True
                self.logger.info("Processing nested email attachment")
                
                try:
                    # Get the raw email content
                    if part.get_content_type() == 'message/rfc822':
                        # For message/rfc822, the payload is already a Message object
                        nested_payload = part.get_payload(0) if part.get_payload() else None
                    else:
                        # For other types, decode and parse
                        nested_payload = part.get_payload(decode=True)
                        if isinstance(nested_payload, bytes):
                            # Use our enhanced parser for nested content
                            nested_message = self.parse_email_from_input(nested_payload, part.get_filename())
                        else:
                            nested_message = self.parser.parsestr(str(nested_payload))
                        nested_payload = nested_message
                    
                    if nested_payload:
                        # Recursively parse the nested email
                        attachment_info['nested_email'] = self.parse_email_structure(
                            nested_payload, depth + 1
                        )
                        self.logger.info(f"Successfully parsed nested email at depth {depth + 1}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to parse nested email: {e}")
                    attachment_info['nested_email_error'] = str(e)
            
        except Exception as e:
            self.logger.error(f"Error parsing attachment: {e}")
            attachment_info['error'] = str(e)
        
        return attachment_info
    
    def parse_email_structure(self, message: Message, depth: int = 0) -> Dict[str, Any]:
        """Recursively parse email structure."""
        self.logger.info(f"Parsing email structure at depth {depth}")
        
        structure = {
            'type': 'email',
            'depth': depth,
            'headers': self.extract_headers(message),
            'content_info': self.analyze_content_type(message),
            'body': self.extract_email_body(message),
            'parts': [],
            'attachments': [],
            'nested_emails': [],
            'part_count': 0,
            'attachment_count': 0,
            'nested_email_count': 0
        }
        
        try:
            if message.is_multipart():
                self.logger.info(f"Processing multipart message with {len(message.get_payload())} parts")
                
                for i, part in enumerate(message.get_payload()):
                    self.logger.debug(f"Processing part {i} at depth {depth}")
                    
                    part_info = {
                        'part_index': i,
                        'content_type': part.get_content_type(),
                        'content_disposition': part.get('Content-Disposition'),
                        'filename': part.get_filename(),
                        'is_attachment': False,
                        'is_nested_email': False
                    }
                    
                    # Determine if this is an attachment
                    disposition = part.get('Content-Disposition', '').lower()
                    if 'attachment' in disposition or part.get_filename():
                        part_info['is_attachment'] = True
                        attachment = self.parse_attachment(part, depth)
                        structure['attachments'].append(attachment)
                        
                        if attachment.get('is_nested_email'):
                            structure['nested_emails'].append(attachment['nested_email'])
                            structure['nested_email_count'] += 1
                        
                        structure['attachment_count'] += 1
                    
                    structure['parts'].append(part_info)
                    structure['part_count'] += 1
                    
            else:
                self.logger.info("Processing single-part message")
                # Check if the single part itself is a nested email
                if self.detect_nested_email(message):
                    self.logger.info("Single-part message contains nested email")
                    attachment = self.parse_attachment(message, depth)
                    structure['attachments'].append(attachment)
                    if attachment.get('is_nested_email'):
                        structure['nested_emails'].append(attachment['nested_email'])
                        structure['nested_email_count'] += 1
                    structure['attachment_count'] += 1
                
        except Exception as e:
            self.logger.error(f"Error parsing email structure: {e}")
            structure['parsing_error'] = str(e)
        
        self.logger.info(f"Completed parsing at depth {depth}: "
                        f"{structure['part_count']} parts, "
                        f"{structure['attachment_count']} attachments, "
                        f"{structure['nested_email_count']} nested emails")
        
        return structure
    
    def parse(self, input_data: Union[str, bytes], filename: str = None) -> Dict[str, Any]:
        """Main parsing function with enhanced format detection."""
        self.logger.info("Starting email parsing process")
        
        # Detect format first
        if isinstance(input_data, str):
            data_bytes = input_data.encode('utf-8')
        else:
            data_bytes = input_data
            
        detected_format, confidence = self.format_detector.detect_format(data_bytes, filename)
        
        result = {
            'status': 'success',
            'detected_format': detected_format,
            'format_confidence': confidence,
            'msg_support_available': MSG_SUPPORT,
            'structure': None,
            'errors': [],
            'warnings': [],
            'format_details': {
                'magic_bytes_detected': None,
                'content_analysis': None,
                'filename_hint': filename
            }
        }
        
        # Add format support warnings
        if detected_format == 'msg' and not MSG_SUPPORT:
            result['warnings'].append("MSG format detected but extract_msg library not installed. Run: pip install extract-msg")
        elif detected_format == 'pst':
            result['warnings'].append("PST format detected but not supported. PST files are mailbox containers, not single email messages.")
        elif detected_format == 'unknown':
            result['warnings'].append("Could not reliably detect email format. Attempting fallback parsing.")
        
        try:
            # Parse the email
            message = self.parse_email_from_input(input_data, filename)
            if not message:
                result['status'] = 'failed'
                result['errors'].append(f'Failed to parse input as {detected_format} format')
                
                # Provide debugging information
                if detected_format == 'unknown':
                    result['errors'].append("Format detection failed. Ensure input is a valid email file (.eml, .msg, etc.)")
                elif detected_format == 'msg' and not MSG_SUPPORT:
                    result['errors'].append("Install extract-msg library: pip install extract-msg")
                elif detected_format == 'pst':
                    result['errors'].append("PST files are not supported. Extract individual emails first.")
                    
                return result
            
            # Extract structure
            result['structure'] = self.parse_email_structure(message)
            
            self.logger.info("Email parsing completed successfully")
            
        except Exception as e:
            self.logger.error(f"Fatal error during parsing: {e}")
            result['status'] = 'failed'
            result['errors'].append(str(e))
        
        return result

def main():
    """Example usage of the EmailParser."""
    parser = EmailParser(log_level=logging.INFO)
    
    # Check MSG support
    if not MSG_SUPPORT:
        print("Warning: MSG file support not available. Install with: pip install extract-msg")
    
    # Example: Read from file
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        try:
            filename = os.path.basename(filepath)
            
            with open(filepath, 'rb') as f:
                email_data = f.read()
            
            result = parser.parse(email_data, filename)
            
            # Output JSON result
            output_file = f"{filepath}_parsed.json"
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            
            print(f"Parsing complete. Results saved to: {output_file}")
            print(f"Status: {result['status']}")
            print(f"Detected format: {result['detected_format']} (confidence: {result['format_confidence']:.2f})")
            
            if result['warnings']:
                print("Warnings:")
                for warning in result['warnings']:
                    print(f"  - {warning}")
            
            if result['errors']:
                print("Errors:")
                for error in result['errors']:
                    print(f"  - {error}")
            
            if result['structure']:
                structure = result['structure']
                print(f"Parts: {structure['part_count']}")
                print(f"Attachments: {structure['attachment_count']}")
                print(f"Nested emails: {structure['nested_email_count']}")
            
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Usage: python email_parser.py <email_file>")
        print("Supported formats: .eml, .msg (with extract-msg), .mbox, raw email")
        print("For MSG support: pip install extract-msg")

if __name__ == "__main__":
    main()