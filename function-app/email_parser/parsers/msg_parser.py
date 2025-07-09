# ============================================================================
# email_parser/parsers/msg_parser.py
# ============================================================================
"""
MSG format parser for Microsoft Outlook email files.

This module provides parsing functionality for MSG files, which are Microsoft
Outlook's proprietary email format based on OLE compound documents.
Supports nested email parsing and attachment extraction.
"""

import tempfile
import os
import base64
import io
import logging
import re
from typing import Optional, Tuple, List
from email.message import Message
import email.parser
import email.policy

from ..interfaces import EmailFormatParser, ContentNormalizer
from ..converters import HtmlToTextConverter

try:
    import extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False


class MsgFormatParser(EmailFormatParser):
    """Parser for Microsoft Outlook MSG files with full functionality from original."""
    
    def __init__(self, logger: logging.Logger, content_normalizer: ContentNormalizer, 
                 html_converter: HtmlToTextConverter, content_analyzer):
        self.logger = logger
        self.content_normalizer = content_normalizer
        self.html_converter = html_converter
        self.content_analyzer = content_analyzer
        self.parser = email.parser.Parser(policy=email.policy.default)
    
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Check if this is a MSG file."""
        # Check magic bytes for OLE/MSG format
        if data.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            return True, 0.9
        
        # Check filename
        if filename and filename.lower().endswith('.msg'):
            return True, 0.7
        
        return False, 0.0
    
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse MSG file data."""
        if not MSG_SUPPORT:
            self.logger.error("MSG support requires extract_msg")
            return None
        
        return self._parse_msg_file(data)
    
    def _parse_msg_file(self, data: bytes) -> Optional[Message]:
        """Parse MSG file using extract_msg with full original functionality."""
        tmp_file_path = None
        try:
            self.logger.info("Parsing MSG file using extract_msg")
            
            # Write to temporary file for extract_msg
            with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmp_file:
                tmp_file.write(data)
                tmp_file.flush()
                tmp_file_path = tmp_file.name
            
            # Extract MSG content
            msg = extract_msg.Message(tmp_file_path)
            
            # Convert MSG to email-like structure
            email_content = self._convert_msg_to_email_format(msg)
            
            # Close MSG object
            if hasattr(msg, 'close'):
                msg.close()
            elif hasattr(msg, '__exit__'):
                msg.__exit__(None, None, None)
            
            if email_content:
                return self.parser.parsestr(email_content)
            return None
                
        except Exception as e:
            self.logger.error(f"Failed to parse MSG file: {e}")
            return None
        finally:
            if tmp_file_path and os.path.exists(tmp_file_path):
                try:
                    os.unlink(tmp_file_path)
                    self.logger.debug(f"Cleaned up temporary file: {tmp_file_path}")
                except Exception as cleanup_error:
                    self.logger.warning(f"Could not clean up temporary file {tmp_file_path}: {cleanup_error}")
    
    def _convert_msg_to_email_format(self, msg) -> Optional[str]:
        """Convert MSG object to email format - full original logic."""
        try:
            lines = []
            
            self.logger.info("Starting MSG to email conversion...")
            
            # Add headers
            self._add_headers(lines, msg)
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
            
            # Extract content with enhanced logic from original
            plain_content = self._extract_plain_content(msg)
            html_content = self._extract_html_content(msg)
            
            # Debug logging for content analysis
            if plain_content:
                self.logger.info(f"Plain content length: {len(plain_content)} chars. First 500: {plain_content[:500]}")
                self.logger.info(f"Plain content contains Proofpoint markers: {self._contains_proofpoint_markers(plain_content)}")
            
            if html_content:
                self.logger.info(f"HTML content length: {len(html_content)} chars. First 500: {html_content[:500]}")
                self.logger.info(f"HTML content contains Proofpoint markers: {self._contains_proofpoint_markers(html_content)}")
                
                # Check if HTML content contains the actual Proofpoint structure
                if "---------- Begin Email Headers ----------" in html_content:
                    self.logger.info("🔍 FOUND: HTML content contains proper Proofpoint structure!")
                elif "Begin Email Headers" in html_content:
                    self.logger.info("🔍 FOUND: HTML content contains simplified Proofpoint structure!")
                elif "---------- Begin Reported Email ----------" in html_content:
                    self.logger.info("🔍 FOUND: HTML content contains Proofpoint email section!")
                
                # Show a larger sample of HTML content to see the structure
                self.logger.info(f"HTML content sample (chars 1000-2000): {html_content[1000:2000]}")
                self.logger.info(f"HTML content sample (chars 5000-6000): {html_content[5000:6000]}")
                self.logger.info(f"HTML content sample (chars 10000-11000): {html_content[10000:11000]}")
            
            # Determine structure based on content and attachments
            has_plain = plain_content and plain_content.strip()
            has_html = html_content and html_content.strip()
            
            if has_attachments:
                self._build_multipart_mixed_structure(lines, plain_content, html_content, 
                                                    has_plain, has_html, msg)
            else:
                self._build_simple_structure(lines, plain_content, html_content, 
                                           has_plain, has_html)
            
            result = "\n".join(str(line) for line in lines)
            self.logger.info(f"Converted MSG to email format with {len(lines)} lines, {attachment_count} attachments")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error converting MSG to email format: {e}")
            return None
    
    def _add_headers(self, lines: List[str], msg) -> None:
        """Add email headers from MSG object."""
        headers = [
            ('sender', 'From'),
            ('to', 'To'), 
            ('cc', 'Cc'),
            ('subject', 'Subject'),
            ('date', 'Date'),
            ('messageId', 'Message-ID')
        ]
        
        for attr, header in headers:
            try:
                value = getattr(msg, attr, None)
                if value:
                    lines.append(f"{header}: {value}")
                    self.logger.debug(f"Added {header}: {value}")
            except Exception as e:
                self.logger.debug(f"Error getting {attr}: {e}")
    
    def _extract_plain_content(self, msg) -> Optional[str]:
        """Extract plain text content using getSaveBody method and fallbacks."""
        # Try getSaveBody method first (from original)
        try:
            if hasattr(msg, 'getSaveBody'):
                save_body_bytes = msg.getSaveBody()
                if save_body_bytes and len(save_body_bytes) > 50:
                    plain_content = save_body_bytes.decode('utf-8', errors='ignore')
                    self.logger.info(f"Extracted plain text from getSaveBody: {len(plain_content)} chars")
                    
                    # Check if content contains header-like patterns and try to extract body
                    if self._contains_header_patterns(plain_content):
                        body_content = self._extract_body_from_formatted_content(plain_content)
                        if body_content:
                            self.logger.info(f"Extracted body content after removing headers: {len(body_content)} chars")
                            return body_content
                    
                    return plain_content
        except Exception as e:
            self.logger.debug(f"Could not extract from getSaveBody: {e}")
        
        # Fall back to body attribute
        try:
            if hasattr(msg, 'body') and msg.body:
                return self.content_normalizer.normalize(msg.body)
        except Exception as e:
            self.logger.debug(f"Error extracting plain body: {e}")
        
        return None
    
    def _contains_header_patterns(self, content: str) -> bool:
        """Check if content contains email header patterns."""
        header_patterns = [
            r'^From:.*',
            r'^To:.*', 
            r'^Subject:.*',
            r'^Sent:.*\d{4}.*',
            r'^Date:.*\d{4}.*',
            r'^-{5,}$'  # Separator line
        ]
        
        lines = content.split('\n')[:10]  # Check first 10 lines
        header_count = 0
        
        for line in lines:
            line = line.strip()
            for pattern in header_patterns:
                if re.match(pattern, line):
                    header_count += 1
                    self.logger.debug(f"Found header pattern: {line}")
                    break
        
        self.logger.debug(f"Header pattern count: {header_count}")
        return header_count >= 2  # At least 2 header-like patterns
    
    def _extract_body_from_formatted_content(self, content: str) -> Optional[str]:
        """Extract body content from formatted message content with headers."""
        lines = content.split('\n')
        
        # Look for separator line like "--------" or empty line after headers
        body_start_idx = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == '-' * len(stripped) and len(stripped) >= 5:
                body_start_idx = i + 1
                break
            elif i > 0 and not stripped and lines[i-1].strip().startswith(('From:', 'To:', 'Subject:', 'Sent:', 'Date:')):
                body_start_idx = i + 1
                break
        
        if body_start_idx is not None and body_start_idx < len(lines):
            body_lines = lines[body_start_idx:]
            body_content = '\n'.join(body_lines).strip()
            return body_content if body_content else None
        
        return None
    
    def _extract_html_content(self, msg) -> Optional[str]:
        """Extract HTML content with proper encoding from original."""
        try:
            if hasattr(msg, 'htmlBody') and msg.htmlBody:
                # Use proper encoding detection from original
                for encoding in ['windows-1252', 'latin-1', 'utf-8']:
                    try:
                        if isinstance(msg.htmlBody, bytes):
                            html_content = msg.htmlBody.decode(encoding)
                        else:
                            html_content = self.content_normalizer.normalize(msg.htmlBody)
                        
                        if html_content:
                            self.logger.info(f"Successfully decoded HTML body using {encoding}")
                            return html_content
                    except UnicodeDecodeError:
                        continue
                
                # Fallback
                if isinstance(msg.htmlBody, bytes):
                    html_content = msg.htmlBody.decode('utf-8', errors='replace')
                else:
                    html_content = self.content_normalizer.normalize(msg.htmlBody)
                self.logger.warning("Used fallback HTML decoding")
                return html_content
        except Exception as e:
            self.logger.error(f"Error extracting HTML body: {e}")
        
        return None
    
    def _build_multipart_mixed_structure(self, lines: List[str], plain_content: Optional[str], 
                                       html_content: Optional[str], has_plain: bool, 
                                       has_html: bool, msg) -> None:
        """Build multipart/mixed structure for messages with attachments."""
        main_boundary = "----=_NextPart_EmailParser_MSG"
        lines.append(f"Content-Type: multipart/mixed; boundary=\"{main_boundary}\"")
        lines.append("")
        lines.append(f"--{main_boundary}")
        
        if has_plain and has_html:
            # Special handling for Proofpoint emails - if HTML contains Proofpoint structure, use only HTML converted to text
            if self._contains_proofpoint_markers(html_content) and "---------- Begin Email Headers ----------" in html_content:
                self.logger.info("Detected Proofpoint structure in HTML - using HTML content only as plain text (with attachments)")
                plain_proofpoint_content = self.html_converter.convert(html_content)
                if plain_proofpoint_content and self._contains_proofpoint_markers(plain_proofpoint_content):
                    self.logger.info("Successfully extracted Proofpoint content from HTML for multipart mixed email")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("Content-Transfer-Encoding: base64")
                    lines.append("")
                    
                    # Encode as base64
                    encoded_content = base64.b64encode(plain_proofpoint_content.encode('utf-8')).decode('ascii')
                    for i in range(0, len(encoded_content), 76):
                        lines.append(encoded_content[i:i+76])
                else:
                    # Fallback to normal multipart
                    self._add_multipart_alternative(lines, plain_content, html_content)
            else:
                self._add_multipart_alternative(lines, plain_content, html_content)
        elif has_plain:
            self._add_plain_text_part(lines, plain_content)
        elif has_html:
            # Check if HTML content contains Proofpoint markers and needs special handling
            if self._contains_proofpoint_markers(html_content):
                self.logger.info("Detected Proofpoint content in HTML - extracting text and preserving as plain text")
                # Convert HTML to plain text to extract the Proofpoint markers properly
                plain_proofpoint_content = self.html_converter.convert(html_content)
                if plain_proofpoint_content and self._contains_proofpoint_markers(plain_proofpoint_content):
                    self.logger.info("Successfully extracted Proofpoint content from HTML")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("Content-Transfer-Encoding: base64")
                    lines.append("")
                    
                    # Encode as base64
                    encoded_content = base64.b64encode(plain_proofpoint_content.encode('utf-8')).decode('ascii')
                    for i in range(0, len(encoded_content), 76):
                        lines.append(encoded_content[i:i+76])
                else:
                    # Fallback to HTML
                    lines.append("Content-Type: text/html; charset=utf-8")
                    lines.append("")
                    lines.append(html_content)
            else:
                self._add_html_as_text_part(lines, html_content)
        else:
            self._add_empty_body(lines)
        
        # Add attachments with full original logic
        self._add_attachments(lines, msg, main_boundary)
        lines.append(f"\n--{main_boundary}--")
    
    def _build_simple_structure(self, lines: List[str], plain_content: Optional[str], 
                               html_content: Optional[str], has_plain: bool, has_html: bool) -> None:
        """Build simple structure for messages without attachments."""
        if has_plain and has_html:
            # Special handling for Proofpoint emails - if HTML contains Proofpoint structure, use only HTML converted to text
            if self._contains_proofpoint_markers(html_content) and "---------- Begin Email Headers ----------" in html_content:
                self.logger.info("Detected Proofpoint structure in HTML - using HTML content only as plain text")
                plain_proofpoint_content = self.html_converter.convert(html_content)
                self.logger.info(f"🔍 DEBUG: HTML-to-text conversion result: {len(plain_proofpoint_content) if plain_proofpoint_content else 0} chars")
                if plain_proofpoint_content:
                    self.logger.info(f"🔍 DEBUG: Converted text first 1000 chars: {plain_proofpoint_content[:1000]}")
                    self.logger.info(f"🔍 DEBUG: Contains Proofpoint markers after conversion: {self._contains_proofpoint_markers(plain_proofpoint_content)}")
                
                if plain_proofpoint_content and self._contains_proofpoint_markers(plain_proofpoint_content):
                    self.logger.info("Successfully extracted Proofpoint content from HTML for multipart email")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("Content-Transfer-Encoding: base64")
                    lines.append("")
                    
                    # Encode as base64
                    encoded_content = base64.b64encode(plain_proofpoint_content.encode('utf-8')).decode('ascii')
                    for i in range(0, len(encoded_content), 76):
                        lines.append(encoded_content[i:i+76])
                else:
                    # Fallback to normal multipart
                    self._add_multipart_alternative(lines, plain_content, html_content)
            else:
                self._add_multipart_alternative(lines, plain_content, html_content)
        elif has_plain:
            self._add_plain_text_part(lines, plain_content)
        elif has_html:
            # Check if HTML content contains Proofpoint markers and needs special handling
            if self._contains_proofpoint_markers(html_content):
                self.logger.info("Detected Proofpoint content in HTML - extracting text and preserving as plain text")
                # Convert HTML to plain text to extract the Proofpoint markers properly
                plain_proofpoint_content = self.html_converter.convert(html_content)
                if plain_proofpoint_content and self._contains_proofpoint_markers(plain_proofpoint_content):
                    self.logger.info("Successfully extracted Proofpoint content from HTML")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("Content-Transfer-Encoding: base64")
                    lines.append("")
                    
                    # Encode as base64
                    encoded_content = base64.b64encode(plain_proofpoint_content.encode('utf-8')).decode('ascii')
                    for i in range(0, len(encoded_content), 76):
                        lines.append(encoded_content[i:i+76])
                else:
                    # Fallback to HTML
                    lines.append("Content-Type: text/html; charset=utf-8")
                    lines.append("")
                    lines.append(html_content)
            else:
                self._add_html_as_text_part(lines, html_content)
        else:
            self._add_empty_body(lines)
    
    def _add_multipart_alternative(self, lines: List[str], plain_content: str, html_content: str) -> None:
        """Add multipart/alternative structure."""
        alt_boundary = "----=_NextPart_EmailParser_MSG_Alt"
        lines.append(f"Content-Type: multipart/alternative; boundary=\"{alt_boundary}\"")
        lines.append("")
        
        # Plain text part - check if it contains Proofpoint content
        lines.append(f"--{alt_boundary}")
        lines.append("Content-Type: text/plain; charset=utf-8")
        
        # If plain content contains Proofpoint markers, use base64 encoding like the original EML
        if self._contains_proofpoint_markers(plain_content):
            self.logger.info("Encoding Proofpoint plain text content as base64")
            lines.append("Content-Transfer-Encoding: base64")
            lines.append("")
            
            # Encode content as base64
            encoded_content = base64.b64encode(plain_content.encode('utf-8')).decode('ascii')
            # Split into 76-character lines
            for i in range(0, len(encoded_content), 76):
                lines.append(encoded_content[i:i+76])
        else:
            lines.append("")
            lines.append(plain_content)
        
        # HTML part
        lines.append(f"\n--{alt_boundary}")
        lines.append("Content-Type: text/html; charset=utf-8")
        
        # If HTML content contains Proofpoint markers, convert to plain text and use base64 encoding
        if self._contains_proofpoint_markers(html_content):
            self.logger.info("Converting Proofpoint HTML to plain text and encoding as base64")
            # Convert HTML to plain text to extract clean Proofpoint markers
            plain_proofpoint_content = self.html_converter.convert(html_content)
            if plain_proofpoint_content and self._contains_proofpoint_markers(plain_proofpoint_content):
                self.logger.info("Successfully converted HTML Proofpoint content to plain text")
                lines.append("Content-Transfer-Encoding: base64")
                lines.append("")
                
                # Encode plain text content as base64
                encoded_content = base64.b64encode(plain_proofpoint_content.encode('utf-8')).decode('ascii')
                # Split into 76-character lines
                for i in range(0, len(encoded_content), 76):
                    lines.append(encoded_content[i:i+76])
            else:
                # Fallback to original HTML
                lines.append("Content-Transfer-Encoding: base64")
                lines.append("")
                encoded_content = base64.b64encode(html_content.encode('utf-8')).decode('ascii')
                for i in range(0, len(encoded_content), 76):
                    lines.append(encoded_content[i:i+76])
        else:
            lines.append("")
            lines.append(html_content)
            
        lines.append(f"\n--{alt_boundary}--")
    
    def _add_plain_text_part(self, lines: List[str], content: str) -> None:
        """Add plain text content."""
        lines.append("Content-Type: text/plain; charset=utf-8")
        
        # If content contains Proofpoint markers, use base64 encoding
        if self._contains_proofpoint_markers(content):
            self.logger.info("Encoding Proofpoint plain text content as base64")
            lines.append("Content-Transfer-Encoding: base64")
            lines.append("")
            
            # Encode content as base64
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('ascii')
            # Split into 76-character lines
            for i in range(0, len(encoded_content), 76):
                lines.append(encoded_content[i:i+76])
        else:
            lines.append("")
            lines.append(content)
    
    def _add_html_as_text_part(self, lines: List[str], html_content: str) -> None:
        """Add HTML content converted to text."""
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("")
        converted_text = self.html_converter.convert(html_content)
        lines.append(converted_text if converted_text else "[HTML conversion failed]")
    
    def _add_empty_body(self, lines: List[str]) -> None:
        """Add empty body placeholder."""
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("")
        lines.append("[No body content found]")
    
    def _add_attachments(self, lines: List[str], msg, boundary: str) -> None:
        """Add attachments with full content analysis from original."""
        try:
            for i, attachment in enumerate(msg.attachments):
                self.logger.info(f"Processing MSG attachment {i}...")
                lines.append(f"\n--{boundary}")
                
                try:
                    filename = (getattr(attachment, 'longFilename', None) or 
                               getattr(attachment, 'shortFilename', f'attachment_{i}'))
                    self.logger.info(f"Attachment filename: {filename} ")
                    
                    # Debug attachment attributes
                    self.logger.debug(f"Attachment type: {type(attachment)}")
                    self.logger.debug(f"Attachment dir: {[x for x in dir(attachment) if not x.startswith('_')][:20]}")
                    
                    # Extract attachment data for analysis
                    attachment_data = self._extract_attachment_data(attachment)
                    
                    # Debug logging for attachment content
                    if attachment_data:
                        self.logger.info(f"Attachment data length: {len(attachment_data)} bytes")
                        # Check if it's text-like content
                        try:
                            if len(attachment_data) > 0:
                                sample_text = attachment_data[:1000].decode('utf-8', errors='ignore')
                                self.logger.info(f"Attachment text sample (first 500 chars): {sample_text[:500]}")
                                if self._contains_proofpoint_markers(sample_text):
                                    self.logger.info("🔍 FOUND: Attachment contains Proofpoint markers!")
                        except Exception as e:
                            self.logger.debug(f"Could not decode attachment as text: {e}")
                    else:
                        self.logger.info("No attachment data extracted")
                    
                    if attachment_data and filename and filename.lower().endswith('.eml'):
                        # Nested email attachment
                        self.logger.info(f"Detected potential nested email attachment: {filename}")
                        lines.append(f"Content-Type: message/rfc822")
                        lines.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
                        lines.append("Content-Transfer-Encoding: base64")
                        lines.append("")
                        
                        encoded_data = base64.b64encode(attachment_data).decode('ascii')
                        for j in range(0, len(encoded_data), 76):
                            lines.append(encoded_data[j:j+76])
                    else:
                        # Regular attachment
                        lines.append(f"Content-Type: application/octet-stream")
                        lines.append(f"Content-Disposition: attachment; filename=\"{filename}\"")
                        
                        if attachment_data:
                            lines.append("Content-Transfer-Encoding: base64")
                            lines.append("")
                            
                            encoded_data = base64.b64encode(attachment_data).decode('ascii')
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
                    
        except Exception as e:
            self.logger.error(f"Error processing MSG attachments: {e}")
    
    def _contains_proofpoint_markers(self, content: str) -> bool:
        """Check if content contains Proofpoint markers."""
        proofpoint_markers = [
            "---------- Begin Email Headers ----------",
            "---------- Begin Reported Email ----------",
            "---------- Begin Email ----------",
            "Begin Email Headers",
            "Begin Reported Email",
            "Potential Phish:",
            "Suspicious Email:",
            "Phishing Alert:",
            "Security Alert:",
            "Proofpoint"
        ]
        
        return any(marker in content for marker in proofpoint_markers)

    def _is_eml_content(self, data: bytes) -> bool:
        """Check if data appears to be EML format by examining headers."""
        try:
            # Check first 1KB for email headers
            sample = data[:1024]
            try:
                text = sample.decode('utf-8', errors='ignore')
            except:
                text = sample.decode('latin-1', errors='ignore')
            
            # Look for common email headers
            email_headers = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'MIME-Version:']
            headers_found = sum(1 for header in email_headers if header in text)
            
            return headers_found >= 2
        except Exception as e:
            self.logger.debug(f"Error checking EML content: {e}")
            return False
    
    def _extract_attachment_data(self, attachment) -> Optional[bytes]:
        """Extract raw data from MSG attachment for content analysis."""
        try:
            # First check if the attachment has a data attribute
            if hasattr(attachment, 'data'):
                data = attachment.data
                if data is not None:
                    # Check if data is a nested Message object
                    if hasattr(data, '__class__') and 'Message' in str(type(data)):
                        self.logger.debug("Attachment data is a nested Message object, extracting EML content")
                        # This is a nested email - we need to export it as EML format
                        try:
                            # First try to construct EML manually
                            eml_content = self._convert_msg_to_email_format(data)
                            if eml_content:
                                self.logger.debug(f"Manually converted nested MSG to EML: {len(eml_content)} bytes")
                                return eml_content.encode('utf-8', errors='ignore')
                                
                            # If that didn't work, try to save the nested message to a temp file
                            if hasattr(data, 'save'):
                                with tempfile.NamedTemporaryFile(suffix='.eml', delete=False) as tmp_file:
                                    temp_path = tmp_file.name
                                try:
                                    # Save as EML format
                                    data.save(temp_path)
                                    with open(temp_path, 'rb') as f:
                                        eml_data = f.read()
                                    if eml_data:
                                        self.logger.debug(f"Successfully extracted nested email as EML: {len(eml_data)} bytes")
                                        return eml_data
                                finally:
                                    if os.path.exists(temp_path):
                                        os.unlink(temp_path)
                                
                        except Exception as e:
                            self.logger.warning(f"Error extracting nested Message: {e}")
                            
                    elif isinstance(data, bytes):
                        self.logger.debug(f"Got attachment data as bytes: {len(data)} bytes")
                        return data
                    elif isinstance(data, str):
                        self.logger.debug(f"Got attachment data as string: {len(data)} chars, encoding to bytes")
                        return data.encode('utf-8', errors='ignore')
                    else:
                        self.logger.debug(f"Attachment data is type: {type(data)}, attempting conversion")
                        try:
                            # Try to convert to string then bytes
                            str_data = str(data)
                            return str_data.encode('utf-8', errors='ignore')
                        except:
                            pass
            
            # If data attribute doesn't work, try save method
            if hasattr(attachment, 'save'):
                self.logger.debug("Trying to extract attachment using save method")
                buffer = io.BytesIO()
                attachment.save(buffer)
                buffer.seek(0)
                data = buffer.getvalue()
                if data:
                    self.logger.debug(f"Got attachment data via save method: {len(data)} bytes")
                    return data
                    
            self.logger.warning("Could not extract attachment data from MSG")
            return None
        except Exception as e:
            self.logger.warning(f"Error extracting MSG attachment data: {e}")
            return None