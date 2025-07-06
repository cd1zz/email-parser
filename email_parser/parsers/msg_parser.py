# ============================================================================
# email_parser/parsers/msg_parser.py
# ============================================================================

import tempfile
import os
import base64
import io
import logging
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
            self._add_multipart_alternative(lines, plain_content, html_content)
        elif has_plain:
            self._add_plain_text_part(lines, plain_content)
        elif has_html:
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
            self._add_multipart_alternative(lines, plain_content, html_content)
        elif has_plain:
            self._add_plain_text_part(lines, plain_content)
        elif has_html:
            self._add_html_as_text_part(lines, html_content)
        else:
            self._add_empty_body(lines)
    
    def _add_multipart_alternative(self, lines: List[str], plain_content: str, html_content: str) -> None:
        """Add multipart/alternative structure."""
        alt_boundary = "----=_NextPart_EmailParser_MSG_Alt"
        lines.append(f"Content-Type: multipart/alternative; boundary=\"{alt_boundary}\"")
        lines.append("")
        
        # Plain text part
        lines.append(f"--{alt_boundary}")
        lines.append("Content-Type: text/plain; charset=utf-8")
        lines.append("")
        lines.append(plain_content)
        
        # HTML part
        lines.append(f"\n--{alt_boundary}")
        lines.append("Content-Type: text/html; charset=utf-8")
        lines.append("")
        lines.append(html_content)
        lines.append(f"\n--{alt_boundary}--")
    
    def _add_plain_text_part(self, lines: List[str], content: str) -> None:
        """Add plain text content."""
        lines.append("Content-Type: text/plain; charset=utf-8")
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
                    self.logger.debug(f"Attachment filename: {filename}")
                    
                    # Extract attachment data for analysis
                    attachment_data = self._extract_attachment_data(attachment)
                    
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
    
    def _extract_attachment_data(self, attachment) -> Optional[bytes]:
        """Extract raw data from MSG attachment for content analysis."""
        try:
            if hasattr(attachment, 'data') and attachment.data:
                data = attachment.data
                if isinstance(data, bytes):
                    return data
                else:
                    self.logger.debug(f"Attachment data is not bytes, type: {type(data)}")
                    return None
            elif hasattr(attachment, 'save'):
                buffer = io.BytesIO()
                attachment.save(buffer)
                return buffer.getvalue()
            else:
                self.logger.warning("Could not extract attachment data from MSG")
                return None
        except Exception as e:
            self.logger.warning(f"Error extracting MSG attachment data: {e}")
            return None