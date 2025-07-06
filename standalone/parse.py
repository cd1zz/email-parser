#!/usr/bin/env python3
"""
Intelligent Email Parser with Robust Format Detection and Recursive Structure Analysis
Handles nested emails, attachments, various input formats (.eml, .msg, raw) with detailed logging.
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

# Try to import extract_msg for MSG file support
try:
    import extract_msg
    MSG_SUPPORT = True
except ImportError:
    MSG_SUPPORT = False

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

    def convert_msg_to_email_format(self, msg) -> Optional[str]:
        """Convert MSG object to email-like format for standard parsing."""
        try:
            lines = []
            
            self.logger.info("Starting MSG to email conversion...")
            self.logger.debug(f"MSG object type: {type(msg)}")
            
            # Log available MSG attributes for debugging
            msg_attrs = [attr for attr in dir(msg) if not attr.startswith('_')]
            self.logger.debug(f"Available MSG attributes: {msg_attrs[:20]}...")  # Limit output
            
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
                    
                    # Log attachment details
                    for i, att in enumerate(msg.attachments):
                        att_attrs = [attr for attr in dir(att) if not attr.startswith('_')]
                        self.logger.debug(f"Attachment {i} attributes: {att_attrs}")
                        
                        try:
                            filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', f'attachment_{i}')
                            self.logger.info(f"Attachment {i}: {filename}")
                        except:
                            self.logger.debug(f"Could not get filename for attachment {i}")
                    
                    boundary = "----=_NextPart_EmailParser_MSG"
                    lines.append(f"Content-Type: multipart/mixed; boundary=\"{boundary}\"")
                    lines.append("")
                    lines.append(f"--{boundary}")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
                else:
                    self.logger.info("No attachments found in MSG file")
                    lines.append("Content-Type: text/plain; charset=utf-8")
                    lines.append("")
            except Exception as e:
                self.logger.error(f"Error checking MSG attachments: {e}")
                lines.append("Content-Type: text/plain; charset=utf-8")
                lines.append("")
            
            # Add body
            try:
                if hasattr(msg, 'body') and msg.body:
                    lines.append(msg.body)
                    self.logger.debug(f"Added plain text body content ({len(msg.body)} chars)")
                elif hasattr(msg, 'htmlBody') and msg.htmlBody:
                    # Convert HTML body to plain text
                    self.logger.info(f"Converting HTML body to plain text ({len(msg.htmlBody)} chars)")
                    plain_text_body = self.convert_html_to_text(msg.htmlBody)
                    if plain_text_body and plain_text_body.strip():
                        lines.append(plain_text_body)
                        self.logger.info(f"Successfully converted HTML to plain text ({len(plain_text_body)} chars)")
                    else:
                        lines.append("[HTML body detected but conversion failed]")
                        self.logger.warning("HTML to text conversion failed or produced empty result")
                else:
                    lines.append("[No body content found]")
                    self.logger.debug("No body content found")
            except Exception as e:
                self.logger.error(f"Error reading body content: {e}")
                lines.append("[Error reading body content]")
            
            # Process attachments with actual content
            if has_attachments:
                try:
                    boundary = "----=_NextPart_EmailParser_MSG"
                    for i, attachment in enumerate(msg.attachments):
                        self.logger.info(f"Processing MSG attachment {i}...")
                        lines.append(f"\n--{boundary}")
                        
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
                    
                    lines.append(f"\n--{boundary}--")
                    
                except Exception as e:
                    self.logger.error(f"Error processing MSG attachments: {e}")
            
            result = "\n".join(str(line) for line in lines)  # Ensure all items are strings
            self.logger.info(f"Converted MSG to email format with {len(lines)} lines, {attachment_count} attachments")
            self.logger.debug(f"First 1000 chars of converted content:\n{result[:1000]}")
            self.logger.debug(f"Last 500 chars of converted content:\n{result[-500:]}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error converting MSG to email format: {e}")
            return None
    
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
                            text_content = part.get_payload(decode=True)
                            if isinstance(text_content, bytes):
                                charset = part.get_content_charset() or 'utf-8'
                                text_content = text_content.decode(charset, errors='ignore')
                            
                            body_info['plain_text'] = str(text_content).strip()
                            body_info['body_type'] = 'plain'
                            body_info['char_count'] = len(body_info['plain_text'])
                            self.logger.debug(f"Found plain text body ({body_info['char_count']} chars)")
                            
                        except Exception as e:
                            self.logger.debug(f"Error extracting plain text: {e}")
                    
                    elif content_type == 'text/html' and not body_info['html_content']:
                        try:
                            html_content = part.get_payload(decode=True)
                            if isinstance(html_content, bytes):
                                charset = part.get_content_charset() or 'utf-8'
                                html_content = html_content.decode(charset, errors='ignore')
                            
                            body_info['html_content'] = str(html_content).strip()
                            self.logger.debug(f"Found HTML body ({len(body_info['html_content'])} chars)")
                            
                            # Convert HTML to plain text if no plain text version exists
                            if not body_info['plain_text']:
                                plain_from_html = self.convert_html_to_text(body_info['html_content'])
                                if plain_from_html:
                                    body_info['plain_text'] = plain_from_html
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
                    content = message.get_payload(decode=True)
                    if isinstance(content, bytes):
                        charset = message.get_content_charset() or 'utf-8'
                        content = content.decode(charset, errors='ignore')
                    
                    content = str(content).strip()
                    
                    if content_type == 'text/plain':
                        body_info['plain_text'] = content
                        body_info['body_type'] = 'plain'
                        body_info['char_count'] = len(content)
                        self.logger.debug(f"Single-part plain text body ({body_info['char_count']} chars)")
                        
                    elif content_type == 'text/html':
                        body_info['html_content'] = content
                        plain_from_html = self.convert_html_to_text(content)
                        if plain_from_html:
                            body_info['plain_text'] = plain_from_html
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
    
    def convert_html_to_text(self, html_content: str) -> str:
        """Convert HTML content to plain text."""
        try:
            # Try to import html2text for better conversion
            try:
                import html2text
                h = html2text.HTML2Text()
                h.ignore_links = True
                h.ignore_images = True
                h.body_width = 0  # No line wrapping
                return h.handle(html_content).strip()
            except ImportError:
                # Fallback to basic HTML tag removal
                import re
                # Remove script and style content
                text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
                # Remove HTML tags
                text = re.sub(r'<[^>]+>', '', text)
                # Convert HTML entities
                import html
                text = html.unescape(text)
                # Clean up whitespace
                text = re.sub(r'\s+', ' ', text).strip()
                return text
        except Exception as e:
            self.logger.debug(f"Error converting HTML to text: {e}")
            return html_content  # Return original if conversion fails
    
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
            'is_multipart': False,
            'is_encrypted': False
        }
        
        try:
            content_type = message.get_content_type()
            content_info['content_type'] = content_type
            content_info['main_type'] = message.get_content_maintype()
            content_info['sub_type'] = message.get_content_subtype()
            content_info['is_multipart'] = message.is_multipart()
            
            # Check for encryption indicators
            if 'encrypted' in content_type.lower() or 'pgp' in content_type.lower():
                content_info['is_encrypted'] = True
                self.logger.warning("Detected encrypted content")
            
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
        """Parse individual attachment with nested email detection."""
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
            'content_disposition': part.get('Content-Disposition')
        }
        
        try:
            # Get payload size
            payload = part.get_payload(decode=False)
            if payload:
                attachment_info['size'] = len(str(payload))
            
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