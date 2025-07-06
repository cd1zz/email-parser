# ============================================================================
# email_parser/structure_extractor.py
# ============================================================================

import email
import base64
import quopri
from typing import Dict, Any, List, Optional
from email.message import Message
import logging

from .converters import HtmlToTextConverter
from typing import Optional


class EmailStructureExtractor:
    """Extracts comprehensive email structure with attachments and nested emails."""
    
    def __init__(self, logger: logging.Logger, content_analyzer, html_converter: HtmlToTextConverter, url_analyzer=None):
        self.logger = logger
        self.content_analyzer = content_analyzer
        self.html_converter = html_converter
        self.url_analyzer = url_analyzer  


    def extract_structure(self, message: Message, depth: int = 0) -> Dict[str, Any]:
        """Extract comprehensive email structure with nested email support and URL analysis."""
        self.logger.info(f"Extracting email structure at depth {depth}")
        
        structure = {
            'type': 'email',
            'depth': depth,
            'headers': self._extract_headers(message),
            'content_info': self._analyze_content_type(message),
            'body': self._extract_email_body(message),
            'parts': [],
            'attachments': [],
            'nested_emails': [],
            'part_count': 0,
            'attachment_count': 0,
            'nested_email_count': 0,
            'url_analysis': None  # Add URL analysis field
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
                        attachment = self._parse_attachment(part, depth)
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
                if self._detect_nested_email(message):
                    self.logger.info("Single-part message contains nested email")
                    attachment = self._parse_attachment(message, depth)
                    structure['attachments'].append(attachment)
                    if attachment.get('is_nested_email'):
                        structure['nested_emails'].append(attachment['nested_email'])
                        structure['nested_email_count'] += 1
                    structure['attachment_count'] += 1
            
            # Add URL analysis if analyzer is available (only at top level to avoid recursion)
            if self.url_analyzer and depth == 0:
                try:
                    self.logger.info("Performing URL analysis on email structure")
                    url_analysis = self.url_analyzer.analyze_email_urls(structure)
                    structure['url_analysis'] = self.url_analyzer.get_serializable_analysis(url_analysis)
                    self.logger.info(f"URL analysis complete: {structure['url_analysis']['summary']}")
                except Exception as e:
                    self.logger.error(f"Error during URL analysis: {e}")
                    structure['url_analysis'] = {'error': str(e)}
            
        except Exception as e:
            self.logger.error(f"Error extracting email structure: {e}")
            structure['parsing_error'] = str(e)
        
        self.logger.info(f"Completed structure extraction at depth {depth}: "
                        f"{structure['part_count']} parts, "
                        f"{structure['attachment_count']} attachments, "
                        f"{structure['nested_email_count']} nested emails")
        
        return structure

    def _extract_headers(self, message: Message) -> Dict[str, Any]:
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
    
    def _analyze_content_type(self, message: Message) -> Dict[str, Any]:
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
    
    def _extract_email_body(self, message: Message) -> Dict[str, Any]:
        """Extract email body content with HTML conversion."""
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
                                    plain_from_html = self.html_converter.convert(body_info['html_content'])
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
                        elif content_type == 'text/html':
                            body_info['html_content'] = content
                            plain_from_html = self.html_converter.convert(content)
                            if plain_from_html and plain_from_html.strip():
                                body_info['plain_text'] = plain_from_html.strip()
                                body_info['body_type'] = 'html_converted'
                                body_info['char_count'] = len(body_info['plain_text'])
                        else:
                            body_info['plain_text'] = content
                            body_info['body_type'] = 'unknown'
                            body_info['char_count'] = len(content)
                except Exception as e:
                    self.logger.debug(f"Error extracting single-part content: {e}")
            
            # Truncate HTML preview only (keep first 50 chars for preview)

            if body_info['html_content'] and len(body_info['html_content']) > 50:
                body_info['html_preview'] = body_info['html_content'][:50] + "... [HTML CONTENT TRUNCATED FOR BREVITY]"
                body_info['truncated'] = True
                del body_info['html_content']
            elif body_info['html_content']:
                body_info['html_preview'] = body_info['html_content'] + " [HTML CONTENT DETECTED]"
                del body_info['html_content']

            
            self.logger.info(f"Body extraction complete: type={body_info['body_type']}, "
                           f"chars={body_info['char_count']}, truncated={body_info['truncated']}")
            
        except Exception as e:
            self.logger.error(f"Error extracting email body: {e}")
            body_info['error'] = str(e)
        
        return body_info
    
    def _extract_text_content(self, part: Message) -> Optional[str]:
        """Extract and decode text content from a message part."""
        try:
            payload = part.get_payload(decode=True)
            
            if payload is None:
                payload = part.get_payload(decode=False)
                if isinstance(payload, list):
                    return None
            
            if isinstance(payload, bytes):
                charset = part.get_content_charset() or 'utf-8'
                
                encoding = part.get('Content-Transfer-Encoding', '').lower()
                
                if encoding == 'quoted-printable':
                    try:
                        payload = quopri.decodestring(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual quoted-printable decode failed: {e}")
                elif encoding == 'base64':
                    try:
                        payload = base64.b64decode(payload)
                    except Exception as e:
                        self.logger.debug(f"Manual base64 decode failed: {e}")
                
                try:
                    content = payload.decode(charset, errors='ignore')
                except (UnicodeDecodeError, LookupError):
                    for fallback_charset in ['utf-8', 'latin1', 'cp1252']:
                        try:
                            content = payload.decode(fallback_charset, errors='ignore')
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        content = payload.decode('utf-8', errors='replace')
                        
            elif isinstance(payload, str):
                content = payload
            else:
                content = str(payload)
            
            return content
            
        except Exception as e:
            self.logger.error(f"Error extracting text content: {e}")
            return None
    
    def _detect_nested_email(self, part: Message) -> bool:
        """Detect if a part contains a nested email."""
        content_type = part.get_content_type()
        filename = part.get_filename()
        
        self.logger.debug(f"Checking for nested email - Content-Type: {content_type}, Filename: {filename}")
        
        # Check content type
        if content_type in ['message/rfc822', 'message/partial', 'message/external-body']:
            self.logger.info(f"Detected nested email by content type: {content_type}")
            return True
        
        # Check filename
        if filename:
            email_extensions = ['.eml', '.msg', '.email']
            for ext in email_extensions:
                if filename.lower().endswith(ext):
                    self.logger.info(f"Detected nested email by filename: {filename}")
                    return True
        
        # Check content for email headers
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                try:
                    payload_str = payload.decode('utf-8')
                except UnicodeDecodeError:
                    payload_str = payload.decode('latin-1', errors='ignore')
            else:
                payload_str = str(payload)
            
            email_indicators = ['From:', 'To:', 'Subject:', 'Date:', 'Message-ID:', 'Received:', 'Return-Path:']
            header_matches = {}
            
            for indicator in email_indicators:
                if indicator in payload_str[:2000]:
                    header_matches[indicator] = payload_str.find(indicator)
                    
            header_count = len(header_matches)
            self.logger.debug(f"Found email headers: {list(header_matches.keys())} (count: {header_count})")
            
            if header_count >= 3:
                self.logger.info(f"Detected nested email by header pattern analysis ({header_count} headers found)")
                return True
                
        except Exception as e:
            self.logger.debug(f"Error in nested email detection: {e}")
        
        return False
    
    def _parse_attachment(self, part: Message, depth: int = 0) -> Dict[str, Any]:
        """Parse individual attachment with content analysis."""
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
            payload = part.get_payload(decode=True)
            if payload:
                attachment_info['size'] = len(payload)
                
                # Content analysis
                self.logger.debug(f"Performing content analysis for attachment: {attachment_info['filename']}")
                content_analysis = self.content_analyzer.analyze_content(
                    payload, 
                    attachment_info['filename'], 
                    attachment_info['content_type']
                )
                
                attachment_info['content_analysis'] = content_analysis.__dict__
                
                # Update content type if analysis detected something different
                if content_analysis.detected_type and content_analysis.confidence > 0.7:
                    if content_analysis.mime_type != attachment_info['content_type']:
                        self.logger.info(f"Content analysis override: {attachment_info['content_type']} -> {content_analysis.mime_type}")
                        attachment_info['fingerprinted_content_type'] = content_analysis.mime_type
            
            # Check for nested email
            if self._detect_nested_email(part):
                attachment_info['is_nested_email'] = True
                self.logger.info("Processing nested email attachment")
                
                try:
                    if part.get_content_type() == 'message/rfc822':
                        nested_payload = part.get_payload(0) if part.get_payload() else None
                    else:
                        nested_payload = part.get_payload(decode=True)
                        if isinstance(nested_payload, bytes):
                            # Parse the nested email
                            from email.parser import BytesParser
                            parser = BytesParser(policy=email.policy.default)
                            nested_message = parser.parsebytes(nested_payload)
                        else:
                            from email.parser import Parser
                            parser = Parser(policy=email.policy.default)
                            nested_message = parser.parsestr(str(nested_payload))
                        nested_payload = nested_message
                    
                    if nested_payload:
                        # Recursively parse the nested email
                        attachment_info['nested_email'] = self.extract_structure(nested_payload, depth + 1)
                        self.logger.info(f"Successfully parsed nested email at depth {depth + 1}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to parse nested email: {e}")
                    attachment_info['nested_email_error'] = str(e)
            
        except Exception as e:
            self.logger.error(f"Error parsing attachment: {e}")
            attachment_info['error'] = str(e)
        
        return attachment_info