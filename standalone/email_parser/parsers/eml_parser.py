# ============================================================================
# email_parser/parsers/eml_parser.py
# ============================================================================
"""
EML format parser for standard RFC822 email files.

This module provides parsing functionality for EML files, which are the
standard email format used by most email clients and servers.
"""

import email.parser
import email.policy
import logging
from typing import Optional, Tuple
from email.message import Message

from ..interfaces import EmailFormatParser


class EmlFormatParser(EmailFormatParser):
    """Parser for standard EML email files."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.parser = email.parser.Parser(policy=email.policy.default)
        self.bytes_parser = email.parser.BytesParser(policy=email.policy.default)
    
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Check if this is an EML file."""
        # Check for email headers in first 2048 bytes (increased from 512)
        header = data[:2048]
        
        # Common email headers (case-insensitive)
        email_headers = [
            b'Return-Path:', b'Received:', b'From:', b'Message-ID:', b'Date:',
            b'To:', b'Subject:', b'Content-Type:', b'MIME-Version:', 
            b'X-', b'ARC-Seal:', b'ARC-Message-Signature:'  # Added ARC headers
        ]
        
        header_count = 0
        for h in email_headers:
            # Case-insensitive search
            if h.lower() in header.lower():
                header_count += 1
        
        # FIXED: More lenient scoring
        if header_count >= 3:
            confidence = min(0.9, 0.6 + (header_count * 0.1))  # Start at 0.6, increase with more headers
            self.logger.debug(f"EML parser found {header_count} headers, confidence: {confidence}")
            return True, confidence
        elif header_count >= 2:
            # Still try to parse if we have at least 2 email headers
            confidence = 0.7
            self.logger.debug(f"EML parser found {header_count} headers, confidence: {confidence}")
            return True, confidence
        
        # Check filename as secondary indicator
        if filename and filename.lower().endswith(('.eml', '.email')):
            if header_count >= 1:
                # If filename suggests EML and we have at least 1 header, try it
                confidence = 0.8
                self.logger.debug(f"EML parser: filename suggests EML with {header_count} headers, confidence: {confidence}")
                return True, confidence
            else:
                confidence = 0.6
                self.logger.debug(f"EML parser: filename suggests EML but no clear headers, confidence: {confidence}")
                return True, confidence
        
        # FIXED: Lower threshold but still try if it looks like email content
        if header_count >= 1:
            confidence = 0.5  # Reduced from 0.3 to 0.5 to give it a better chance
            self.logger.debug(f"EML parser found {header_count} headers, low confidence: {confidence}")
            return True, confidence
            
        return False, 0.0
    
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse EML data."""
        try:
            return self.bytes_parser.parsebytes(data)
        except Exception as e:
            self.logger.error(f"Failed to parse EML: {e}")
            return None