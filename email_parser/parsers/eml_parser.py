# ============================================================================
# email_parser/parsers/eml_parser.py
# ============================================================================

import email.parser
import email.policy


class EmlFormatParser(EmailFormatParser):
    """Parser for standard EML email files."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.parser = email.parser.Parser(policy=email.policy.default)
        self.bytes_parser = email.parser.BytesParser(policy=email.policy.default)
    
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Check if this is an EML file."""
        # Check for email headers in first 512 bytes
        header = data[:512]
        email_headers = [b'Return-Path:', b'Received:', b'From:', b'Message-ID:', b'Date:']
        
        header_count = sum(1 for h in email_headers if h in header)
        if header_count >= 2:
            return True, 0.8
        
        # Check filename
        if filename and filename.lower().endswith(('.eml', '.email')):
            return True, 0.6
        
        return False, 0.3  # Default fallback
    
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse EML data."""
        try:
            return self.bytes_parser.parsebytes(data)
        except Exception as e:
            self.logger.error(f"Failed to parse EML: {e}")
            return None
