# ============================================================================
# email_parser/parsers/mbox_parser.py
# ============================================================================

import email.parser
import email.policy
import logging
from typing import Optional, Tuple
from email.message import Message

from ..interfaces import EmailFormatParser


class MboxFormatParser(EmailFormatParser):
    """Parser for MBOX email files."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.parser = email.parser.Parser(policy=email.policy.default)
    
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Check if this is an MBOX file."""
        # Check for mbox format
        if data.startswith(b'From '):
            return True, 0.9
        
        # Check filename
        if filename and filename.lower().endswith('.mbox'):
            return True, 0.7
        
        return False, 0.0
    
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse MBOX data (extract first message)."""
        try:
            content = data.decode('utf-8', errors='replace')
            
            if content.startswith('From '):
                # Find end of first message
                next_from = content.find('\nFrom ', 1)
                if next_from > 0:
                    first_message = content[content.find('\n', 1):next_from]
                else:
                    first_message = content[content.find('\n', 1):]
                
                return self.parser.parsestr(first_message)
        except Exception as e:
            self.logger.error(f"Failed to parse MBOX: {e}")
            return None