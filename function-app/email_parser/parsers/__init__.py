"""
Email format parsers for different email file types.

This module contains format-specific parsers for various email formats:
- EML: Standard RFC822 email format
- MSG: Microsoft Outlook email format  
- MBOX: Unix mailbox format
- Proofpoint: Enhanced email structure extractor with Proofpoint support
"""

from typing import TYPE_CHECKING

from .eml_parser import EmlFormatParser
from .msg_parser import MsgFormatParser
from .mbox_parser import MboxFormatParser
from .proofpoint_detector import EnhancedEmailStructureExtractor

if TYPE_CHECKING:
    from ..interfaces import EmailFormatParser

__all__ = [
    'EmlFormatParser',
    'MsgFormatParser', 
    'MboxFormatParser',
    'EnhancedEmailStructureExtractor'
]