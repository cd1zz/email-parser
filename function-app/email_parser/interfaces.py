# ============================================================================
# email_parser/interfaces.py
# ============================================================================

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, Tuple
from email.message import Message


class EmailFormatParser(ABC):
    """Interface for format-specific email parsers."""
    
    @abstractmethod
    def can_parse(self, data: bytes, filename: Optional[str] = None) -> Tuple[bool, float]:
        """Check if this parser can handle the data. Returns (can_parse, confidence)."""
        pass
    
    @abstractmethod
    def parse(self, data: bytes, filename: Optional[str] = None) -> Optional[Message]:
        """Parse the data into an email Message object."""
        pass


class ContentNormalizer(ABC):
    """Interface for content normalization strategies."""
    
    @abstractmethod
    def normalize(self, content: Union[str, bytes, Any]) -> Optional[str]:
        """Normalize content to a proper string format."""
        pass
