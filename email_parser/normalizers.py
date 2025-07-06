# ============================================================================
# email_parser/normalizers.py
# ============================================================================

import logging
from typing import Union, Optional, Any


class BaseContentNormalizer(ContentNormalizer):
    """Base normalizer with common functionality."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def _is_reasonable_text(self, text: str) -> bool:
        """Check if decoded text looks reasonable (not garbage)."""
        if not text or len(text) < 10:
            return False
        
        printable_chars = sum(1 for c in text[:200] if c.isprintable() or c.isspace())
        ratio = printable_chars / min(len(text), 200)
        
        has_html_tags = '<' in text and '>' in text
        has_common_words = any(word in text.lower() for word in ['the', 'and', 'html', 'body', 'div', 'span'])
        
        return ratio > 0.7 or (has_html_tags and has_common_words)


class Utf16ContentNormalizer(BaseContentNormalizer):
    """Specialized normalizer for UTF-16 content (common in MSG files)."""
    
    def normalize(self, content: Union[str, bytes, Any]) -> Optional[str]:
        """Normalize UTF-16 content with enhanced Unicode handling."""
        if content is None:
            return None
        
        try:
            self.logger.debug(f"Normalizing content, type: {type(content)}")
            
            if isinstance(content, str):
                return self._handle_string_content(content)
            elif isinstance(content, bytes):
                return self._handle_bytes_content(content)
            else:
                return self._handle_other_content(content)
                
        except Exception as e:
            self.logger.error(f"Error normalizing content: {e}")
            return str(content) if content is not None else None
    
    def _handle_string_content(self, content: str) -> str:
        """Handle string content that might have encoding issues."""
        if len(content) > 10:
            sample = content[:20]
            if any(ord(c) > 127 and ord(c) < 65536 for c in sample if len(sample) > 5):
                self.logger.debug("String content appears to contain improperly decoded Unicode")
                try:
                    byte_content = content.encode('latin-1')
                    if len(byte_content) % 2 == 0:
                        decoded = byte_content.decode('utf-16le', errors='ignore')
                        if self._is_reasonable_text(decoded):
                            self.logger.info("Successfully re-decoded as UTF-16LE")
                            return decoded
                except Exception as e:
                    self.logger.debug(f"UTF-16 re-decoding failed: {e}")
        return content
    
    def _handle_bytes_content(self, content: bytes) -> str:
        """Handle bytes content with UTF-16 detection."""
        self.logger.debug(f"Content is bytes, length: {len(content)}")
        
        if len(content) >= 4:
            # Check for UTF-16 BOM
            if content[:2] == b'\xff\xfe' or content[:2] == b'\xfe\xff':
                self.logger.debug("Detected UTF-16 BOM")
                try:
                    return content.decode('utf-16')
                except UnicodeDecodeError:
                    pass
            
            # Check for UTF-16LE pattern
            if len(content) >= 20:
                null_pattern = sum(1 for i in range(1, min(20, len(content)), 2) if content[i] == 0)
                if null_pattern > 5:
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
        
        result = content.decode('utf-8', errors='replace')
        self.logger.warning("Used fallback decoding with errors='replace'")
        return result
    
    def _handle_other_content(self, content: Any) -> str:
        """Handle other content types."""
        content_str = str(content)
        self.logger.debug(f"Converted {type(content)} to string")
        
        # Check if it looks like a bytes representation string
        if content_str.startswith("b'") and content_str.endswith("'"):
            try:
                inner_content = content_str[2:-1]
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