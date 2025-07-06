# ============================================================================
# email_parser/converters.py
# ============================================================================

import html
import re
import logging
from typing import Optional


class HtmlToTextConverter:
    """Converts HTML content to plain text with better Unicode handling."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def convert(self, html_content: str) -> str:
        """Convert HTML content to plain text."""
        try:
            self.logger.debug(f"Converting HTML to text, input length: {len(html_content) if html_content else 0}")
            
            if not html_content:
                return ""
            
            # Try html2text for better conversion
            try:
                import html2text
                h = html2text.HTML2Text()
                h.ignore_links = True
                h.ignore_images = True
                h.body_width = 0
                h.unicode_snob = True
                result = h.handle(html_content).strip()
                self.logger.debug("html2text conversion successful")
                return result
            except ImportError:
                self.logger.debug("html2text not available, using fallback conversion")
                return self._fallback_conversion(html_content)
                
        except Exception as e:
            self.logger.error(f"Error converting HTML to text: {e}")
            return f"[HTML conversion failed: {e}]"
    
    def _fallback_conversion(self, html_content: str) -> str:
        """Fallback HTML to text conversion."""
        # Remove script and style content
        text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Convert HTML entities
        text = html.unescape(text)
        
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        self.logger.debug("Fallback conversion successful")
        return text
