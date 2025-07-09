# ============================================================================
# email_parser/converters.py - FIXED: Clean invisible Unicode characters
# ============================================================================

import html
import re
import logging
import unicodedata
from typing import Optional


class HtmlToTextConverter:
    """Converts HTML content to plain text with better Unicode handling and cleanup."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
    
    def convert(self, html_content: str) -> str:
        """Convert HTML content to plain text with Unicode cleanup."""
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
                
                # CRITICAL FIX: Clean up Unicode control characters after conversion
                cleaned_result = self._clean_unicode_control_characters(result)
                
                self.logger.debug("html2text conversion successful with Unicode cleanup")
                return cleaned_result
                
            except ImportError:
                self.logger.debug("html2text not available, using fallback conversion")
                fallback_result = self._fallback_conversion(html_content)
                
                # CRITICAL FIX: Clean up Unicode control characters in fallback too
                cleaned_fallback = self._clean_unicode_control_characters(fallback_result)
                return cleaned_fallback
                
        except Exception as e:
            self.logger.error(f"Error converting HTML to text: {e}")
            return f"[HTML conversion failed: {e}]"
    
    def _clean_unicode_control_characters(self, text: str) -> str:
        """
        CRITICAL FIX: Remove invisible Unicode control characters that clutter the output.
        
        These are commonly used in HTML emails for layout but are meaningless in plain text.
        """
        if not text:
            return text
        
        # Map of problematic Unicode characters to their replacements
        unicode_cleanup_map = {
            # Invisible formatting characters
            '\u034f': '',      # Combining Grapheme Joiner (invisible)
            '\u200b': '',      # Zero Width Space
            '\u200c': '',      # Zero Width Non-Joiner  
            '\u200d': '',      # Zero Width Joiner
            '\u200e': '',      # Left-to-Right Mark
            '\u200f': '',      # Right-to-Left Mark
            '\u2060': '',      # Word Joiner
            '\ufeff': '',      # Zero Width No-Break Space (BOM)
            
            # Soft hyphens (invisible line break hints)
            '\u00ad': '',      # Soft Hyphen
            
            # Replace non-breaking spaces with regular spaces
            '\u00a0': ' ',     # Non-Breaking Space (&nbsp;)
            '\u2007': ' ',     # Figure Space
            '\u2009': ' ',     # Thin Space
            '\u200a': ' ',     # Hair Space
            '\u202f': ' ',     # Narrow No-Break Space
            
            # Other problematic characters
            '\u2028': '\n',    # Line Separator -> newline
            '\u2029': '\n\n',  # Paragraph Separator -> double newline
        }
        
        # Apply character replacements
        cleaned_text = text
        removed_chars = []
        
        for unicode_char, replacement in unicode_cleanup_map.items():
            if unicode_char in cleaned_text:
                char_count = cleaned_text.count(unicode_char)
                cleaned_text = cleaned_text.replace(unicode_char, replacement)
                if char_count > 0:
                    char_name = unicodedata.name(unicode_char, f'U+{ord(unicode_char):04X}')
                    removed_chars.append(f"{char_name} ({char_count}x)")
        
        # Log what we cleaned up
        if removed_chars:
            self.logger.info(f"Cleaned Unicode control characters: {', '.join(removed_chars)}")
        
        # Additional cleanup patterns
        cleaned_text = self._additional_text_cleanup(cleaned_text)
        
        return cleaned_text
    
    def _additional_text_cleanup(self, text: str) -> str:
        """Additional text cleanup patterns."""
        
        # Remove excessive whitespace patterns that often result from table layouts
        # Pattern: |  |  |  | becomes just |
        text = re.sub(r'\|\s*\|\s*\|\s*\|', '|', text)
        
        # Clean up excessive table markup patterns
        # Pattern: multiple --- lines become single ---
        text = re.sub(r'(---\s*\n){2,}', '---\n', text)
        
        # Clean up patterns like |  |  with just spaces
        text = re.sub(r'\|\s{2,}\|', '| |', text)
        
        # Remove lines that are just | and whitespace
        lines = text.split('\n')
        cleaned_lines = []
        
        for line in lines:
            stripped = line.strip()
            # Skip lines that are just pipes and spaces/dashes
            if not stripped or stripped in ['|', '---', '| |', '||']:
                continue
            # Skip lines that are just repetitive pipe/space patterns
            if re.match(r'^[\|\s\-]+$', stripped) and len(set(stripped.replace(' ', ''))) <= 2:
                continue
            cleaned_lines.append(line)
        
        # Rejoin and clean up excessive newlines
        cleaned_text = '\n'.join(cleaned_lines)
        
        # Replace multiple consecutive newlines with at most 2
        cleaned_text = re.sub(r'\n{3,}', '\n\n', cleaned_text)
        
        # Clean up spaces around newlines
        cleaned_text = re.sub(r' +\n', '\n', cleaned_text)
        cleaned_text = re.sub(r'\n +', '\n', cleaned_text)
        
        return cleaned_text.strip()
    
    def _fallback_conversion(self, html_content: str) -> str:
        """Fallback HTML to text conversion with better cleanup."""
        # Remove script and style content
        text = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        
        # Convert common HTML elements to text equivalents
        # Tables - try to preserve some structure
        text = re.sub(r'<tr[^>]*>', '\n', text, flags=re.IGNORECASE)
        text = re.sub(r'<td[^>]*>', ' | ', text, flags=re.IGNORECASE)
        text = re.sub(r'<th[^>]*>', ' | ', text, flags=re.IGNORECASE)
        
        # Lists
        text = re.sub(r'<li[^>]*>', '\n• ', text, flags=re.IGNORECASE)
        
        # Block elements - add newlines
        block_elements = ['div', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6']
        for element in block_elements:
            text = re.sub(f'<{element}[^>]*>', '\n', text, flags=re.IGNORECASE)
            text = re.sub(f'</{element}>', '\n', text, flags=re.IGNORECASE)
        
        # Remove remaining HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        
        # Convert HTML entities
        text = html.unescape(text)
        
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'\n\s*\n', '\n\n', text)
        
        self.logger.debug("Fallback conversion successful")
        return text.strip()


def sanitize_text_content(text: str, logger: logging.Logger = None) -> str:
    """
    Standalone function to sanitize text content by removing invisible Unicode control characters.
    
    This should be used for ALL text content extracted from emails and documents to ensure
    clean, readable output without hidden characters that can clutter analysis.
    
    Args:
        text: The text content to sanitize
        logger: Optional logger for reporting what was cleaned
        
    Returns:
        Sanitized text with invisible Unicode characters removed
    """
    if not text:
        return text
    
    # Map of problematic Unicode characters to their replacements
    unicode_cleanup_map = {
        # Invisible formatting characters
        '\u034f': '',      # Combining Grapheme Joiner (invisible)
        '\u200b': '',      # Zero Width Space
        '\u200c': '',      # Zero Width Non-Joiner  
        '\u200d': '',      # Zero Width Joiner
        '\u200e': '',      # Left-to-Right Mark
        '\u200f': '',      # Right-to-Left Mark
        '\u2060': '',      # Word Joiner
        '\ufeff': '',      # Zero Width No-Break Space (BOM)
        
        # Soft hyphens (invisible line break hints)
        '\u00ad': '',      # Soft Hyphen
        
        # Replace non-breaking spaces with regular spaces
        '\u00a0': ' ',     # Non-Breaking Space (&nbsp;)
        '\u2007': ' ',     # Figure Space
        '\u2009': ' ',     # Thin Space
        '\u200a': ' ',     # Hair Space
        '\u202f': ' ',     # Narrow No-Break Space
        
        # Other problematic characters
        '\u2028': '\n',    # Line Separator -> newline
        '\u2029': '\n\n',  # Paragraph Separator -> double newline
    }
    
    # Apply character replacements
    cleaned_text = text
    removed_chars = []
    
    for unicode_char, replacement in unicode_cleanup_map.items():
        if unicode_char in cleaned_text:
            char_count = cleaned_text.count(unicode_char)
            cleaned_text = cleaned_text.replace(unicode_char, replacement)
            if char_count > 0:
                char_name = unicodedata.name(unicode_char, f'U+{ord(unicode_char):04X}')
                removed_chars.append(f"{char_name} ({char_count}x)")
    
    # Log what we cleaned up if logger provided
    if removed_chars and logger:
        logger.info(f"Sanitized Unicode control characters: {', '.join(removed_chars)}")
    
    return cleaned_text