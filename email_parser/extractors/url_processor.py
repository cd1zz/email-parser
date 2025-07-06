# ============================================================================
# email_parser/extractors/url_processor.py
# ============================================================================
"""URL processing integrating decoder, validator, and expansion."""

import logging
import time
import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from ..url_processing.decoder import UrlDecoder
from ..url_processing.validator import UrlValidator
from ..url_processing.processor import UrlProcessor as BaseUrlProcessor


@dataclass
class ProcessedUrl:
    """Container for processed URL information."""
    original_url: str
    cleaned_url: str
    decoded_url: Optional[str] = None
    expanded_url: Optional[str] = None
    final_url: Optional[str] = None
    domain: Optional[str] = None
    is_shortened: bool = False
    is_image: bool = False
    processing_errors: List[str] = None
    source: str = "unknown"
    
    def __post_init__(self):
        if self.processing_errors is None:
            self.processing_errors = []


class UrlProcessor:
    """URL processor that combines cleaning, decoding, and expansion."""
    
    # URL shortener domains
    URL_SHORTENER_PROVIDERS = [
        "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly",
        "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in",
        "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id",
        "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at",
        "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im"
    ]
    
    # Image file extensions
    IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']
    
    def __init__(self, logger: logging.Logger, enable_expansion: bool = False, 
                 expansion_timeout: int = 5, expansion_delay: float = 0.5):
        self.logger = logger
        self.enable_expansion = enable_expansion
        self.expansion_timeout = expansion_timeout
        self.expansion_delay = expansion_delay
    
    def process_extracted_urls(self, url_extraction_result) -> List[ProcessedUrl]:
        """Process URLs from UrlExtractionResult."""
        self.logger.info(f"Processing {len(url_extraction_result.urls)} extracted URLs")
        
        processed_urls = []
        
        for url_info in url_extraction_result.urls:
            processed_url = self._process_single_url(url_info)
            processed_urls.append(processed_url)
        
        # Expand URLs if enabled
        if self.enable_expansion:
            self._batch_expand_urls(processed_urls)
        
        self.logger.info(f"Completed processing {len(processed_urls)} URLs")
        return processed_urls
    
    def _process_single_url(self, url_info: Dict[str, Any]) -> ProcessedUrl:
        """Process a single URL through the complete pipeline."""
        original_url = url_info['original_url']
        source = url_info.get('source', 'unknown')
        
        self.logger.debug(f"Processing URL: {original_url}")
        
        processed = ProcessedUrl(
            original_url=original_url,
            cleaned_url=original_url,
            source=source,
            is_shortened=url_info.get('is_shortened', False),
            domain=url_info.get('domain')
        )
        
        try:
            # Step 1: Clean the URL
            processed.cleaned_url = self._clean_url(original_url)
            
            # Step 2: Decode wrapped URLs (SafeLinks, Proofpoint, etc.)
            processed.decoded_url = self._decode_wrapped_urls(processed.cleaned_url)
            
            # Step 3: Determine final URL for analysis
            processed.final_url = processed.decoded_url or processed.cleaned_url
            
            # Step 4: Re-analyze the final URL
            processed.domain = self._extract_domain(processed.final_url)
            processed.is_shortened = self._is_url_shortened(processed.final_url)
            processed.is_image = self._is_image_url(processed.final_url)
            
            if processed.decoded_url and processed.decoded_url != processed.cleaned_url:
                self.logger.debug(f"URL decoded: {processed.cleaned_url} -> {processed.decoded_url}")
            
        except Exception as e:
            error_msg = f"Error processing URL {original_url}: {e}"
            self.logger.error(error_msg)
            processed.processing_errors.append(error_msg)
        
        return processed
    
    def _clean_url(self, url: str) -> str:
        """Clean URL by removing trailing punctuation."""
        if not url:
            return url

        while url and url[-1] in '.,;:!?)]}\'"':
            url = url[:-1]

        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                return urllib.parse.urlunparse(parsed)
        except Exception as e:
            self.logger.warning(f"Error normalizing URL {url}: {e}")

        return url
    
    def _decode_wrapped_urls(self, url: str) -> Optional[str]:
        """Decode wrapped URLs (SafeLinks, Proofpoint, etc.)."""
        if not url:
            return url
        
        # Try SafeLinks decoding
        decoded = self._decode_safelinks(url)
        if decoded != url:
            return decoded
        
        # Try Proofpoint decoding
        decoded = self._decode_proofpoint_urls(url)
        if decoded != url:
            return decoded
        
        return url
    
    def _decode_safelinks(self, url: str) -> str:
        """Decode Microsoft SafeLinks URLs."""
        if not url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get('url') or query.get('target')
            if target:
                return target[0]
        except Exception as e:
            self.logger.warning(f"Error decoding SafeLinks URL {url}: {e}")
        return url
    
    def _decode_proofpoint_urls(self, url: str) -> str:
        """Decode Proofpoint URL Defense links."""
        if not url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            if 'u' in query:
                encoded = query['u'][0]
                decoded = urllib.parse.unquote(encoded)
                return decoded
        except Exception as e:
            self.logger.warning(f"Error decoding Proofpoint URL {url}: {e}")
        return url
    
    def _is_url_shortened(self, url: str) -> bool:
        """Check if URL is shortened."""
        if not url:
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()

            if any(domain == shortener or domain.endswith('.' + shortener)
                   for shortener in self.URL_SHORTENER_PROVIDERS):
                return True

            if parsed.path and len(parsed.path) <= 10:
                import re
                if re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
                    return True
        except Exception as e:
            self.logger.warning(f"Error checking if URL is shortened: {e}")

        return False
    
    def _is_image_url(self, url: str) -> bool:
        """Check if URL points to an image."""
        if not url:
            return False

        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            return any(path.endswith(ext) for ext in self.IMAGE_EXTENSIONS)
        except Exception as e:
            self.logger.warning(f"Error checking if URL is an image: {e}")
            return False
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Remove www prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain if domain else None
        except Exception as e:
            self.logger.debug(f"Error extracting domain from {url}: {e}")
            return None
    
    def _batch_expand_urls(self, processed_urls: List[ProcessedUrl]) -> None:
        """Expand shortened URLs in batch."""
        if not self.enable_expansion:
            return
        
        self.logger.info("Starting batch URL expansion")
        
        for processed_url in processed_urls:
            if processed_url.is_shortened and processed_url.final_url:
                try:
                    expanded = self._expand_url(processed_url.final_url)
                    if expanded and expanded != processed_url.final_url:
                        processed_url.expanded_url = expanded
                        # Update domain based on expanded URL
                        processed_url.domain = self._extract_domain(expanded)
                        self.logger.debug(f"Expanded URL: {processed_url.final_url} -> {expanded}")
                    
                    if self.expansion_delay > 0:
                        time.sleep(self.expansion_delay)
                        
                except Exception as e:
                    error_msg = f"Error expanding URL {processed_url.final_url}: {e}"
                    self.logger.warning(error_msg)
                    processed_url.processing_errors.append(error_msg)
    
    def _expand_url(self, url: str) -> Optional[str]:
        """Expand a single shortened URL."""
        try:
            import requests
            
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            session = requests.Session()
            response = session.head(
                url,
                allow_redirects=True,
                timeout=self.expansion_timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return response.url
        except Exception as e:
            self.logger.debug(f"Error expanding URL {url}: {e}")
            return None