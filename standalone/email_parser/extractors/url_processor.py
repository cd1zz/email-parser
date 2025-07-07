# ============================================================================
# email_parser/extractors/url_processor.py - FIXED VERSION
# ============================================================================
"""Conservative URL processing - minimal transformation, preserve original URLs."""

import logging
import time
import urllib.parse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ProcessedUrl:
    """Container for processed URL information - minimal processing."""
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
    """Conservative URL processor - minimal transformation, preserve original URLs."""
    
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
    
    def process_extracted_urls(self, url_extraction_result) -> Tuple[List[ProcessedUrl], List[str]]:
        """Process URLs and return both detailed info and final URL list."""
        self.logger.info(f"Processing {len(url_extraction_result.urls)} extracted URLs (conservative mode)")
        
        processed_urls = []
        seen_final_urls = set()
        
        for url_info in url_extraction_result.urls:
            processed_url = self._process_single_url(url_info)
            
            # Deduplicate based on final processed URL
            final_url_normalized = self._normalize_for_deduplication(processed_url.final_url)
            
            if final_url_normalized not in seen_final_urls:
                seen_final_urls.add(final_url_normalized)
                processed_urls.append(processed_url)
                self.logger.debug(f"Added processed URL: {processed_url.final_url}")
            else:
                self.logger.debug(f"Skipped duplicate processed URL: {processed_url.final_url}")
        
        # Expand URLs if enabled
        if self.enable_expansion:
            self._batch_expand_urls(processed_urls)
        
        # Generate final URLs list (decoded/expanded destinations only)
        final_urls_list = self.get_final_urls_list(processed_urls)
        
        self.logger.info(f"Completed processing {len(processed_urls)} unique URLs, "
                        f"final destinations: {len(final_urls_list)}")
        
        return processed_urls, final_urls_list
    
    def get_final_urls_list(self, processed_urls: List[ProcessedUrl]) -> List[str]:
        """Get list of final destination URLs (decoded/expanded URLs, not wrappers)."""
        final_urls = []
        
        for processed_url in processed_urls:
            # Priority order for final URL:
            # 1. Expanded URL (if it was shortened and we expanded it)
            # 2. Decoded URL (if it was wrapped by security service)  
            # 3. Final URL (cleaned original)
            
            if processed_url.expanded_url:
                # Use expanded URL for shortened links (bit.ly, t.co, etc.)
                final_url = processed_url.expanded_url
                self.logger.debug(f"Using expanded URL: {final_url} (from {processed_url.original_url})")
            elif processed_url.decoded_url:
                # Use decoded URL for wrapped links (SafeLinks, Proofpoint, etc.)
                final_url = processed_url.decoded_url
                self.logger.debug(f"Using decoded URL: {final_url} (from {processed_url.original_url})")
            else:
                # Use final URL (cleaned original) for regular URLs
                final_url = processed_url.final_url
                self.logger.debug(f"Using original URL: {final_url}")
            
            if final_url and final_url not in final_urls:
                final_urls.append(final_url)
        
        self.logger.info(f"Generated {len(final_urls)} final destination URLs")
        return final_urls
    
    def _process_single_url(self, url_info: Dict[str, Any]) -> ProcessedUrl:
        """Process a single URL with minimal transformation."""
        original_url = url_info['original_url']
        source = url_info.get('source', 'unknown')
        
        self.logger.debug(f"Processing URL: {original_url}")
        
        processed = ProcessedUrl(
            original_url=original_url,
            cleaned_url=original_url,  # Start with original
            source=source,
            is_shortened=url_info.get('is_shortened', False),
            domain=url_info.get('domain')
        )
        
        try:
            # Step 1: Minimal cleaning (just remove trailing punctuation)
            processed.cleaned_url = self._clean_url_minimal(original_url)
            
            # Step 2: Decode wrapped URLs (SafeLinks, Proofpoint, etc.)
            processed.decoded_url = self._decode_wrapped_urls(processed.cleaned_url)
            
            # Step 3: Determine final URL for analysis
            processed.final_url = processed.decoded_url or processed.cleaned_url
            
            # Step 4: Extract metadata from final URL
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
    
    def _clean_url_minimal(self, url: str) -> str:
        """Minimal URL cleaning - just remove trailing punctuation."""
        if not url:
            return url

        # Remove trailing punctuation
        while url and url[-1] in '.,;:!?)]}\'"':
            url = url[:-1]

        # Remove leading/trailing whitespace
        return url.strip()
    
    def _decode_wrapped_urls(self, url: str) -> Optional[str]:
        """Decode wrapped URLs (SafeLinks, Proofpoint, etc.)."""
        if not url:
            return None
        
        # Try SafeLinks decoding
        decoded = self._decode_safelinks(url)
        if decoded != url:
            return decoded
        
        # Try Proofpoint decoding
        decoded = self._decode_proofpoint_urls(url)
        if decoded != url:
            return decoded
        
        # Try other common wrappers
        decoded = self._decode_other_wrappers(url)
        if decoded != url:
            return decoded
        
        return None
    
    def _decode_safelinks(self, url: str) -> str:
        """Decode Microsoft SafeLinks URLs."""
        if not url or 'safelinks.protection.outlook.com' not in url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            target = query.get('url') or query.get('target')
            if target:
                decoded = urllib.parse.unquote(target[0])
                self.logger.debug(f"SafeLinks decoded: {url} -> {decoded}")
                return decoded
        except Exception as e:
            self.logger.warning(f"Error decoding SafeLinks URL {url}: {e}")
        return url
    
    def _decode_proofpoint_urls(self, url: str) -> str:
        """Decode Proofpoint URL Defense links (multiple variants)."""
        if not url or 'urldefense.proofpoint.com' not in url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            
            # Version 2 format: ?u=encoded_url
            if 'u' in query:
                encoded = query['u'][0]
                # Proofpoint v2 uses custom encoding
                decoded = encoded.replace('-', '%').replace('_', '/')
                decoded = urllib.parse.unquote(decoded)
                self.logger.debug(f"Proofpoint decoded: {url} -> {decoded}")
                return decoded
                
        except Exception as e:
            self.logger.warning(f"Error decoding Proofpoint URL {url}: {e}")
        return url
    
    def _decode_other_wrappers(self, url: str) -> str:
        """Decode other common URL wrappers."""
        common_wrappers = [
            ('protection.office.com', ['url']),
            ('clicktime.symantec.com', ['u']),
            ('secure-web.cisco.com', ['u']),
        ]
        
        for wrapper_domain, param_names in common_wrappers:
            if wrapper_domain in url:
                try:
                    parsed = urllib.parse.urlparse(url)
                    query = urllib.parse.parse_qs(parsed.query)
                    for param_name in param_names:
                        if param_name in query:
                            decoded = urllib.parse.unquote(query[param_name][0])
                            self.logger.debug(f"{wrapper_domain} decoded: {url} -> {decoded}")
                            return decoded
                except Exception as e:
                    self.logger.debug(f"Error decoding {wrapper_domain} URL: {e}")
        
        return url
    
    def _normalize_for_deduplication(self, url: str) -> str:
        """Normalize URL for deduplication purposes."""
        if not url:
            return ""
        
        try:
            # Convert to lowercase for case-insensitive comparison
            normalized = url.lower().strip()
            
            # Handle www vs non-www variants
            if normalized.startswith('www.'):
                # Convert www.example.com to http://www.example.com for parsing
                temp_url = 'http://' + normalized
            elif normalized.startswith(('http://', 'https://', 'ftp://')):
                temp_url = normalized
            else:
                return normalized  # Return as-is if we can't parse it
            
            # Parse the URL
            parsed = urllib.parse.urlparse(temp_url)
            
            # Normalize the domain (remove www, convert to lowercase)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove default ports
            if ':80' in domain and parsed.scheme == 'http':
                domain = domain.replace(':80', '')
            elif ':443' in domain and parsed.scheme == 'https':
                domain = domain.replace(':443', '')
            
            # Normalize path (remove trailing slash if it's just "/")
            path = parsed.path
            if path == '/':
                path = ''
            
            # Rebuild normalized URL for comparison
            # Use http as default scheme for comparison (treats http/https as same)
            normalized_url = f"http://{domain}{path}"
            if parsed.query:
                normalized_url += f"?{parsed.query}"
            if parsed.fragment:
                normalized_url += f"#{parsed.fragment}"
            
            return normalized_url
            
        except Exception as e:
            self.logger.debug(f"Error normalizing URL for deduplication {url}: {e}")
            # Fall back to simple lowercase comparison
            return url.lower().strip()
    
    def _is_url_shortened(self, url: str) -> bool:
        """Check if URL is shortened."""
        if not url:
            return False

        try:
            # For analysis, add protocol if needed
            analysis_url = url
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                analysis_url = 'http://' + url
            elif not url.startswith(('http://', 'https://', 'ftp://')):
                return False  # Can't analyze URLs without protocol
            
            parsed = urllib.parse.urlparse(analysis_url)
            domain = parsed.netloc.lower()

            # Remove www prefix for comparison
            if domain.startswith('www.'):
                domain = domain[4:]

            if any(domain == shortener or domain.endswith('.' + shortener)
                   for shortener in self.URL_SHORTENER_PROVIDERS):
                return True

            # Additional heuristics for unknown shorteners
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
            # For analysis, add protocol if needed
            analysis_url = url
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                analysis_url = 'http://' + url
            elif not url.startswith(('http://', 'https://', 'ftp://')):
                return False  # Can't analyze URLs without protocol
            
            parsed = urllib.parse.urlparse(analysis_url)
            path = parsed.path.lower()
            return any(path.endswith(ext) for ext in self.IMAGE_EXTENSIONS)
        except Exception as e:
            self.logger.warning(f"Error checking if URL is an image: {e}")
            return False
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            # For analysis, add protocol if needed
            analysis_url = url
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                analysis_url = 'http://' + url
            elif not url.startswith(('http://', 'https://', 'ftp://')):
                return None  # Can't extract domain from URLs without protocol
            
            parsed = urllib.parse.urlparse(analysis_url)
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
            
            # Only expand URLs that already have protocols
            if not url.startswith(('http://', 'https://')):
                if url.startswith('www.'):
                    url = 'http://' + url
                else:
                    return None  # Don't expand bare domains

            session = requests.Session()
            response = session.head(
                url,
                allow_redirects=True,
                timeout=self.expansion_timeout,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            return response.url
        except Exception as e:
            self.logger.debug(f"Error expanding URL {url}: {e}")
            return None