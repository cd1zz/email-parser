# ============================================================================
# email_parser/extractors/url_extractor.py - Enhanced with document support
# ============================================================================
"""Enhanced URL extraction with document text processing support."""

import logging
import re
import urllib.parse
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field


@dataclass
class UrlExtractionResult:
    """Result of URL extraction from email content including documents."""
    urls: List[Dict[str, Any]] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    url_count: int = 0
    unique_domain_count: int = 0
    shortened_url_count: int = 0
    document_url_count: int = 0  # New: URLs found in documents


class UrlExtractor:
    """Enhanced URL extractor with document text processing support."""
    
    # URL patterns for matching complete URLs with protocols
    URL_PATTERNS = [
        # HTTP/HTTPS URLs (most common)
        r'https?://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?::\d{1,5})?(?:/[^\s<>"{}|\\^`\[\]]*)?',
        
        # FTP URLs
        r'ftp://[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?::\d{1,5})?(?:/[^\s<>"{}|\\^`\[\]]*)?',
        
        # www URLs (commonly appear without http/https in emails)
        r'www\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(?:/[^\s<>"{}|\\^`\[\]]*)?'
    ]
    
    # URL shortener domains for classification
    SHORTENER_DOMAINS = [
        "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly",
        "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in",
        "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id",
        "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at",
        "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im"
    ]
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.URL_PATTERNS]
    
    def extract_urls_from_email(self, email_structure: Dict[str, Any]) -> UrlExtractionResult:
        """Extract URLs from email body content and document attachments."""
        self.logger.info("Starting enhanced URL extraction from email body and documents")
        
        result = UrlExtractionResult()
        seen_urls = set()
        
        # Extract from email body content
        body = email_structure.get('body', {})
        
        # Extract from plain text body
        if body.get('text'):
            self._extract_from_text(body['text'], result, seen_urls, 'body_plain')
        
        # Extract from HTML preview (converted to text)
        if body.get('html'):
            self._extract_from_text(body['html'], result, seen_urls, 'body_html')
        
        # For backward compatibility, also check old field names
        if body.get('plain_text'):
            self._extract_from_text(body['plain_text'], result, seen_urls, 'body_plain')
        
        if body.get('html_preview'):
            self._extract_from_text(body['html_preview'], result, seen_urls, 'body_html')
        
        # NEW: Extract from document attachments
        self._extract_from_documents(email_structure.get('attachments', []), result, seen_urls)
        
        # Extract from nested emails (including their documents)
        self._extract_from_nested_emails(email_structure.get('nested_emails', []), result, seen_urls)
        
        # Finalize results
        result.url_count = len(result.urls)
        result.unique_domain_count = len(result.domains)
        result.shortened_url_count = sum(1 for url in result.urls if url.get('is_shortened', False))
        result.document_url_count = sum(1 for url in result.urls if url.get('source', '').startswith('document_'))
        
        self.logger.info(f"Enhanced URL extraction complete: {result.url_count} URLs, "
                        f"{result.unique_domain_count} unique domains, "
                        f"{result.shortened_url_count} shortened URLs, "
                        f"{result.document_url_count} document URLs")
        
        return result
    
    def _extract_from_documents(self, attachments: List[Dict[str, Any]], 
                               result: UrlExtractionResult, seen_urls: Set[str]) -> None:
        """Extract URLs from document text in attachments."""
        document_count = 0
        
        for i, attachment in enumerate(attachments):
            # Check if attachment has extracted document text
            document_text = attachment.get('document_text')
            if document_text:
                document_count += 1
                source = f"document_{i}_{attachment.get('name', 'unknown')}"
                self.logger.debug(f"Extracting URLs from document: {attachment.get('name', 'unknown')}")
                self._extract_from_text(document_text, result, seen_urls, source)
            
            # Also check for URLs that were already extracted and stored in document_urls
            doc_urls = attachment.get('document_urls', [])
            for url in doc_urls:
                if isinstance(url, str):
                    self._process_url_string(url, result, seen_urls, 
                                           f"document_{i}_{attachment.get('name', 'unknown')}_extracted")
        
        if document_count > 0:
            self.logger.info(f"Processed {document_count} documents for URL extraction")
    
    def _extract_from_text(self, text: str, result: UrlExtractionResult, 
                          seen_urls: Set[str], source: str) -> None:
        """Extract URLs from text content with deduplication."""
        if not text:
            return
        
        self.logger.debug(f"Extracting URLs from {source} ({len(text)} chars)")
        
        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            
            for match in matches:
                self._process_url_string(match, result, seen_urls, source)
    
    def _process_url_string(self, url_string: str, result: UrlExtractionResult, 
                           seen_urls: Set[str], source: str) -> None:
        """Process a single URL string and add to results if not duplicate."""
        url = self._clean_url(url_string)
        if not url:
            return
        
        # Normalize URL for deduplication (case-insensitive, protocol-agnostic)
        normalized_url = self._normalize_for_deduplication(url)
        
        if normalized_url not in seen_urls:
            seen_urls.add(normalized_url)
            
            url_info = self._analyze_url(url, source)
            result.urls.append(url_info)
            
            # Extract domain
            domain = self._extract_domain(url)
            if domain:
                result.domains.add(domain)
            
            self.logger.debug(f"Found new URL: {url} from {source}")
        else:
            self.logger.debug(f"Skipped duplicate URL: {url} from {source}")
    
    def _extract_from_nested_emails(self, nested_emails: List[Dict[str, Any]], 
                                   result: UrlExtractionResult, seen_urls: Set[str]) -> None:
        """Extract URLs from nested emails including their documents."""
        for i, nested_email in enumerate(nested_emails):
            self.logger.debug(f"Extracting URLs from nested email {i}")
            
            # Extract from nested email body
            nested_body = nested_email.get('body', {})
            
            if nested_body.get('text'):
                self._extract_from_text(nested_body['text'], result, seen_urls, f'nested_email_{i}_body_plain')
            
            if nested_body.get('html'):
                self._extract_from_text(nested_body['html'], result, seen_urls, f'nested_email_{i}_body_html')
            
            # For backward compatibility
            if nested_body.get('plain_text'):
                self._extract_from_text(nested_body['plain_text'], result, seen_urls, f'nested_email_{i}_body_plain')
            
            if nested_body.get('html_preview'):
                self._extract_from_text(nested_body['html_preview'], result, seen_urls, f'nested_email_{i}_body_html')
            
            # NEW: Extract from nested email documents
            nested_attachments = nested_email.get('attachments', [])
            if nested_attachments:
                self.logger.debug(f"Processing {len(nested_attachments)} attachments in nested email {i}")
                for j, attachment in enumerate(nested_attachments):
                    document_text = attachment.get('document_text')
                    if document_text:
                        source = f"nested_email_{i}_document_{j}_{attachment.get('name', 'unknown')}"
                        self._extract_from_text(document_text, result, seen_urls, source)
                    
                    # Also process pre-extracted document URLs
                    doc_urls = attachment.get('document_urls', [])
                    for url in doc_urls:
                        if isinstance(url, str):
                            self._process_url_string(url, result, seen_urls, 
                                                   f"nested_email_{i}_document_{j}_extracted")
            
            # Recursively check any further nested emails
            if nested_email.get('nested_emails'):
                self._extract_from_nested_emails(nested_email['nested_emails'], result, seen_urls)
    
    def _clean_url(self, url: str) -> Optional[str]:
        """Clean URL - minimal processing, just cleanup."""
        if not url:
            return None
        
        # Remove trailing punctuation
        while url and url[-1] in '.,;:!?)]}\'"':
            url = url[:-1]
        
        # Remove leading/trailing whitespace
        url = url.strip()
        
        # Only add https:// to www URLs (common case where protocol is omitted)
        if url.startswith('www.') and not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Validate URL structure only for URLs that should have protocols
        if url.startswith(('http://', 'https://', 'ftp://')):
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme and parsed.netloc:
                    return urllib.parse.urlunparse(parsed)
            except Exception as e:
                self.logger.debug(f"Error normalizing URL {url}: {e}")
                return None
        
        return url
    
    def _normalize_for_deduplication(self, url: str) -> str:
        """Normalize URL for deduplication purposes."""
        if not url:
            return url
        
        try:
            # Convert to lowercase for case-insensitive comparison
            normalized = url.lower().strip()
            
            # Handle www vs non-www variants
            if normalized.startswith('www.'):
                # Convert www.example.com to https://www.example.com for parsing
                temp_url = 'https://' + normalized
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
            # Use https as default scheme for comparison (treats http/https as same)
            normalized_url = f"https://{domain}{path}"
            if parsed.query:
                normalized_url += f"?{parsed.query}"
            if parsed.fragment:
                normalized_url += f"#{parsed.fragment}"
            
            return normalized_url
            
        except Exception as e:
            self.logger.debug(f"Error normalizing URL for deduplication {url}: {e}")
            # Fall back to simple lowercase comparison
            return url.lower().strip()
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        try:
            if not url.startswith(('http://', 'https://', 'ftp://')):
                # For www URLs without protocol
                if url.startswith('www.'):
                    temp_url = 'https://' + url
                else:
                    return None
            else:
                temp_url = url
            
            parsed = urllib.parse.urlparse(temp_url)
            domain = parsed.netloc.lower()
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Remove www prefix for domain storage
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain if domain else None
        except Exception as e:
            self.logger.debug(f"Error extracting domain from {url}: {e}")
            return None
    
    def _analyze_url(self, url: str, source: str) -> Dict[str, Any]:
        """Analyze URL properties including source information."""
        domain = self._extract_domain(url)
        
        url_info = {
            'original_url': url,
            'source': source,
            'domain': domain,
            'is_shortened': self._is_url_shortened(url),
            'scheme': None,
            'path_depth': 0,
            'has_query_params': False,
            'has_fragment': False,
            'url_length': len(url),
            'is_document_url': source.startswith('document_') or 'document_' in source  # NEW: Flag document URLs
        }
        
        try:
            # For analysis, temporarily add protocol if needed
            analysis_url = url
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                analysis_url = 'https://' + url
            
            if analysis_url.startswith(('http://', 'https://', 'ftp://')):
                parsed = urllib.parse.urlparse(analysis_url)
                url_info['scheme'] = parsed.scheme
                url_info['has_query_params'] = bool(parsed.query)
                url_info['has_fragment'] = bool(parsed.fragment)
                
                if parsed.path:
                    url_info['path_depth'] = len([p for p in parsed.path.split('/') if p])
            
        except Exception as e:
            self.logger.debug(f"Error parsing URL {url}: {e}")
        
        return url_info
    
    def _is_url_shortened(self, url: str) -> bool:
        """Check if URL is likely shortened."""
        domain = self._extract_domain(url)
        if not domain:
            return False
        
        # Check against known shorteners
        for shortener in self.SHORTENER_DOMAINS:
            if domain == shortener or domain.endswith('.' + shortener):
                return True
        
        # Check for short paths (common in shorteners)
        try:
            analysis_url = url
            if url.startswith('www.') and not url.startswith(('http://', 'https://')):
                analysis_url = 'https://' + url
            
            if analysis_url.startswith(('http://', 'https://', 'ftp://')):
                parsed = urllib.parse.urlparse(analysis_url)
                if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
                    return True
        except Exception:
            pass
        
        return False

    def extract_urls_from_document_text(self, text: str, document_name: str = "unknown") -> List[str]:
        """Standalone method to extract URLs from document text."""
        if not text:
            return []
        
        urls = []
        seen_urls = set()
        
        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            
            for match in matches:
                url = self._clean_url(match)
                if url:
                    normalized_url = self._normalize_for_deduplication(url)
                    if normalized_url not in seen_urls:
                        seen_urls.add(normalized_url)
                        urls.append(url)
        
        self.logger.debug(f"Extracted {len(urls)} URLs from document text: {document_name}")
        return urls