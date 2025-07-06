# ============================================================================
# email_parser/extractors/url_extractor.py
# ============================================================================
"""URL extraction from email content."""

import logging
import re
import urllib.parse
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field


@dataclass
class UrlExtractionResult:
    """Result of URL extraction from email content."""
    urls: List[Dict[str, Any]] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    url_count: int = 0
    unique_domain_count: int = 0
    shortened_url_count: int = 0


class UrlExtractor:
    """Extract URLs from email content."""
    
    # URL regex patterns
    URL_PATTERNS = [
        # Standard HTTP/HTTPS URLs
        r'https?://[^\s<>"{}|\\^`\[\]]+',
        # URLs without protocol
        r'(?:www\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}(?:/[^\s<>"{}|\\^`\[\]]*)?',
        # Email-style URLs (ftp, etc.)
        r'ftp://[^\s<>"{}|\\^`\[\]]+',
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
        """Extract URLs from complete email structure."""
        self.logger.info("Starting URL extraction from email structure")
        
        result = UrlExtractionResult()
        seen_urls = set()
        
        # Extract from body content
        body = email_structure.get('body', {})
        if body.get('plain_text'):
            self._extract_from_text(body['plain_text'], result, seen_urls, 'body_plain')
        
        if body.get('html_preview'):
            self._extract_from_text(body['html_preview'], result, seen_urls, 'body_html')
        
        # Extract from headers
        headers = email_structure.get('headers', {})
        for header_name, header_value in headers.items():
            if isinstance(header_value, str):
                self._extract_from_text(header_value, result, seen_urls, f'header_{header_name}')
        
        # Extract from attachments (including nested emails)
        self._extract_from_attachments(email_structure.get('attachments', []), result, seen_urls)
        
        # Extract from nested emails
        self._extract_from_nested_emails(email_structure.get('nested_emails', []), result, seen_urls)
        
        # Finalize results
        result.url_count = len(result.urls)
        result.unique_domain_count = len(result.domains)
        result.shortened_url_count = sum(1 for url in result.urls if url.get('is_shortened', False))
        
        self.logger.info(f"URL extraction complete: {result.url_count} URLs, "
                        f"{result.unique_domain_count} unique domains, "
                        f"{result.shortened_url_count} shortened URLs")
        
        return result
    
    def _extract_from_text(self, text: str, result: UrlExtractionResult, 
                          seen_urls: Set[str], source: str) -> None:
        """Extract URLs from text content."""
        if not text:
            return
        
        self.logger.debug(f"Extracting URLs from {source} ({len(text)} chars)")
        
        for pattern in self._compiled_patterns:
            matches = pattern.findall(text)
            
            for match in matches:
                url = self._clean_url(match)
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    
                    url_info = self._analyze_url(url, source)
                    result.urls.append(url_info)
                    
                    # Extract domain
                    domain = self._extract_domain(url)
                    if domain:
                        result.domains.add(domain)
    
    def _extract_from_attachments(self, attachments: List[Dict[str, Any]], 
                                 result: UrlExtractionResult, seen_urls: Set[str]) -> None:
        """Extract URLs from attachment metadata and content."""
        for i, attachment in enumerate(attachments):
            # Check filename for URLs
            filename = attachment.get('filename')
            if filename:
                self._extract_from_text(filename, result, seen_urls, f'attachment_{i}_filename')
            
            # Check content analysis for URLs (in metadata)
            content_analysis = attachment.get('content_analysis', {})
            if isinstance(content_analysis, dict):
                for key, value in content_analysis.items():
                    if isinstance(value, str):
                        self._extract_from_text(value, result, seen_urls, f'attachment_{i}_{key}')
    
    def _extract_from_nested_emails(self, nested_emails: List[Dict[str, Any]], 
                                   result: UrlExtractionResult, seen_urls: Set[str]) -> None:
        """Extract URLs from nested emails recursively."""
        for i, nested_email in enumerate(nested_emails):
            self.logger.debug(f"Extracting URLs from nested email {i}")
            
            # Recursively extract from nested email structure
            nested_result = self.extract_urls_from_email(nested_email)
            
            # Merge results, avoiding duplicates
            for url_info in nested_result.urls:
                url = url_info['original_url']
                if url not in seen_urls:
                    seen_urls.add(url)
                    # Update source to indicate nested email
                    url_info['source'] = f"nested_email_{i}_{url_info['source']}"
                    result.urls.append(url_info)
            
            # Merge domains
            result.domains.update(nested_result.domains)
    
    def _clean_url(self, url: str) -> Optional[str]:
        """Clean and normalize URL."""
        if not url:
            return None
        
        # Remove trailing punctuation
        while url and url[-1] in '.,;:!?)]}\'"':
            url = url[:-1]
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://', 'ftp://')):
            if url.startswith('www.'):
                url = 'http://' + url
            elif '.' in url and not url.startswith('mailto:'):
                url = 'http://' + url
        
        # Validate URL structure
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                return urllib.parse.urlunparse(parsed)
        except Exception as e:
            self.logger.debug(f"Error normalizing URL {url}: {e}")
        
        return url
    
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
    
    def _analyze_url(self, url: str, source: str) -> Dict[str, Any]:
        """Analyze URL properties."""
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
            'url_length': len(url)
        }
        
        try:
            parsed = urllib.parse.urlparse(url)
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
            parsed = urllib.parse.urlparse(url)
            if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
                return True
        except Exception:
            pass
        
        return False