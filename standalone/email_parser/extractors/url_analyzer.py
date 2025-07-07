# ============================================================================
# email_parser/extractors/url_analyzer.py
# ============================================================================
"""Email URL analysis coordination."""

import logging
from typing import Dict, Any, List
from dataclasses import dataclass, asdict

from .url_extractor import UrlExtractor, UrlExtractionResult
from .url_processor import UrlProcessor, ProcessedUrl


@dataclass
class UrlAnalysisResult:
    """Complete URL analysis results for an email."""
    extraction_result: UrlExtractionResult
    processed_urls: List[ProcessedUrl]
    final_urls: List[str]  # NEW: Final destination URLs only
    domain_analysis: Dict[str, Any]
    summary: Dict[str, Any]


class UrlAnalyzer:
    """Main analyzer that orchestrates URL extraction and processing."""
    
    def __init__(self, logger: logging.Logger, enable_url_expansion: bool = False,
                 expansion_timeout: int = 5, expansion_delay: float = 0.5):
        self.logger = logger
        self.url_extractor = UrlExtractor(logger)
        self.url_processor = UrlProcessor(
            logger, 
            enable_expansion=enable_url_expansion,
            expansion_timeout=expansion_timeout,
            expansion_delay=expansion_delay
        )
    
    def analyze_email_urls(self, email_structure: Dict[str, Any]) -> UrlAnalysisResult:
        """Perform complete URL analysis on email structure."""
        self.logger.info("Starting URL analysis")
        
        # Step 1: Extract URLs from email
        extraction_result = self.url_extractor.extract_urls_from_email(email_structure)
        
        # Step 2: Process extracted URLs (returns both detailed info and final URL list)
        processed_urls, final_urls_list = self.url_processor.process_extracted_urls(extraction_result)
        
        # Step 3: Analyze domains (use final destinations for domain analysis)
        domain_analysis = self._analyze_domains(processed_urls, extraction_result.domains)
        
        # Step 4: Generate summary
        summary = self._generate_summary(extraction_result, processed_urls, domain_analysis)
        
        analysis = UrlAnalysisResult(
            extraction_result=extraction_result,
            processed_urls=processed_urls,
            final_urls=final_urls_list,  # NEW: Add final URLs list
            domain_analysis=domain_analysis,
            summary=summary
        )
        
        self.logger.info(f"URL analysis complete: {summary['total_urls']} URLs analyzed, "
                        f"{len(final_urls_list)} final destinations")
        
        return analysis
    
    def _analyze_domains(self, processed_urls: List[ProcessedUrl], all_domains: set) -> Dict[str, Any]:
        """Analyze domain patterns and characteristics."""
        domain_stats = {}
        image_domains = set()
        shortened_domains = set()
        
        for url in processed_urls:
            if url.domain:
                if url.domain not in domain_stats:
                    domain_stats[url.domain] = {
                        'count': 0,
                        'sources': set(),
                        'shortened_count': 0,
                        'image_count': 0
                    }
                
                stats = domain_stats[url.domain]
                stats['count'] += 1
                stats['sources'].add(url.source)
                
                if url.is_shortened:
                    stats['shortened_count'] += 1
                    shortened_domains.add(url.domain)
                
                if url.is_image:
                    stats['image_count'] += 1
                    image_domains.add(url.domain)
        
        # Convert sets to lists for JSON serialization
        for domain, stats in domain_stats.items():
            stats['sources'] = list(stats['sources'])
        
        return {
            'total_unique_domains': len(all_domains),
            'domain_statistics': domain_stats,
            'image_hosting_domains': list(image_domains),
            'url_shortener_domains': list(shortened_domains),
            'most_referenced_domain': max(domain_stats.keys(), 
                                        key=lambda d: domain_stats[d]['count']) if domain_stats else None
        }
    
    def _generate_summary(self, extraction_result: UrlExtractionResult, 
                         processed_urls: List[ProcessedUrl],
                         domain_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of URL analysis."""
        return {
            'total_urls': len(processed_urls),
            'unique_domains': domain_analysis['total_unique_domains'],
            'shortened_urls': sum(1 for url in processed_urls if url.is_shortened),
            'image_urls': sum(1 for url in processed_urls if url.is_image),
            'decoded_urls': sum(1 for url in processed_urls if url.decoded_url and url.decoded_url != url.cleaned_url),
            'expanded_urls': sum(1 for url in processed_urls if url.expanded_url),
            'processing_errors': sum(1 for url in processed_urls if url.processing_errors),
            'most_referenced_domain': domain_analysis.get('most_referenced_domain'),
            'url_sources': list(set(url.source for url in processed_urls))
        }
    
    def get_serializable_analysis(self, analysis: UrlAnalysisResult) -> Dict[str, Any]:
        """Convert analysis to JSON-serializable format."""
        return {
            'extraction_result': {
                'urls': [dict(url) for url in analysis.extraction_result.urls],
                'domains': list(analysis.extraction_result.domains),
                'url_count': analysis.extraction_result.url_count,
                'unique_domain_count': analysis.extraction_result.unique_domain_count,
                'shortened_url_count': analysis.extraction_result.shortened_url_count
            },
            'processed_urls': [asdict(url) for url in analysis.processed_urls],
            'final_urls': analysis.final_urls,  # NEW: Simple list of final URLs
            'domain_analysis': analysis.domain_analysis,
            'summary': analysis.summary
        }