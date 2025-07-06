# ============================================================================
# email_parser/__init__.py - Factory and DI setup
# ============================================================================

import logging
import sys

from .converters import HtmlToTextConverter
from .content_analyzer import ContentAnalyzer
from .normalizers import Utf16ContentNormalizer
from .parser import EmailParser
from .parsers.eml_parser import EmlFormatParser
from .parsers.mbox_parser import MboxFormatParser
from .parsers.msg_parser import MsgFormatParser
from .structure_extractor import EmailStructureExtractor
from .extractors.url_analyzer import UrlAnalyzer

def create_email_parser(log_level: int = logging.INFO, enable_url_analysis: bool = True,
                       enable_url_expansion: bool = False, expansion_timeout: int = 5):
    """Factory function to create a fully configured EmailParser."""
    # Setup logging
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logger = logging.getLogger(__name__)
    
    # Create dependencies
    content_normalizer = Utf16ContentNormalizer(logger)
    html_converter = HtmlToTextConverter(logger)
    content_analyzer = ContentAnalyzer(logger)
    
    # Create URL analyzer if enabled
    url_analyzer = None
    if enable_url_analysis:
        url_analyzer = UrlAnalyzer(
            logger, 
            enable_url_expansion=enable_url_expansion,
            expansion_timeout=expansion_timeout
        )
    
    # Create structure extractor
    structure_extractor = EmailStructureExtractor(
        logger, content_analyzer, html_converter, url_analyzer
    )
    
    # Create parsers in order of preference (most specific first)
    parsers = [
        MsgFormatParser(logger, content_normalizer, html_converter, content_analyzer),
        MboxFormatParser(logger),
        EmlFormatParser(logger),  # EML last as it's the fallback
    ]
    
    return EmailParser(parsers, structure_extractor, logger)




