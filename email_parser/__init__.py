# ============================================================================
# email_parser/__init__.py - Factory and DI setup
# ============================================================================

import logging
import sys


def create_email_parser(log_level: int = logging.INFO):
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
    
    # Create structure extractor
    structure_extractor = EmailStructureExtractor(logger, content_analyzer, html_converter)
    
    # Create parsers in order of preference (most specific first)
    parsers = [
        MsgFormatParser(logger, content_normalizer, html_converter, content_analyzer),
        MboxFormatParser(logger),
        EmlFormatParser(logger),  # EML last as it's the fallback
    ]
    
    return EmailParser(parsers, structure_extractor, logger)




