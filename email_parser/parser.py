# ============================================================================
# email_parser/parser.py - Main parser with dependency injection
# ============================================================================

from typing import List, Dict, Any, Union, Optional
import logging

from .interfaces import EmailFormatParser
from .structure_extractor import EmailStructureExtractor


class EmailParser:
    """Main email parser that delegates to format-specific parsers."""
    
    def __init__(self, parsers: List[EmailFormatParser], structure_extractor: EmailStructureExtractor, logger: logging.Logger):
        self.parsers = parsers
        self.structure_extractor = structure_extractor
        self.logger = logger
    
    def parse(self, input_data: Union[str, bytes], filename: Optional[str] = None) -> Dict[str, Any]:
        """Parse email using the appropriate format parser."""
        # Convert to bytes for format detection
        if isinstance(input_data, str):
            data_bytes = input_data.encode('utf-8')
        else:
            data_bytes = input_data
        
        # Find the best parser
        best_parser = None
        best_confidence = 0.0
        parser_results = []
        
        for parser in self.parsers:
            can_parse, confidence = parser.can_parse(data_bytes, filename)
            parser_results.append({
                'parser': type(parser).__name__,
                'can_parse': can_parse,
                'confidence': confidence
            })
            
            if can_parse and confidence > best_confidence:
                best_parser = parser
                best_confidence = confidence
        
        if not best_parser:
            return {
                "status": "failed",
                "errors": ["No suitable parser found"],
                "detected_format": "unknown",
                "parser_results": parser_results,
            }
        
        # Parse the message
        message = best_parser.parse(data_bytes, filename)
        if not message:
            return {
                "status": "failed", 
                "errors": ["Parser failed to extract message"],
                "detected_format": type(best_parser).__name__,
                "parser_results": parser_results,
            }
        
        # Extract comprehensive structure
        structure = self.structure_extractor.extract_structure(message)
        
        return {
            "status": "success",
            "detected_format": type(best_parser).__name__,
            "format_confidence": best_confidence,
            "structure": structure,
            "parser_results": parser_results,
        }
