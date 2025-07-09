# ============================================================================
# email_parser/parser.py - Updated main parser with verbose support
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
    
    def parse(self, input_data: Union[str, bytes], filename: Optional[str] = None, verbose: bool = False) -> Dict[str, Any]:
        """Parse email using the appropriate format parser.
        
        Args:
            input_data: Email data as string or bytes
            filename: Optional filename for format detection
            verbose: If True, use verbose output format. If False, use streamlined format.
        
        Returns:
            Dictionary containing parsing results in either streamlined or verbose format
        """
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
        
        # Extract structure with format option
        structure = self.structure_extractor.extract_structure(message, depth=0, verbose=verbose)

        
        # Build response based on format
        if verbose:
            # Verbose format (legacy)
            return {
                "status": "success",
                "detected_format": type(best_parser).__name__.replace('FormatParser', '').lower(),
                "format_confidence": best_confidence,
                "msg_support_available": True,  # Keep for backward compatibility
                "structure": structure,
                "errors": [],
                "warnings": [],
                "format_details": {
                    "magic_bytes_detected": None,
                    "content_analysis": None,
                    "filename_hint": filename
                }
            }
        else:
            # Streamlined format (default)
            return {
                "status": "success",
                "detected_format": type(best_parser).__name__.replace('FormatParser', '').lower(),
                "format_confidence": best_confidence,
                "msg_support_available": True,
                "structure": structure,
                "errors": [],
                "warnings": []
            }