# ============================================================================
# email_parser/cli.py - CLI
# ============================================================================

import argparse
import json
from pathlib import Path
import logging

from . import create_email_parser


def main() -> None:
    """Command line interface for the email parser."""
    parser = argparse.ArgumentParser(description="Email parsing utility")
    parser.add_argument("file", type=Path, help="Input email file (.eml, .msg, .mbox)")
    parser.add_argument("--log-level", type=str, default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Set logging level")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    args = parser.parse_args()

    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    
    # Create parser
    email_parser = create_email_parser(log_level)
    
    # Read and parse file
    try:
        data = args.file.read_bytes()
        result = email_parser.parse(data, args.file.name)
        
        # Output results
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"Results saved to: {args.output}")
        else:
            print(json.dumps(result, indent=2, default=str))
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(main())


# ============================================================================
# Usage Examples
# ============================================================================

"""
# Basic usage:
from email_parser import create_email_parser

parser = create_email_parser()
with open('email.msg', 'rb') as f:
    data = f.read()
result = parser.parse(data, 'email.msg')

# Advanced usage with custom configuration:
import logging
from email_parser import create_email_parser

parser = create_email_parser(log_level=logging.DEBUG)
result = parser.parse(email_data, filename="suspicious.eml")

# The result structure:
{
    "status": "success",
    "detected_format": "MsgFormatParser", 
    "format_confidence": 0.9,
    "structure": {
        "type": "email",
        "headers": {...},
        "body": {
            "plain_text": "Email content...",
            "body_type": "plain",
            "char_count": 1234
        },
        "attachments": [
            {
                "filename": "document.pdf",
                "content_analysis": {
                    "detected_type": "pdf",
                    "mime_type": "application/pdf",
                    "hashes": {"md5": "...", "sha256": "..."},
                    "size": 12345
                },
                "is_nested_email": false
            }
        ],
        "nested_emails": [],
        "attachment_count": 1
    }
}

# Testing individual components:
from email_parser.content_analyzer import ContentAnalyzer
from email_parser.normalizers import Utf16ContentNormalizer

analyzer = ContentAnalyzer(logger)
normalizer = Utf16ContentNormalizer(logger)

# Test content analysis
with open('attachment.pdf', 'rb') as f:
    analysis = analyzer.analyze_content(f.read(), 'attachment.pdf')
print(analysis.detected_type, analysis.confidence)

# Test content normalization  
normalized = normalizer.normalize(msg_body_content)
"""