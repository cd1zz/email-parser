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
    parser = argparse.ArgumentParser(description="Email parsing utility with URL analysis")
    parser.add_argument("file", type=Path, help="Input email file (.eml, .msg, .mbox)")
    parser.add_argument("--log-level", type=str, default="INFO", 
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Set logging level")
    parser.add_argument("--output", type=Path, help="Output JSON file")
    parser.add_argument("--no-url-analysis", action="store_true", 
                       help="Disable URL extraction and analysis")
    parser.add_argument("--expand-urls", action="store_true",
                       help="Enable URL expansion for shortened URLs (slower)")
    parser.add_argument("--expansion-timeout", type=int, default=5,
                       help="Timeout for URL expansion requests (seconds)")
    args = parser.parse_args()

    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    
    # Create parser with URL analysis options
    email_parser = create_email_parser(
        log_level=log_level,
        enable_url_analysis=not args.no_url_analysis,
        enable_url_expansion=args.expand_urls,
        expansion_timeout=args.expansion_timeout
    )
    
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
# Basic usage with URL analysis:
python -m email_parser.cli email.msg

# With URL expansion (slower but more comprehensive):
python -m email_parser.cli email.msg --expand-urls

# Disable URL analysis for faster processing:
python -m email_parser.cli email.msg --no-url-analysis

# Save results with URL analysis to file:
python -m email_parser.cli email.msg --output analysis.json --expand-urls

# Programmatic usage with URL analysis:
from email_parser import create_email_parser

# Enable URL analysis with expansion
parser = create_email_parser(
    enable_url_analysis=True,
    enable_url_expansion=True,
    expansion_timeout=10
)

with open('email.msg', 'rb') as f:
    data = f.read()

result = parser.parse(data, 'email.msg')

# Access URL analysis
if 'url_analysis' in result['structure']:
    url_analysis = result['structure']['url_analysis']
    print(f"Found {url_analysis['summary']['total_urls']} URLs")
    print(f"Unique domains: {url_analysis['summary']['unique_domains']}")
    
    # Access detailed URL information
    for url in url_analysis['processed_urls']:
        print(f"URL: {url['original_url']}")
        print(f"Domain: {url['domain']}")
        print(f"Shortened: {url['is_shortened']}")
        if url['expanded_url']:
            print(f"Expanded: {url['expanded_url']}")
"""