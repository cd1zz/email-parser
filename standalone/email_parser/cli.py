# ============================================================================
# email_parser/cli.py - Enhanced CLI with document processing support
# ============================================================================

import argparse
import json
from pathlib import Path
import logging

from . import create_email_parser


def main() -> None:
    """Command line interface for the email parser with document processing."""
    parser = argparse.ArgumentParser(
        description="Email parsing utility with URL analysis and document text extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic parsing with document text extraction (DEFAULT):
  python -m email_parser.cli email.msg

  # Disable document processing for faster parsing:
  python -m email_parser.cli email.msg --no-document-processing

  # Verbose output with detailed structure:
  python -m email_parser.cli email.msg --verbose

  # With URL expansion for comprehensive analysis:
  python -m email_parser.cli email.msg --expand-urls --verbose

  # Save results to file:
  python -m email_parser.cli email.msg --output analysis.json

  # Disable URL analysis for faster processing:
  python -m email_parser.cli email.msg --no-url-analysis

Document Support (ENABLED BY DEFAULT):
  The parser automatically extracts text from PDF, Word (.doc/.docx), 
  and Excel (.xls/.xlsx) attachments by default. Extracted text is 
  included in the analysis and searched for URLs and domains.
  
  Use --no-document-processing to disable this feature.

Required Libraries for Full Document Support:
  - PDF: pdfminer3k or pdfminer.six
  - Word: python-docx (for .docx) or textract (for .doc/.docx)
  - Excel: pandas with openpyxl and xlrd engines
        """
    )
    
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
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose output with detailed email structure")
    
    # Document processing options
    doc_group = parser.add_argument_group("Document Processing Options")
    doc_group.add_argument("--no-document-processing", action="store_true",
                          help="Disable document text extraction from attachments")
    doc_group.add_argument("--show-document-text", action="store_true",
                          help="Include full extracted document text in output (can be large)")
    doc_group.add_argument("--document-text-limit", type=int, default=10000,
                          help="Maximum characters of document text to include (default: 10000)")
    
    args = parser.parse_args()

    # Set log level
    log_level = getattr(logging, args.log_level.upper())
    
    # Create parser with URL analysis options
    email_parser = create_email_parser(
        log_level=log_level,
        enable_url_analysis=not args.no_url_analysis,
        enable_url_expansion=args.expand_urls,
        expansion_timeout=args.expansion_timeout,
        enable_document_processing=not args.no_document_processing  # NEW: Document processing enabled by default
    )
    
    # Read and parse file
    try:
        print(f"Reading email file: {args.file}")
        data = args.file.read_bytes()
        
        print("Parsing email structure and processing documents...")
        result = email_parser.parse(data, args.file.name, verbose=args.verbose)
        
        # Post-process result for document text display options
        if not args.show_document_text:
            result = _truncate_document_text(result, args.document_text_limit)
        
        # Add processing summary to output
        if not args.verbose:
            _add_processing_summary(result)
        
        # Output results
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"Results saved to: {args.output}")
            
            # Print summary to console even when saving to file
            _print_summary(result, args.verbose)
        else:
            if args.verbose:
                print(json.dumps(result, indent=2, default=str))
            else:
                # For non-verbose mode, print a nice summary first, then the JSON
                _print_summary(result, args.verbose)
                print("\n" + "="*50)
                print("FULL RESULTS:")
                print("="*50)
                print(json.dumps(result, indent=2, default=str))
            
    except Exception as e:
        print(f"Error: {e}")
        if args.log_level == "DEBUG":
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


def _truncate_document_text(result: dict, text_limit: int) -> dict:
    """Truncate document text in the result to specified limit."""
    def truncate_in_structure(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == 'document_extracts' and isinstance(value, list):
                    for extract in value:
                        if isinstance(extract, dict) and 'text' in extract:
                            text = extract['text']
                            if text and len(text) > text_limit:
                                extract['text'] = text[:text_limit] + f"... [TRUNCATED - {len(text)} total chars]"
                                extract['truncated'] = True
                
                elif key == 'document_text' and isinstance(value, str):
                    if len(value) > text_limit:
                        data[key] = value[:text_limit] + f"... [TRUNCATED - {len(value)} total chars]"
                
                elif isinstance(value, (dict, list)):
                    truncate_in_structure(value)
        
        elif isinstance(data, list):
            for item in data:
                truncate_in_structure(item)
    
    truncate_in_structure(result)
    return result


def _add_processing_summary(result: dict) -> None:
    """Add a processing summary to the result."""
    summary = result.get('summary', {})
    doc_analysis = result.get('document_analysis', {})
    
    processing_summary = {
        'emails_processed': summary.get('email_chain_length', 1),
        'attachments_found': summary.get('total_attachments', 0),
        'urls_extracted': len(result.get('email', {}).get('urls', [])),
        'documents_processed': doc_analysis.get('total_documents_processed', 0),
        'text_extracted_chars': doc_analysis.get('total_text_extracted', 0),
        'document_urls_found': doc_analysis.get('document_urls_found', 0)
    }
    
    result['processing_summary'] = processing_summary


def _print_summary(result: dict, verbose: bool) -> None:
    """Print a human-readable summary of the parsing results."""
    print("\n" + "="*60)
    print("EMAIL PARSING SUMMARY")
    print("="*60)
    
    # Basic info
    status = result.get('status', 'unknown')
    format_detected = result.get('detected_format', 'unknown')
    confidence = result.get('format_confidence', 0)
    
    print(f"Status: {status.upper()}")
    print(f"Format: {format_detected} (confidence: {confidence:.2f})")
    
    if status != 'success':
        errors = result.get('errors', [])
        if errors:
            print(f"Errors: {', '.join(errors)}")
        return
    
    # Email structure summary
    if verbose:
        structure = result.get('structure', {})
        print(f"Structure type: {structure.get('type', 'unknown')}")
        print(f"Depth: {structure.get('depth', 0)}")
        print(f"Parts: {structure.get('part_count', 0)}")
        print(f"Attachments: {structure.get('attachment_count', 0)}")
        print(f"Nested emails: {structure.get('nested_email_count', 0)}")
    else:
        # Streamlined mode summary
        summary = result.get('summary', {})
        doc_analysis = result.get('document_analysis', {})
        
        print(f"Email chain length: {summary.get('email_chain_length', 1)}")
        print(f"Total attachments: {summary.get('total_attachments', 0)}")
        print(f"Attachment types: {', '.join(summary.get('attachment_types', []))}")
        print(f"Domains involved: {len(summary.get('domains_involved', []))}")
        
        # Document processing summary
        if doc_analysis.get('total_documents_processed', 0) > 0:
            print(f"\nDocument Processing:")
            print(f"  Documents processed: {doc_analysis['total_documents_processed']}")
            print(f"  Successful extractions: {len(doc_analysis.get('successful_extractions', []))}")
            print(f"  Text extracted: {doc_analysis.get('total_text_extracted', 0):,} characters")
            print(f"  URLs found in documents: {doc_analysis.get('document_urls_found', 0)}")
            
            doc_types = doc_analysis.get('document_types_found', [])
            if doc_types:
                print(f"  Document types: {', '.join(doc_types)}")
            
            failed = doc_analysis.get('failed_extractions', [])
            if failed:
                print(f"  Failed extractions: {len(failed)}")
                for failure in failed:
                    print(f"    - {failure.get('filename', 'unknown')}: {failure.get('error', 'unknown error')}")
    
    # URL analysis summary
    email_obj = result.get('email', {}) if not verbose else result.get('structure', {})
    urls = email_obj.get('urls', []) if not verbose else []
    
    if not verbose and hasattr(result, 'get') and 'structure' in result:
        # For verbose mode, check url_analysis
        url_analysis = result['structure'].get('url_analysis')
        if url_analysis and 'summary' in url_analysis:
            url_summary = url_analysis['summary']
            print(f"\nURL Analysis:")
            print(f"  Total URLs: {url_summary.get('total_urls', 0)}")
            print(f"  Unique domains: {url_summary.get('unique_domains', 0)}")
            print(f"  Shortened URLs: {url_summary.get('shortened_urls', 0)}")
            print(f"  Expanded URLs: {url_summary.get('expanded_urls', 0)}")
    elif urls:
        print(f"\nURL Analysis:")
        print(f"  URLs found: {len(urls)}")
        if len(urls) <= 5:
            for url in urls:
                print(f"    - {url}")
        else:
            for url in urls[:3]:
                print(f"    - {url}")
            print(f"    ... and {len(urls) - 3} more")
    
    # Security indicators
    if not verbose:
        print(f"\nSecurity Indicators:")
        print(f"  External domains: {'Yes' if summary.get('contains_external_domains') else 'No'}")
    
    print("="*60)


if __name__ == "__main__":
    import sys
    sys.exit(main())


# ============================================================================
# Usage Examples with Document Processing
# ============================================================================

"""
# Basic usage with automatic document text extraction:
python -m email_parser.cli email.msg

# Verbose mode with full document processing details:
python -m email_parser.cli email.msg --verbose

# With URL expansion and document processing:
python -m email_parser.cli email.msg --expand-urls --show-document-text

# Save comprehensive analysis to file:
python -m email_parser.cli email.msg --output analysis.json --verbose --expand-urls

# Fast processing without URL analysis:
python -m email_parser.cli email.msg --no-url-analysis

# Control document text display:
python -m email_parser.cli email.msg --document-text-limit 5000
python -m email_parser.cli email.msg --show-document-text  # Show full text

# Debug mode for troubleshooting:
python -m email_parser.cli email.msg --log-level DEBUG

# Programmatic usage with document processing:
from email_parser import create_email_parser

# Create parser with document processing enabled (default)
parser = create_email_parser(
    enable_url_analysis=True,
    enable_url_expansion=True,
    expansion_timeout=10
)

with open('email.msg', 'rb') as f:
    data = f.read()

result = parser.parse(data, 'email.msg')

# Access document analysis
if 'document_analysis' in result:
    doc_analysis = result['document_analysis']
    print(f"Processed {doc_analysis['total_documents_processed']} documents")
    print(f"Extracted {doc_analysis['total_text_extracted']} characters")
    print(f"Found {doc_analysis['document_urls_found']} URLs in documents")
    
    # Access individual document extractions
    for attachment in result['email']['attachments']:
        if attachment.get('document_text'):
            print(f"Document: {attachment['name']}")
            print(f"Extracted text preview: {attachment['document_text'][:200]}...")
            print(f"URLs found: {attachment.get('document_urls', [])}")

# Access URL analysis including document URLs
total_urls = result['email']['urls']
print(f"Total URLs found (email + documents): {len(total_urls)}")

# Access summary with document information
summary = result['summary']
if 'document_summary' in summary:
    doc_summary = summary['document_summary']
    print(f"Document processing successful: {doc_summary['successful_extractions']}")
    print(f"Document types found: {doc_summary['document_types_found']}")

# Error handling example:
if result['status'] != 'success':
    print(f"Parsing failed: {result.get('errors', [])}")
else:
    # Check for document extraction errors
    doc_analysis = result.get('document_analysis', {})
    if doc_analysis.get('extraction_errors'):
        print(f"Document extraction errors: {doc_analysis['extraction_errors']}")

# Working with nested emails and their documents:
def process_nested_emails(email_obj, level=0):
    indent = "  " * level
    print(f"{indent}Email at level {level}")
    
    # Process attachments at this level
    for attachment in email_obj.get('attachments', []):
        if attachment.get('document_text'):
            print(f"{indent}  Document: {attachment['name']}")
            print(f"{indent}    Text length: {len(attachment['document_text'])}")
            print(f"{indent}    URLs: {len(attachment.get('document_urls', []))}")
    
    # Process nested emails recursively
    for nested_email in email_obj.get('nested_emails', []):
        process_nested_emails(nested_email, level + 1)

# Process the entire email structure
process_nested_emails(result['email'])

# Library availability check:
try:
    from email_parser.extractors.document_extractor import DocumentTextExtractor
    import logging
    
    extractor = DocumentTextExtractor(logging.getLogger())
    
    # Test library availability
    libraries_available = {
        'pandas': False,
        'python-docx': False,
        'pdfminer': False,
        'textract': False
    }
    
    try:
        import pandas
        libraries_available['pandas'] = True
    except ImportError:
        pass
    
    try:
        from docx import Document
        libraries_available['python-docx'] = True
    except ImportError:
        pass
    
    try:
        from pdfminer.high_level import extract_text
        libraries_available['pdfminer'] = True
    except ImportError:
        pass
    
    try:
        import textract
        libraries_available['textract'] = True
    except ImportError:
        pass
    
    print("Document processing library availability:")
    for lib, available in libraries_available.items():
        status = "✓ Available" if available else "✗ Not available"
        print(f"  {lib}: {status}")
    
    if not any(libraries_available.values()):
        print("\nTo enable document processing, install required libraries:")
        print("  pip install pdfminer.six python-docx pandas openpyxl xlrd")

except ImportError:
    print("Document processing components not available")

# Performance monitoring example:
import time

start_time = time.time()
result = parser.parse(data, filename)
processing_time = time.time() - start_time

print(f"Email processing completed in {processing_time:.2f} seconds")

doc_analysis = result.get('document_analysis', {})
if doc_analysis.get('total_documents_processed', 0) > 0:
    docs_per_second = doc_analysis['total_documents_processed'] / processing_time
    print(f"Document processing rate: {docs_per_second:.2f} documents/second")
    
    chars_per_second = doc_analysis.get('total_text_extracted', 0) / processing_time
    print(f"Text extraction rate: {chars_per_second:,.0f} characters/second")
"""