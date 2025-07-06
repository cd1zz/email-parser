#!/usr/bin/env python3
"""
Fixed Proofpoint diagnostic script
"""

import sys
import os
from pathlib import Path

# Add the parent directory to Python path so we can import email_parser
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

# Now import the email parser
from email_parser import create_email_parser
import logging

def test_proofpoint_parsing():
    """Test Proofpoint email parsing with enhanced base64 detection."""
    
    # Set up the file path (use raw string or forward slashes)
    email_file = Path(__file__).parent.parent / "test_emails" / "proofpoint_sample.eml"
    
    if not email_file.exists():
        print(f"ERROR: Email file not found: {email_file}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Looking for file at: {email_file.absolute()}")
        
        # Try alternative locations
        alt_locations = [
            Path("proofpoint_sample.eml"),
            Path("test_emails/proofpoint_sample.eml"),
            Path("../proofpoint_sample.eml"),
        ]
        
        for alt_path in alt_locations:
            if alt_path.exists():
                email_file = alt_path
                print(f"Found file at alternative location: {alt_path}")
                break
        else:
            print("Could not find the email file in any expected location.")
            return False
    
    print("=" * 60)
    print("PROOFPOINT EMAIL PARSING DIAGNOSTIC")
    print("=" * 60)
    print(f"Email file: {email_file}")
    print(f"File size: {email_file.stat().st_size} bytes")
    
    # Create parser with debug logging
    parser = create_email_parser(
        log_level=logging.DEBUG,
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    # Read and parse the email
    print("\nReading email file...")
    with open(email_file, 'rb') as f:
        data = f.read()
    
    print(f"Read {len(data)} bytes")
    
    print("\nParsing email with enhanced base64 detection...")
    result = parser.parse(data, email_file.name, verbose=True)
    
    print(f"\nParsing Status: {result['status']}")
    
    if result['status'] != 'success':
        print(f"Parsing failed: {result.get('errors', [])}")
        return False
    
    print(f"Format detected: {result['detected_format']}")
    
    # Analyze the structure
    structure = result['structure']
    
    print(f"\nEMAIL STRUCTURE ANALYSIS:")
    print(f"  Type: {structure.get('type', 'unknown')}")
    print(f"  Depth: {structure.get('depth', 0)}")
    print(f"  Total parts: {structure.get('part_count', 0)}")
    print(f"  Attachments: {structure.get('attachment_count', 0)}")
    print(f"  Nested emails: {structure.get('nested_email_count', 0)}")
    
    # Check each attachment for base64 emails
    print(f"\nATTACHMENT ANALYSIS:")
    attachments = structure.get('attachments', [])
    
    if not attachments:
        print("  No attachments found")
    else:
        for i, attachment in enumerate(attachments):
            print(f"\n  Attachment {i+1}:")
            print(f"    Filename: {attachment.get('filename', 'N/A')}")
            print(f"    Content-Type: {attachment.get('content_type', 'N/A')}")
            print(f"    Encoding: {attachment.get('encoding', 'N/A')}")
            print(f"    Size: {attachment.get('size', 'N/A')} bytes")
            print(f"    Is nested email: {attachment.get('is_nested_email', False)}")
            
            # Check for base64 detection (if we added this flag)
            if attachment.get('base64_email_detected'):
                print(f"    ✓ Base64 email detected!")
            
            # If it's a nested email, show details
            if attachment.get('is_nested_email') and attachment.get('nested_email'):
                nested = attachment['nested_email']
                headers = nested.get('headers', {})
                print(f"    NESTED EMAIL DETAILS:")
                print(f"      Subject: {headers.get('subject', 'N/A')}")
                print(f"      From: {headers.get('from', 'N/A')}")
                print(f"      To: {headers.get('to', 'N/A')}")
                print(f"      Date: {headers.get('date', 'N/A')}")
                print(f"      Nested attachments: {nested.get('attachment_count', 0)}")
                print(f"      Further nesting: {nested.get('nested_email_count', 0)}")
    
    # URL Analysis
    if 'url_analysis' in structure:
        url_analysis = structure['url_analysis']
        summary = url_analysis.get('summary', {})
        print(f"\nURL ANALYSIS:")
        print(f"  Total URLs: {summary.get('total_urls', 0)}")
        print(f"  Unique domains: {summary.get('unique_domains', 0)}")
        print(f"  Shortened URLs: {summary.get('shortened_urls', 0)}")
        print(f"  Expanded URLs: {summary.get('expanded_urls', 0)}")
    
    print(f"\n" + "=" * 60)
    print("DIAGNOSTIC COMPLETE")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    try:
        success = test_proofpoint_parsing()
        if success:
            print("\n✓ Diagnostic completed successfully")
        else:
            print("\n✗ Diagnostic encountered errors")
            sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Diagnostic failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)