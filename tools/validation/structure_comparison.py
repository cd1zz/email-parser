#!/usr/bin/env python3
import json
import logging
import sys
from pathlib import Path
sys.path.append('../../function-app')
from email_parser import create_email_parser

# Disable logging for cleaner output
logging.disable(logging.CRITICAL)

def show_current_structure(email_file):
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    with open(email_file, 'rb') as f:
        email_data = f.read()
    
    result = parser.parse(email_data, Path(email_file).name, verbose=False)
    
    if result.get("status") != "success":
        return None
    
    structure = result.get("structure", {})
    email = structure.get("email", {})
    
    print(f"=== CURRENT STRUCTURE: {email_file} ===")
    
    # Show top-level structure
    print("Top-level email:")
    print(f"  - Subject: {email.get('headers', {}).get('subject', 'N/A')}")
    print(f"  - From: {email.get('headers', {}).get('from', 'N/A')}")
    print(f"  - Body text: {len(email.get('body', {}).get('text', ''))} chars")
    print(f"  - Body HTML: {len(email.get('body', {}).get('html', ''))} chars")
    print(f"  - URLs: {len(email.get('urls', []))} found")
    
    # Show attachments
    attachments = email.get("attachments", [])
    print(f"\nAttachments ({len(attachments)}):")
    for i, att in enumerate(attachments):
        print(f"  [{i}] {att.get('name', 'unnamed')} ({att.get('size', 0)} bytes)")
        print(f"      Type: {att.get('type', 'unknown')}")
        print(f"      Contains email: {att.get('contains_email', False)}")
        
        if att.get('contains_email') and att.get('nested_email'):
            nested = att.get('nested_email')
            print(f"      Nested email subject: {nested.get('headers', {}).get('subject', 'N/A')}")
            print(f"      Nested email body: {len(nested.get('body', {}).get('text', ''))} chars")
            print(f"      Nested email URLs: {len(nested.get('urls', []))} found")
    
    # Show nested emails array
    nested_emails = email.get("nested_emails", [])
    print(f"\nNested emails array ({len(nested_emails)}):")
    for i, nested in enumerate(nested_emails):
        print(f"  [{i}] Subject: {nested.get('headers', {}).get('subject', 'N/A')}")
        print(f"      From: {nested.get('headers', {}).get('from', 'N/A')}")
        print(f"      Body text: {len(nested.get('body', {}).get('text', ''))} chars")
        print(f"      Source attachment: {nested.get('source_attachment', 'N/A')}")
        print(f"      URLs: {len(nested.get('urls', []))} found")
    
    return result

def show_proposed_structure(current_result, email_file):
    """Convert current structure to proposed structure"""
    if not current_result:
        return
    
    print(f"\n=== PROPOSED STRUCTURE: {email_file} ===")
    
    structure = current_result.get("structure", {})
    email = structure.get("email", {})
    
    # Top-level remains the same
    print("Top-level email: (UNCHANGED)")
    print(f"  - Subject: {email.get('headers', {}).get('subject', 'N/A')}")
    print(f"  - From: {email.get('headers', {}).get('from', 'N/A')}")
    print(f"  - Body text: {len(email.get('body', {}).get('text', ''))} chars")
    print(f"  - Body HTML: {len(email.get('body', {}).get('html', ''))} chars")
    print(f"  - URLs: {len(email.get('urls', []))} found")
    
    # Show modified attachments structure
    attachments = email.get("attachments", [])
    nested_emails = email.get("nested_emails", [])
    
    print(f"\nAttachments ({len(attachments)}): (MODIFIED)")
    for i, att in enumerate(attachments):
        print(f"  [{i}] {att.get('name', 'unnamed')} ({att.get('size', 0)} bytes)")
        print(f"      Type: {att.get('type', 'unknown')}")
        print(f"      Contains email: {att.get('contains_email', False)}")
        
        if att.get('contains_email'):
            # Instead of full nested email, show reference
            nested_id = f"nested_{i}"
            print(f"      Nested email reference: '{nested_id}' (INSTEAD OF FULL CONTENT)")
            print(f"      → Points to nested_emails[{i}] for full content")
    
    # Show enhanced nested emails array
    print(f"\nNested emails array ({len(nested_emails)}): (ENHANCED)")
    for i, nested in enumerate(nested_emails):
        nested_id = f"nested_{i}"
        print(f"  [{i}] ID: '{nested_id}' (NEW)")
        print(f"      Subject: {nested.get('headers', {}).get('subject', 'N/A')}")
        print(f"      From: {nested.get('headers', {}).get('from', 'N/A')}")
        print(f"      Body text: {len(nested.get('body', {}).get('text', ''))} chars")
        print(f"      Body HTML: {len(nested.get('body', {}).get('html', ''))} chars")
        print(f"      Source attachment: {nested.get('source_attachment', 'N/A')}")
        print(f"      URLs: {len(nested.get('urls', []))} found")
        
        # Show nested attachments if any
        nested_attachments = nested.get('attachments', [])
        if nested_attachments:
            print(f"      Nested attachments: {len(nested_attachments)} files")
            for j, nested_att in enumerate(nested_attachments):
                print(f"        [{j}] {nested_att.get('name', 'unnamed')} ({nested_att.get('size', 0)} bytes)")

if __name__ == "__main__":
    # Test with different email types
    test_files = [
        "../test_emails/1.msg",   # Email with nested content + images
        "../test_emails/5.msg",   # Complex nested with Excel attachment
    ]
    
    for test_file in test_files:
        try:
            result = show_current_structure(test_file)
            show_proposed_structure(result, test_file)
            print("\n" + "="*80 + "\n")
        except Exception as e:
            print(f"Error with {test_file}: {e}")
            print("\n" + "="*80 + "\n")