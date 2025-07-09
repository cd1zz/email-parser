#!/usr/bin/env python3
import json
import logging
import sys
from pathlib import Path
sys.path.append('../../function-app')
from email_parser import create_email_parser

# Disable logging for cleaner output
logging.disable(logging.CRITICAL)

def analyze_duplication(email_file):
    parser = create_email_parser(
        enable_url_analysis=True,
        enable_document_processing=True
    )
    
    with open(email_file, 'rb') as f:
        email_data = f.read()
    
    result = parser.parse(email_data, Path(email_file).name, verbose=False)
    
    if result.get("status") != "success":
        print(f"Error parsing {email_file}")
        return
    
    structure = result.get("structure", {})
    email = structure.get("email", {})
    
    print(f"=== Analyzing {email_file} ===")
    print(f"Total JSON size: {len(json.dumps(result))} characters")
    
    # Check for duplication between main email and nested emails
    main_body = email.get("body", {})
    nested_emails = email.get("nested_emails", [])
    attachments = email.get("attachments", [])
    
    print(f"\nMain email body text length: {len(main_body.get('text', ''))}")
    print(f"Main email body HTML length: {len(main_body.get('html', ''))}")
    
    # Check nested emails
    total_nested_text = 0
    total_nested_html = 0
    for i, nested in enumerate(nested_emails):
        nested_body = nested.get("body", {})
        nested_text_len = len(nested_body.get('text', ''))
        nested_html_len = len(nested_body.get('html', ''))
        total_nested_text += nested_text_len
        total_nested_html += nested_html_len
        print(f"  Nested email {i}: text={nested_text_len}, html={nested_html_len}")
    
    # Check attachments for nested emails
    nested_in_attachments = 0
    for i, att in enumerate(attachments):
        if att.get("contains_email"):
            nested_in_att = att.get("nested_email", {})
            if nested_in_att:
                nested_in_attachments += 1
                att_body = nested_in_att.get("body", {})
                att_text_len = len(att_body.get('text', ''))
                att_html_len = len(att_body.get('html', ''))
                print(f"  Attachment {i} nested email: text={att_text_len}, html={att_html_len}")
    
    print(f"\nSummary:")
    print(f"  Main email body: {len(main_body.get('text', '')) + len(main_body.get('html', ''))} chars")
    print(f"  Nested emails total: {total_nested_text + total_nested_html} chars")
    print(f"  Attachments with nested emails: {nested_in_attachments}")
    
    # Check for URL duplication
    main_urls = set(email.get("urls", []))
    nested_urls = set()
    for nested in nested_emails:
        nested_urls.update(nested.get("urls", []))
    
    print(f"  Main email URLs: {len(main_urls)}")
    print(f"  Nested email URLs: {len(nested_urls)}")
    print(f"  URL overlap: {len(main_urls & nested_urls)}")
    
    # Check summary section
    summary = structure.get("summary", {})
    print(f"\nSummary section size: {len(json.dumps(summary))} chars")
    
    return result

if __name__ == "__main__":
    # Test with a few different email types
    test_files = [
        "../test_emails/1.msg",  # Working email with nested content
        "../test_emails/3.msg",  # Fixed nested email
        "../test_emails/5.msg",  # Complex nested with Excel
    ]
    
    for test_file in test_files:
        try:
            analyze_duplication(test_file)
            print("\n" + "="*60 + "\n")
        except Exception as e:
            print(f"Error with {test_file}: {e}")
            print("\n" + "="*60 + "\n")