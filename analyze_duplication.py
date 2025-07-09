#!/usr/bin/env python3
"""
Analyze the nested_msgs files for duplication issues in JSON structure
"""
import json
import sys
from pathlib import Path

# Add the function-app directory to the path
sys.path.append('./function-app')
from email_parser import create_email_parser

def analyze_duplication_in_json(file_path):
    """Analyze the JSON output for duplication issues"""
    print(f"\n=== Analyzing duplication in {Path(file_path).name} ===")
    
    parser = create_email_parser(enable_url_analysis=True, enable_document_processing=True)
    
    with open(file_path, 'rb') as f:
        email_data = f.read()
    
    result = parser.parse(email_data, Path(file_path).name, verbose=False)
    
    if result.get("status") != "success":
        print(f"Failed to parse: {result.get('error', 'Unknown error')}")
        return
    
    structure = result.get("structure", {})
    email_data = structure.get("email", {})
    summary = structure.get("summary", {})
    
    print(f"Structure keys: {list(structure.keys())}")
    print(f"Email keys: {list(email_data.keys())}")
    print(f"Summary keys: {list(summary.keys())}")
    
    # Check nested email IDs for uniqueness
    nested_emails = email_data.get("nested_emails", [])
    nested_ids = [ne.get("id") for ne in nested_emails]
    print(f"\nNested email IDs: {nested_ids}")
    print(f"Unique nested IDs: {len(set(nested_ids))} / {len(nested_ids)}")
    
    # Check URL deduplication
    url_summary = summary.get("urls", {})
    print(f"\nURL Summary:")
    print(f"  Total URLs: {url_summary.get('total_count', 0)}")
    print(f"  Unique domains: {url_summary.get('unique_domain_count', 0)}")
    print(f"  Shortened URLs: {url_summary.get('shortened_url_count', 0)}")
    
    # Check for URL duplication across nested emails
    all_urls_in_structure = []
    
    # URLs from main email body
    main_body = email_data.get("body", {})
    if main_body.get("text"):
        import re
        urls = re.findall(r'https?://[^\s<>"]+', main_body["text"])
        all_urls_in_structure.extend(urls)
        print(f"  URLs in main body: {len(urls)}")
    
    # URLs from nested emails
    for i, nested in enumerate(nested_emails):
        nested_body = nested.get("body", {})
        if nested_body.get("text"):
            urls = re.findall(r'https?://[^\s<>"]+', nested_body["text"])
            all_urls_in_structure.extend(urls)
            print(f"  URLs in nested {i} body: {len(urls)}")
    
    print(f"  Total URLs found in structure: {len(all_urls_in_structure)}")
    print(f"  Unique URLs in structure: {len(set(all_urls_in_structure))}")
    
    # Check domains deduplication
    domain_summary = summary.get("domains", {})
    print(f"\nDomain Summary:")
    print(f"  Total domains: {domain_summary.get('total_count', 0)}")
    print(f"  Unique domains: {domain_summary.get('unique_count', 0)}")
    if domain_summary.get('list'):
        print(f"  Domain list: {domain_summary['list'][:5]}...")  # Show first 5
    
    # Check for duplication in attachments
    attachments = email_data.get("attachments", [])
    print(f"\nAttachment Analysis:")
    print(f"  Total attachments: {len(attachments)}")
    
    # Check for nested email references in attachments
    nested_refs = []
    for att in attachments:
        if att.get("contains_email"):
            nested_refs.append(att.get("nested_email_index"))
    
    print(f"  Attachments with nested emails: {len(nested_refs)}")
    print(f"  Nested email references: {nested_refs}")
    
    # Check summary email count vs actual structure
    summary_emails = summary.get("emails", {})
    actual_email_count = len(nested_emails) + 1  # +1 for main email
    print(f"\nEmail Count Verification:")
    print(f"  Summary total emails: {summary_emails.get('total_count', 0)}")
    print(f"  Actual emails in structure: {actual_email_count}")
    print(f"  Match: {summary_emails.get('total_count', 0) == actual_email_count}")
    
    # Check for the restructured JSON format compliance
    print(f"\nJSON Structure Compliance (from c959a50 commit):")
    print(f"  Has nested email IDs: {all(ne.get('id') for ne in nested_emails)}")
    print(f"  Has summary section: {'summary' in structure}")
    print(f"  Has URL deduplication: {'urls' in summary}")
    print(f"  Has domain deduplication: {'domains' in summary}")
    
    return structure

if __name__ == "__main__":
    # Analyze both files
    eml_structure = analyze_duplication_in_json("./test_emails/nested_msgs.eml")
    msg_structure = analyze_duplication_in_json("./test_emails/nested_msgs.msg")
    
    # Compare the two structures
    print("\n=== COMPARISON ===")
    
    if eml_structure and msg_structure:
        eml_summary = eml_structure.get("summary", {})
        msg_summary = msg_structure.get("summary", {})
        
        print(f"EML URLs total: {eml_summary.get('urls', {}).get('total_count', 0)}")
        print(f"MSG URLs total: {msg_summary.get('urls', {}).get('total_count', 0)}")
        
        print(f"EML domains: {eml_summary.get('domains', {}).get('unique_count', 0)}")
        print(f"MSG domains: {msg_summary.get('domains', {}).get('unique_count', 0)}")
        
        eml_nested = eml_structure.get("email", {}).get("nested_emails", [])
        msg_nested = msg_structure.get("email", {}).get("nested_emails", [])
        
        print(f"EML nested emails: {len(eml_nested)}")
        print(f"MSG nested emails: {len(msg_nested)}")
        
        print(f"EML attachments: {len(eml_structure.get('email', {}).get('attachments', []))}")
        print(f"MSG attachments: {len(msg_structure.get('email', {}).get('attachments', []))}")